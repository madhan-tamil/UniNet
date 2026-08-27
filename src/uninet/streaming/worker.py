"""The pipeline: source -> (bus) -> windowed features -> TB-Graph -> detection.

``run_pipeline`` is the synchronous entry point used by the demo, tests and eval.
It is streaming-shaped: records go through a :class:`MessageBus` (in-process by
default) exactly as they would in a live deployment, then are processed in
fixed-width time windows.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from uninet.baseline.profile_store import ProfileStore
from uninet.config import Settings, load_settings
from uninet.detection.detector import Detector
from uninet.features.extractor import FeatureExtractor, HostWindowFeatures
from uninet.ingestion.flow_parser import local_host_of, sort_by_time
from uninet.ingestion.sources.base import FlowSource
from uninet.schemas.alert import Alert
from uninet.schemas.flow import FlowRecord
from uninet.streaming.bus import InProcBus, MessageBus
from uninet.tb_graph.burst_builder import BurstBuilder
from uninet.tb_graph.graph_builder import GraphBuilder
from uninet.tb_graph.graph_store import TBGraphStore


@dataclass
class PipelineResult:
    alerts: list[Alert] = field(default_factory=list)
    graph: TBGraphStore = field(default_factory=TBGraphStore)
    features: list[HostWindowFeatures] = field(default_factory=list)
    flow_count: int = 0
    window_count: int = 0

    def alerts_json(self) -> list[dict]:
        return [a.model_dump(mode="json") for a in self.alerts]

    def merge(self, other: PipelineResult) -> PipelineResult:
        """Fold another result in. Safe when partitions are host-disjoint."""
        self.alerts.extend(other.alerts)
        self.features.extend(other.features)
        self.graph.merge(other.graph.g)
        self.flow_count += other.flow_count
        self.window_count = max(self.window_count, other.window_count)
        return self


def merge_results(results: list[PipelineResult]) -> PipelineResult:
    out = PipelineResult()
    for r in results:
        out.merge(r)
    out.alerts.sort(key=lambda a: -a.confidence)
    return out


def _drain(source: FlowSource, bus: MessageBus, topic: str) -> list[FlowRecord]:
    """Publish every record onto the bus, then read it all back (one-way)."""
    for rec in source.stream():
        bus.publish(topic, rec)
    if isinstance(bus, InProcBus):
        bus.seal(topic)
    return list(bus.consume(topic))


def run_pipeline(
    source: FlowSource,
    settings: Settings | None = None,
    *,
    detector: Detector | None = None,
    profile_store: ProfileStore | None = None,
    use_bus: bool = True,
    window_anchor: float | None = None,
) -> PipelineResult:
    s = settings or load_settings()
    detector = detector or Detector.from_settings(s)
    profiles = profile_store if profile_store is not None else ProfileStore()

    if use_bus:
        bus: MessageBus = InProcBus() if s.bus == "inproc" else _make_kafka(s)
        flows = _drain(source, bus, s.kafka_topic)
        bus.close()
    else:
        flows = source.collect()

    flows = sort_by_time(flows)
    result = PipelineResult(flow_count=len(flows))
    if not flows:
        return result

    burst_builder = BurstBuilder(s.burst_gap_seconds)
    graph_builder = GraphBuilder()
    extractor = FeatureExtractor(s.window_seconds)

    t0 = window_anchor if window_anchor is not None else flows[0].start_ts
    t_end = flows[-1].start_ts
    win = float(s.window_seconds)

    ws = t0
    while ws <= t_end:
        we = ws + win
        window_flows = [f for f in flows if ws <= f.start_ts < we]
        if window_flows:
            result.window_count += 1
            by_host: dict[str, list[FlowRecord]] = defaultdict(list)
            for f in window_flows:
                by_host[local_host_of(f)].append(f)

            for host, hflows in by_host.items():
                bursts = burst_builder.build(hflows, host)
                feats = extractor.extract(host, hflows, bursts, ws, we)
                result.features.append(feats)

                result.graph.merge(graph_builder.build(bursts))

                novelty = profiles.novelty(host, feats.vector)
                profiles.update(host, feats.vector)

                # Too little activity to judge - keep learning the baseline, don't alert.
                if len(hflows) < s.min_flows_per_window:
                    continue

                subgraph = result.graph.subgraph_for_host(host)
                alert = detector.assess(feats, subgraph, baseline_novelty=novelty)
                if alert is not None:
                    alert.graph_node_ids = alert.graph_node_ids or [f"host:{host}"]
                    result.alerts.append(alert)
        ws = we

    return result


def _make_kafka(s: Settings) -> MessageBus:  # pragma: no cover - needs a broker
    from uninet.streaming.bus import make_bus

    return make_bus("kafka", s.kafka_brokers)
