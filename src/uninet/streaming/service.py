"""Phase 5 - scale-out.

    PCAP / NetFlow  ->  bus  ->  N workers (host-partitioned)  ->  merge

Two entry points:

* :func:`run_sharded` - split the flow stream by host across a worker pool
  (thread or process), run the Phase 1/2 pipeline per shard, merge the results.
  Partitioning on the local host keeps every host's TB-Graph on a single worker,
  so sharding does not change detections - only wall-clock time.

* :class:`LiveService` - a continuous runner: it keeps pulling new flows from a
  source on an interval and republishes a rolling :class:`PipelineResult` that the
  dashboard polls. Used by ``uninet --live``.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

from uninet.config import Settings, load_settings
from uninet.ingestion.flow_parser import local_host_of
from uninet.ingestion.sources.base import FlowSource
from uninet.schemas.flow import FlowRecord
from uninet.streaming.worker import PipelineResult, merge_results, run_pipeline


class _ListSource(FlowSource):
    name = "shard"

    def __init__(self, records: list[FlowRecord]) -> None:
        self._records = records

    def stream(self):
        yield from self._records


def _partition(flows: list[FlowRecord], n: int) -> list[list[FlowRecord]]:
    buckets: list[list[FlowRecord]] = [[] for _ in range(n)]
    for f in flows:
        buckets[hash(local_host_of(f)) % n].append(f)
    return buckets


def _process_shard(args: tuple[list[FlowRecord], Settings, float | None]) -> PipelineResult:
    flows, settings, anchor = args
    # Detector (and its models) is rebuilt inside the worker so this is safe to
    # ship to a separate process.
    return run_pipeline(_ListSource(flows), settings, use_bus=False, window_anchor=anchor)


def run_sharded(
    source: FlowSource,
    settings: Settings | None = None,
    *,
    workers: int = 4,
    executor: str = "process",
) -> PipelineResult:
    """Host-partitioned parallel run. ``executor``: ``"process"`` | ``"thread"``.

    A shared window anchor (global earliest flow) is passed to every shard so
    windowing - and therefore detections - are identical to a single-shot run.
    """
    s = settings or load_settings()
    flows = source.collect()
    if not flows:
        return PipelineResult()
    anchor = min(f.start_ts for f in flows)
    if workers <= 1 or len(flows) < workers:
        return _process_shard((flows, s, anchor))

    shards = _partition(flows, workers)
    pool_cls = ProcessPoolExecutor if executor == "process" else ThreadPoolExecutor
    with pool_cls(max_workers=workers) as pool:
        results = list(pool.map(_process_shard, [(sh, s, anchor) for sh in shards]))
    return merge_results(results)


class LiveService:
    """Background thread that refreshes a rolling PipelineResult from a source."""

    def __init__(
        self,
        source_factory: Callable[[], FlowSource],
        settings: Settings | None = None,
        *,
        interval: float = 8.0,
        on_update: Callable[[PipelineResult], None] | None = None,
    ) -> None:
        self.source_factory = source_factory
        self.settings = settings or load_settings()
        self.interval = interval
        self.on_update = on_update
        self.result = PipelineResult()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _loop(self) -> None:
        from uninet.detection.detector import Detector

        detector = Detector.from_settings(self.settings)
        while not self._stop.is_set():
            try:
                res = run_pipeline(self.source_factory(), self.settings, detector=detector)
                self.result = res
                if self.on_update:
                    self.on_update(res)
            except Exception as exc:  # keep the service alive across a bad batch
                print(f"[live] refresh failed: {exc}")
            self._stop.wait(self.interval)

    def start(self) -> LiveService:
        self._thread = threading.Thread(target=self._loop, name="uninet-live", daemon=True)
        self._thread.start()
        # prime one synchronous cycle so the dashboard has data immediately
        t0 = time.time()
        while not self.result.alerts and time.time() - t0 < 20:
            time.sleep(0.2)
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
