"""Evidence fusion: combine rules + anomaly + graph into one :class:`Alert`.

    confidence = w_rule * rule_score + w_anom * anomaly_score + w_graph * graph_score
                 + corroboration_bonus   (when two independent signals agree)

The threat *class* is taken from the most interpretable signal that fired (rules
first, then graph structure, then "UNKNOWN" for a pure anomaly). Nothing here
touches the network - it only reads features and writes an Alert object.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from uninet.config import Settings, load_settings
from uninet.detection.anomaly_model import AnomalyModel
from uninet.detection.rgat_model import GraphScore, GraphThreatScorer
from uninet.detection.rules import RuleEngine, RuleHit
from uninet.detection.sequence_model import SequenceScore, SequenceThreatScorer
from uninet.detection.threat_types import ThreatType
from uninet.features.extractor import HostWindowFeatures
from uninet.schemas.alert import Alert, Evidence, EvidenceKind, Severity
from uninet.utils import clamp01


@dataclass
class DetectorConfig:
    weights: dict[str, float] = field(
        default_factory=lambda: {"rule": 0.5, "anomaly": 0.2, "graph": 0.3}
    )
    alert_threshold: float = 0.5
    corroboration_bonus: float = 0.1

    @classmethod
    def from_settings(cls, s: Settings) -> DetectorConfig:
        return cls(
            weights=s.normalized_fusion_weights(),
            alert_threshold=s.alert_threshold,
        )


class Detector:
    def __init__(
        self,
        config: DetectorConfig | None = None,
        rule_engine: RuleEngine | None = None,
        anomaly_model: AnomalyModel | None = None,
        graph_scorer: GraphThreatScorer | None = None,
        sequence_scorer: SequenceThreatScorer | None = None,
    ) -> None:
        self.cfg = config or DetectorConfig()
        self.rules = rule_engine or RuleEngine()
        self.anomaly = anomaly_model or AnomalyModel()
        self.graph_scorer = graph_scorer or GraphThreatScorer()
        self.sequence_scorer = sequence_scorer or SequenceThreatScorer()

    # ------------------------------------------------------------------ #
    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> Detector:
        s = settings or load_settings()
        return cls(
            config=DetectorConfig.from_settings(s),
            anomaly_model=AnomalyModel.load_or_none(s.model_path_anomaly) or AnomalyModel(),
            graph_scorer=GraphThreatScorer(s.model_path_rgat),
            sequence_scorer=SequenceThreatScorer(s.model_path_sequence),
        )

    # ------------------------------------------------------------------ #
    def assess(
        self,
        feats: HostWindowFeatures,
        subgraph=None,
        baseline_novelty: float = 0.0,
    ) -> Alert | None:
        rule_hits: list[RuleHit] = self.rules.run(feats)
        rule_score = max((h.confidence for h in rule_hits), default=0.0)
        rule_threat = (
            max(rule_hits, key=lambda h: h.confidence).threat_type if rule_hits else None
        )

        anomaly_score = clamp01(max(self.anomaly.score(feats.as_array()), baseline_novelty))

        gs: GraphScore = (
            self.graph_scorer.score(subgraph, feats.host)
            if subgraph is not None
            else GraphScore(0.0, ThreatType.BENIGN, [], "no graph supplied")
        )

        # 4th signal: temporal read of the burst sequence. Additive evidence only -
        # it does not enter the fusion math or the threat-class decision.
        seq: SequenceScore = self.sequence_scorer.score(feats.bursts, feats.host)

        threat = self._decide_threat(rule_threat, gs, anomaly_score)
        if threat in (ThreatType.BENIGN,):
            return None

        # Fusion: dominated by the strongest single signal, widened by breadth of
        # agreement, then a small bonus when two independent signals concur.
        w = self.cfg.weights
        strongest = max(rule_score, anomaly_score, gs.score)
        breadth = (
            w.get("rule", 0.0) * rule_score
            + w.get("anomaly", 0.0) * anomaly_score
            + w.get("graph", 0.0) * gs.score
        )
        fused = 0.7 * strongest + 0.3 * breadth
        if rule_threat is not None and rule_threat == gs.threat_hint:
            fused += self.cfg.corroboration_bonus
        fused = clamp01(fused)

        if fused < self.cfg.alert_threshold:
            return None

        evidence = self._collect_evidence(rule_hits, anomaly_score, baseline_novelty, gs, seq)
        return Alert(
            window_start=feats.window_start,
            window_end=feats.window_end,
            src_host=feats.host,
            peers=feats.peers[:12],
            threat_type=threat,
            confidence=round(fused, 4),
            severity=self._severity(threat, fused),
            title=self._title(threat, feats.host),
            summary=self._summary(threat, feats, evidence),
            evidence=evidence,
            graph_node_ids=gs.top_nodes,
            scores={
                "rule": round(rule_score, 4),
                "anomaly": round(anomaly_score, 4),
                "graph": round(gs.score, 4),
                "sequence": round(seq.score, 4),
            },
        )

    # ------------------------------------------------------------------ #
    @staticmethod
    def _decide_threat(
        rule_threat: ThreatType | None, gs: GraphScore, anomaly_score: float
    ) -> ThreatType:
        if rule_threat is not None:
            return rule_threat
        if gs.threat_hint not in (ThreatType.BENIGN, ThreatType.UNKNOWN) and gs.score >= 0.5:
            return gs.threat_hint
        if anomaly_score >= 0.8 or (gs.threat_hint == ThreatType.UNKNOWN and gs.score >= 0.55):
            return ThreatType.UNKNOWN
        return ThreatType.BENIGN

    @staticmethod
    def _severity(threat: ThreatType, conf: float) -> Severity:
        high_impact = {ThreatType.C2_BEACON, ThreatType.DATA_EXFIL, ThreatType.DDOS}
        if conf >= 0.85 and threat in high_impact:
            return Severity.CRITICAL
        if conf >= 0.75:
            return Severity.HIGH
        if conf >= 0.6:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _collect_evidence(
        rule_hits: list[RuleHit], anomaly_score: float, baseline_novelty: float,
        gs: GraphScore, seq: SequenceScore | None = None
    ) -> list[Evidence]:
        ev = [h.evidence for h in rule_hits]
        if anomaly_score >= 0.6:
            src = "baseline deviation" if baseline_novelty >= anomaly_score else "isolation forest"
            ev.append(Evidence(
                kind=EvidenceKind.ANOMALY, name="unsupervised_anomaly",
                detail=f"behaviour is an outlier ({src}), score {anomaly_score:.2f}",
                score=anomaly_score,
            ))
        if gs.score >= 0.45:
            ev.append(Evidence(
                kind=EvidenceKind.GRAPH, name="tb_graph_structure",
                detail=gs.rationale or f"TB-Graph suspicion {gs.score:.2f}",
                score=gs.score,
                data={"top_nodes": gs.top_nodes, "hint": gs.threat_hint.value},
            ))
        if seq is not None and seq.score >= 0.5:
            ev.append(Evidence(
                kind=EvidenceKind.ML, name="temporal_sequence",
                detail=seq.rationale or f"burst-sequence suspicion {seq.score:.2f}",
                score=seq.score,
                data={**seq.features, "hint": seq.threat_hint.value},
            ))
        return ev

    @staticmethod
    def _title(threat: ThreatType, host: str) -> str:
        names = {
            ThreatType.DDOS: "Volumetric DDoS activity",
            ThreatType.C2_BEACON: "C2 beaconing",
            ThreatType.DGA: "DGA domain activity",
            ThreatType.PORT_SCAN: "Port scan / reconnaissance",
            ThreatType.DATA_EXFIL: "Data exfiltration",
            ThreatType.BOTNET: "Botnet coordination",
            ThreatType.UNKNOWN: "Anomalous traffic (unclassified)",
        }
        return f"{names.get(threat, threat.value)} from {host}"

    @staticmethod
    def _summary(threat: ThreatType, feats: HostWindowFeatures, evidence: list[Evidence]) -> str:
        lead = "; ".join(e.detail for e in evidence[:3]) or "multiple weak indicators"
        return (
            f"Host {feats.host} over "
            f"{feats.window_end - feats.window_start:.0f}s: {lead}."
        )
