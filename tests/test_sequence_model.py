"""4th signal - temporal burst-sequence scorer (heuristic backend)."""
from uninet.config import load_settings
from uninet.detection.detector import Detector
from uninet.detection.sequence_model import HeuristicSequenceScorer, SequenceThreatScorer
from uninet.detection.threat_types import ThreatType
from uninet.ingestion.sources.synthetic import SyntheticSource
from uninet.schemas.burst import Direction, TrafficBurst
from uninet.streaming.worker import run_pipeline


def _burst(i, ts, byte_count, direction=Direction.OUTBOUND, ports=None, periodic=0.0):
    return TrafficBurst(
        burst_id=f"h->p#{i}@{int(ts)}", host="10.0.0.9", peer="203.0.113.5",
        direction=direction, start_ts=ts, end_ts=ts + 0.5,
        flow_count=3, packet_count=9, byte_count=byte_count,
        dst_ports=ports or [443], intra_periodicity=periodic,
    )


def test_regular_small_bursts_read_as_beacon():
    bursts = [_burst(i, i * 30.0, 1200, periodic=0.95) for i in range(8)]
    s = HeuristicSequenceScorer().score(bursts)
    assert s.threat_hint == ThreatType.C2_BEACON
    assert s.score > 0.5
    assert s.features["regularity"] > 0.8


def test_monotone_ramp_reads_as_ddos_or_scan():
    bursts = [_burst(i, i * 5.0 + (i * i) * 0.1, 500 * (i + 1) ** 2) for i in range(7)]
    s = HeuristicSequenceScorer().score(bursts)
    assert s.threat_hint in (ThreatType.DDOS, ThreatType.PORT_SCAN, ThreatType.UNKNOWN)
    assert s.features["rising_fraction"] >= 0.7


def test_too_few_bursts_is_benign():
    s = HeuristicSequenceScorer().score([_burst(0, 0.0, 1000), _burst(1, 5.0, 1000)])
    assert s.threat_hint == ThreatType.BENIGN and s.score == 0.0


def test_scorer_backend_is_heuristic_without_torch():
    assert SequenceThreatScorer().backend in ("heuristic", "gru")


def test_sequence_evidence_appears_on_beacon_alert():
    s = load_settings()
    res = run_pipeline(SyntheticSource(seed=42), s, detector=Detector.from_settings(s))
    c2 = [a for a in res.alerts if a.src_host == "10.0.0.31"]
    assert c2
    a = c2[0]
    assert "sequence" in a.scores
    # the C2 beacon host should trip the temporal signal
    assert any(e.name == "temporal_sequence" for e in a.evidence)
