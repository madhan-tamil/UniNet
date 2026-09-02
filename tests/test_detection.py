import pytest

from uninet.config import load_settings
from uninet.detection.detector import Detector
from uninet.detection.threat_types import ThreatType
from uninet.ingestion.sources.synthetic import SyntheticSource
from uninet.streaming.worker import run_pipeline


@pytest.fixture(scope="module")
def result():
    settings = load_settings()
    return run_pipeline(SyntheticSource(seed=42), settings, detector=Detector.from_settings(settings))


def _threats_for(result, host):
    return {a.threat_type for a in result.alerts if a.src_host == host}


def test_pipeline_runs_and_builds_graph(result):
    assert result.flow_count > 1000
    assert result.window_count >= 1
    assert result.graph.stats()["nodes"] > 0


def test_ddos_detected(result):
    assert ThreatType.DDOS in _threats_for(result, "10.0.0.20")


def test_c2_beacon_detected(result):
    hits = _threats_for(result, "10.0.0.31")
    assert ThreatType.C2_BEACON in hits or ThreatType.UNKNOWN in hits


def test_dga_detected(result):
    assert ThreatType.DGA in _threats_for(result, "10.0.0.42")


def test_port_scan_detected(result):
    assert ThreatType.PORT_SCAN in _threats_for(result, "10.0.0.53")


def test_benign_hosts_quiet(result):
    for host in ("10.0.0.11", "10.0.0.12", "10.0.0.13"):
        assert not _threats_for(result, host), f"false positive on {host}"


def test_every_alert_has_evidence_and_scores(result):
    for a in result.alerts:
        assert a.evidence, a
        assert set(a.scores) == {"rule", "anomaly", "graph", "sequence"}
        assert 0.0 <= a.confidence <= 1.0
