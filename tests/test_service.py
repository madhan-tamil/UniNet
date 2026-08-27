"""Phase 5: host-partitioned sharding must not change detections."""
from uninet.config import load_settings
from uninet.ingestion.sources.synthetic import SyntheticSource
from uninet.streaming.service import run_sharded
from uninet.streaming.worker import run_pipeline


def _threats(result):
    return {(a.src_host, a.threat_type) for a in result.alerts}


def test_sharded_matches_single_shot():
    settings = load_settings()
    single = run_pipeline(SyntheticSource(seed=42), settings)
    sharded = run_sharded(SyntheticSource(seed=42), settings, workers=4, executor="thread")

    assert sharded.flow_count == single.flow_count
    # same hosts flagged with the same threat classes
    assert _threats(sharded) == _threats(single)
    assert sharded.graph.stats()["nodes"] == single.graph.stats()["nodes"]


def test_sharded_falls_back_for_tiny_input():
    settings = load_settings()
    src = SyntheticSource(seed=1)
    out = run_sharded(src, settings, workers=16, executor="thread")
    assert out.flow_count > 0
