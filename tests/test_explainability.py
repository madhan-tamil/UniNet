"""Phase 3 - explainer output shape and content."""
from uninet.config import load_settings
from uninet.detection.detector import Detector
from uninet.explainability.explainer import explain_alert, feature_importance
from uninet.ingestion.sources.synthetic import SyntheticSource
from uninet.streaming.worker import run_pipeline


def _first_alert():
    s = load_settings()
    res = run_pipeline(SyntheticSource(seed=42), s, detector=Detector.from_settings(s))
    assert res.alerts
    return max(res.alerts, key=lambda a: a.confidence)


def test_explain_alert_has_all_sections():
    ex = explain_alert(_first_alert())
    for key in ("verdict", "confidence", "fusion", "signals", "key_factors",
                "graph", "timeline", "narrative", "window_seconds"):
        assert key in ex, key
    assert ex["signals"], "at least one ranked signal"
    assert isinstance(ex["narrative"], str) and len(ex["narrative"]) > 40
    assert {"rule", "anomaly", "graph"} == {b["signal"] for b in ex["fusion"]["bars"]}
    # legacy keys still present
    assert "why" in ex and "fused_from" in ex


def test_key_factors_are_numeric_and_labelled():
    ex = explain_alert(_first_alert())
    for f in ex["key_factors"]:
        assert isinstance(f["value"], (int, float))
        assert f["label"] and f["from"] in ("rule", "anomaly", "ml", "graph")


def test_graph_anchors_carry_kind():
    ex = explain_alert(_first_alert())
    for a in ex["graph"]["anchors"]:
        assert a["kind"] in ("host", "burst", "domain", "node")


def test_feature_importance_ranks_by_abs_z():
    vec = {"a": 1.0, "b": 2.0, "c": 3.0}
    z = {"a": 0.1, "b": -4.0, "c": 1.5}
    ranked = feature_importance(vec, z, top=2)
    assert [r["feature"] for r in ranked] == ["b", "c"]
    assert ranked[0]["direction"] == "low"
