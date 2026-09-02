"""Explainability (Phase 3). Turns fused evidence into human-readable rationale.

Every ``Alert`` already carries structured ``Evidence``; this module renders it as
an ordered "why", concrete key factors, a burst timeline, graph anchors and a
short narrative - all derived from the alert, no model re-run.
"""
from uninet.explainability.explainer import explain_alert, feature_importance

__all__ = ["explain_alert", "feature_importance"]
