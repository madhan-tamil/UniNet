"""Turn an :class:`Alert` into an analyst-facing explanation (Phase 3).

Everything here is derived from data the detector already put on the alert -
the fused sub-scores, each :class:`Evidence` entry and its ``data`` payload, the
graph anchors and the time window. No model re-run, no I/O.

Output of :func:`explain_alert`:
    verdict / confidence / severity
    fusion      - the rule/anomaly/graph bars that were fused
    signals     - evidence ranked by contribution ("why")
    key_factors - the concrete numbers pulled out of evidence.data
    graph       - anchors with their node kind + a one-line read
    timeline    - ordered burst events reconstructed from the anchors
    narrative   - 2-3 plain-English sentences
"""
from __future__ import annotations

from uninet.schemas.alert import Alert

# Human labels for the numbers rules/anomaly stash in Evidence.data.
_FACTOR_LABELS: dict[str, str] = {
    "flow_count": "flows in window",
    "packets_per_second": "packet rate (pkt/s)",
    "periodicity": "beacon periodicity (0-1)",
    "gap_cov": "inter-burst gap variability",
    "unique_domains": "distinct domains",
    "mean_entropy": "mean domain-label entropy (bits/char)",
    "nxdomain_ratio": "NXDOMAIN ratio",
    "unique_dst_ports": "distinct destination ports",
    "syn_only_ratio": "SYN-only flow ratio",
    "outbound_bytes": "outbound bytes",
    "out_in_ratio": "out:in byte ratio",
    "anomaly_score": "isolation-forest anomaly score",
    "baseline_z_rms": "baseline deviation (z RMS)",
}

_THREAT_BLURB: dict[str, str] = {
    "ddos": "a volumetric flood - many tiny flows aimed at one target",
    "c2_beacon": "command-and-control beaconing - small, clock-regular check-ins",
    "dga": "algorithmically generated domain lookups, typical of DGA malware",
    "port_scan": "host/service reconnaissance - one source sweeping many ports",
    "data_exfil": "bulk egress - sustained outbound volume to a single peer",
    "botnet": "coordinated activity consistent with a bot cohort",
    "unknown": "behaviour that is a clear statistical outlier but matches no known class",
}


def _anchor_kind(node_id: str) -> str:
    return node_id.split(":", 1)[0] if ":" in node_id else "node"


def _key_factors(alert: Alert) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for ev in alert.evidence:
        for k, v in (ev.data or {}).items():
            if k in seen or not isinstance(v, (int, float)):
                continue
            seen.add(k)
            out.append({
                "name": k,
                "label": _FACTOR_LABELS.get(k, k.replace("_", " ")),
                "value": round(float(v), 4),
                "from": ev.kind.value,
            })
    return out


def _timeline(alert: Alert) -> list[dict]:
    """Reconstruct burst events from the graph anchors (id encodes host->peer@ts)."""
    events: list[dict] = []
    for node_id in alert.graph_node_ids:
        if not node_id.startswith("burst:"):
            continue
        body = node_id.split(":", 1)[1]
        peer = body.split("->", 1)[1].split("#", 1)[0] if "->" in body else "?"
        ts = None
        if "@" in body:
            try:
                ts = float(body.rsplit("@", 1)[1])
            except ValueError:
                ts = None
        events.append({"anchor": node_id, "peer": peer, "ts": ts})
    events.sort(key=lambda e: (e["ts"] is None, e["ts"] or 0.0))
    return events


def _narrative(alert: Alert, factors: list[dict]) -> str:
    dur = max(0.0, alert.window_end - alert.window_start)
    lead = (
        f"Host {alert.src_host} is flagged as {alert.threat_type.value} "
        f"({alert.severity.value}, confidence {alert.confidence:.2f}) over a "
        f"{dur:.0f}s window."
    )
    blurb = _THREAT_BLURB.get(alert.threat_type.value)
    why = "; ".join(e.detail for e in alert.evidence[:2]) or alert.summary
    sc = alert.scores or {}
    drivers = ", ".join(
        f"{k} {sc[k]:.2f}" for k in ("rule", "anomaly", "graph") if k in sc
    )
    tail = f" Fused from {drivers}." if drivers else ""
    mid = f" This pattern is {blurb}." if blurb else ""
    return f"{lead}{mid} Evidence: {why}.{tail}"


def explain_alert(alert: Alert) -> dict:
    ordered = sorted(alert.evidence, key=lambda e: -e.score)
    factors = _key_factors(alert)
    return {
        "alert_id": alert.alert_id,
        "verdict": f"{alert.threat_type.value} ({alert.severity.value})",
        "threat_type": alert.threat_type.value,
        "severity": alert.severity.value,
        "confidence": alert.confidence,
        "fusion": {
            "fused_from": alert.scores,
            "bars": [
                {"signal": k, "score": round(alert.scores.get(k, 0.0), 3)}
                for k in ("rule", "anomaly", "graph")
            ],
        },
        # kept for backwards compatibility with existing callers
        "fused_from": alert.scores,
        "why": [
            {"signal": e.kind.value, "name": e.name,
             "weight": round(e.score, 3), "detail": e.detail}
            for e in ordered
        ],
        "signals": [
            {"signal": e.kind.value, "name": e.name,
             "weight": round(e.score, 3), "detail": e.detail, "data": e.data}
            for e in ordered
        ],
        "key_factors": factors,
        "graph": {
            "anchors": [
                {"id": nid, "kind": _anchor_kind(nid)} for nid in alert.graph_node_ids
            ],
        },
        "graph_anchors": alert.graph_node_ids,
        "timeline": _timeline(alert),
        "narrative": _narrative(alert, factors),
        "window": [alert.window_start, alert.window_end],
        "window_seconds": round(max(0.0, alert.window_end - alert.window_start), 1),
    }


def feature_importance(
    vector: dict[str, float], baseline_z: dict[str, float] | None = None, top: int = 8
) -> list[dict]:
    """Rank features by |z| deviation from the per-host baseline.

    Standalone helper (not needed for the alert-only path above) - useful for
    training diagnostics and a future per-feature panel.
    """
    z = baseline_z or {}
    rows = [
        {
            "feature": k,
            "value": round(float(vector.get(k, 0.0)), 4),
            "z": round(float(z.get(k, 0.0)), 3),
            "direction": "high" if z.get(k, 0.0) >= 0 else "low",
        }
        for k in vector
    ]
    rows.sort(key=lambda r: -abs(r["z"]))
    return rows[:top]
