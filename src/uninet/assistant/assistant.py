"""Read-only analyst assistant (Phase 4).

Answers questions about an alert **entirely from the context bundle** the pipeline
already produced - the alert, its Phase 3 explanation and the TB-Graph subgraph.
It is templated, offline and deterministic: no LLM call, no network, no shell.
That is what keeps ``tests/test_assistant_readonly.py`` green and the passive
architecture intact.

    ask("why is this a c2 beacon?", context)  -> {"intent": "why", "answer": "...", ...}
"""
from __future__ import annotations

import re

from uninet.assistant.context import AssistantContext

# intent -> keyword patterns (first match wins, order matters)
_INTENTS: list[tuple[str, re.Pattern]] = [
    ("confidence", re.compile(r"confiden\w*|certain\w*|\bsure\b|how likely|false.positive|\bfps?\b|\bscore\b", re.IGNORECASE)),
    ("graph", re.compile(r"\bgraph\w*|\bnode\w*|\bburst\w*|subgraph\w*|\bedge\w*|which flows|anchor\w*", re.IGNORECASE)),
    ("timeline", re.compile(r"\bwhen\b|timeline\w*|\btime\b|sequence\w*|first seen|\border\b", re.IGNORECASE)),
    ("peers", re.compile(r"peer\w*|\bwho\b|destination\w*|\bdst\b|talking to|c2 server|which ip", re.IGNORECASE)),
    ("next", re.compile(r"what (should|do)|next step\w*|investigat\w*|recommend\w*|\baction\w*|respond\w*|do now", re.IGNORECASE)),
    ("why", re.compile(r"\bwhy\b|\breason\w*|explain\w*|how do you know|\bevidence\b|\bbecause\b", re.IGNORECASE)),
]

# read-only investigation hints per threat class (never mitigation actions)
_NEXT_STEPS: dict[str, list[str]] = {
    "c2_beacon": [
        "pull the PCAP slice for this window and confirm the check-in interval",
        "look up the destination IP / SNI reputation out-of-band",
        "check whether other internal hosts share this behavioural fingerprint",
    ],
    "ddos": [
        "confirm the target is one of yours and check its upstream capacity",
        "correlate with edge-router flow counters for the same window",
    ],
    "dga": [
        "export the resolved domains and score them against a DGA classifier / feed",
        "check the resolver logs for the NXDOMAIN burst",
    ],
    "port_scan": [
        "list the ports touched and whether any completed a handshake",
        "check if the source is an authorised scanner (vuln-mgmt, asset discovery)",
    ],
    "data_exfil": [
        "identify the destination and whether it is a sanctioned backup / sync target",
        "compare the egress volume to this host's 30-day baseline",
    ],
    "botnet": [
        "cluster hosts by behavioural fingerprint and map their shared peers",
    ],
    "unknown": [
        "review the top deviating features and compare against the host baseline",
        "keep the window's evidence for a later signature once the class is known",
    ],
}

_HELP = (
    "Ask about: why (evidence), confidence (how the score was fused), "
    "graph (which bursts/nodes), peers (destinations), timeline (when), "
    "or next (read-only investigation steps)."
)


def classify(question: str) -> str:
    for name, pat in _INTENTS:
        if pat.search(question or ""):
            return name
    return "summary"


def _answer_why(ex: dict) -> str:
    top = "; ".join(
        f"[{s['signal']}] {s['detail']}" for s in ex.get("signals", [])[:3]
    )
    facts = ", ".join(
        f"{f['label']}={f['value']}" for f in ex.get("key_factors", [])[:4]
    )
    out = ex.get("narrative", "")
    if top:
        out += f"  Top signals: {top}."
    if facts:
        out += f"  Key numbers: {facts}."
    return out.strip()


def _answer_confidence(ex: dict) -> str:
    bars = ex.get("fusion", {}).get("bars", [])
    parts = ", ".join(f"{b['signal']} {b['score']:.2f}" for b in bars)
    return (
        f"Fused confidence {ex.get('confidence', 0):.2f} ({ex.get('severity', '?')}). "
        f"It is a 0.7·strongest + 0.3·weighted blend of {parts}, plus a bonus when "
        f"two independent signals agree. A rule-driven alert with a low anomaly bar "
        f"is still high-precision; a rule + graph agreement is the strongest case."
    )


def _answer_graph(ex: dict, ctx: AssistantContext) -> str:
    anchors = ex.get("graph", {}).get("anchors", [])
    if not anchors:
        return "No specific TB-Graph nodes were tagged; the alert is feature-driven."
    kinds: dict[str, int] = {}
    for a in anchors:
        kinds[a["kind"]] = kinds.get(a["kind"], 0) + 1
    listed = ", ".join(a["id"] for a in anchors[:5])
    sub = ctx.subgraph or {}
    n_nodes = len(sub.get("nodes", []))
    n_edges = len(sub.get("edges", []))
    return (
        f"{sum(kinds.values())} anchor node(s) drove this: "
        + ", ".join(f"{v} {k}" for k, v in kinds.items())
        + f". Anchors: {listed}. The host subgraph has {n_nodes} nodes / {n_edges} edges."
    )


def _answer_timeline(ex: dict) -> str:
    tl = ex.get("timeline", [])
    if not tl:
        w = ex.get("window", [0, 0])
        return f"No per-burst timestamps tagged; window spans {w[0]:.0f}–{w[1]:.0f}."
    lines = [
        f"{i + 1}. burst → {e['peer']}"
        + (f" @ {e['ts']:.0f}" if e.get("ts") is not None else "")
        for i, e in enumerate(tl[:6])
    ]
    return f"{len(tl)} burst event(s) over {ex.get('window_seconds', 0)}s:\n" + "\n".join(lines)


def _answer_peers(alert: dict) -> str:
    peers = alert.get("peers", [])
    if not peers:
        return f"Host {alert.get('src_host')} — no external peer recorded on the alert."
    return (
        f"Host {alert.get('src_host')} → "
        + ", ".join(peers[:8])
        + (f" (+{len(peers) - 8} more)" if len(peers) > 8 else "")
    )


def _answer_next(alert: dict) -> str:
    steps = _NEXT_STEPS.get(alert.get("threat_type", ""), _NEXT_STEPS["unknown"])
    header = "Read-only next steps (UniNet takes no action itself):"
    return header + "\n" + "\n".join(f"- {s}" for s in steps)


def _answer_summary(ex: dict) -> str:
    return f"{ex.get('narrative', '')}\n\n{_HELP}"


def ask(question: str, context: AssistantContext) -> dict:
    ex = context.explanation
    alert = context.alert
    intent = classify(question)
    answer = {
        "why": lambda: _answer_why(ex),
        "confidence": lambda: _answer_confidence(ex),
        "graph": lambda: _answer_graph(ex, context),
        "timeline": lambda: _answer_timeline(ex),
        "peers": lambda: _answer_peers(alert),
        "next": lambda: _answer_next(alert),
        "summary": lambda: _answer_summary(ex),
    }[intent]()

    return {
        "question": question,
        "intent": intent,
        "answer": answer,
        "refs": {
            "alert_id": alert.get("alert_id"),
            "anchors": ex.get("graph_anchors", []),
            "window": ex.get("window"),
        },
        "read_only": True,
    }
