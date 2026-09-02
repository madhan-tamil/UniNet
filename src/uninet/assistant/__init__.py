"""Read-only analyst assistant (Phase 4).

HARD CONSTRAINT - enforced by tests/test_assistant_readonly.py:
this package must never import networking, subprocess, or packet-crafting modules.
It can READ alerts, evidence, the TB-Graph and explanations; it can do NOTHING
that touches the network, a shell, a firewall, or packet injection.

The assistant is templated and offline - it answers from the context bundle only,
with no LLM call, so the guarantee holds by construction.
"""
from uninet.assistant.assistant import ask, classify
from uninet.assistant.context import AssistantContext, build_context

__all__ = ["AssistantContext", "ask", "build_context", "classify"]
