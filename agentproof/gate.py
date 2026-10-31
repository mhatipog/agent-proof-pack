"""Synchronous adapter: independent policy checks before and after a tool call.

It does not provide transactional rollback; inspect the postflight receipt and
escalate discrepancies. Production integrations should use idempotent tools,
trusted authority readers, and durable receipts in an independent store.
"""
from collections.abc import Callable
from copy import deepcopy
from typing import Any

from .engine import evaluate


def run_guarded(*, pre_policy: dict, post_policy: dict, pre_evidence: dict,
                execute: Callable[[], Any], observe: Callable[[], dict],
                signing_key: str | None = None) -> dict:
    """Only call execute after all preflight checks pass.

    `pre_evidence` must be collected outside the agent; `observe` must read the
    destination itself rather than trusting the agent's success message.
    No exception string is exposed (tool exceptions might contain secrets).
    """
    pre = evaluate(pre_policy, pre_evidence, signing_key=signing_key)
    if pre["verdict"] != "approve":
        return {"state": "refused", "executed": False, "preflight": pre, "postflight": None}
    try:
        execute()
    except Exception:
        # May have partially executed. Never call this a verified failure or success.
        return {"state": "indeterminate_execution", "executed": True,
                "preflight": pre, "postflight": None}
    try:
        after = observe()
    except Exception:
        return {"state": "unverifiable_after_action", "executed": True,
                "preflight": pre, "postflight": None}
    post_evidence = deepcopy(pre_evidence)
    post_evidence["phase"] = "postflight"
    post_evidence["after"] = after
    post = evaluate(post_policy, post_evidence, signing_key=signing_key)
    return {"state": "verified" if post["verdict"] == "approve" else "postcondition_failed",
            "executed": True, "preflight": pre, "postflight": post}
