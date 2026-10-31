"""Synthetic in-memory CRM example. Uses an independently read target state."""
from copy import deepcopy

from agentproof.gate import run_guarded


def demo(mode="success"):
    db = {"C-42": {"status": "open", "owner": "ada"}}
    proposal = {"customer_id": "C-42", "status": "won",
                "expected_after": {"status": "won", "owner": "ada"}}
    proposed_tool = "crm.update" if mode != "unauthorized" else "bank.transfer"
    pre_evidence = {
        "phase": "preflight", "action": {"id": "demo-action-1", "tool": proposed_tool, "resource": "customer:C-42"},
        "before": {"record": deepcopy(db["C-42"])},
        "proposed": proposal,
        "authority": {"customer_ids": list(db)},
        "grants": {"tools": ["crm.update"], "resources": ["customer:C-42"]},
    }
    pre_policy = {"id": "crm/preflight/v1", "rules": [
        {"id": "customer-present", "kind": "exists_in",
         "value": "proposed.customer_id", "collection": "authority.customer_ids"},
        {"id": "allowed-action", "kind": "tool_permission", "tool": "action.tool",
         "resource": "action.resource", "allowed_tools": "grants.tools",
         "allowed_resources": "grants.resources"},
    ]}
    post_policy = {"id": "crm/postflight/v1", "rules": [
        {"id": "read-after-write", "kind": "state_matches",
         "expected": "proposed.expected_after", "observed": "after.record"},
    ]}

    def execute():
        # Simulate lying success: the tool returns without changing anything.
        if mode != "no-op":
            db["C-42"]["status"] = proposal["status"]

    return run_guarded(pre_policy=pre_policy, post_policy=post_policy,
                       pre_evidence=pre_evidence, execute=execute,
                       observe=lambda: {"record": deepcopy(db["C-42"])})


if __name__ == "__main__":
    for mode in ("success", "unauthorized", "no-op"):
        r = demo(mode)
        print(f"{mode:12} -> {r['state']:23} executed={r['executed']}")
