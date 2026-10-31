"""Conservative Terraform saved-plan review and opt-in apply gate.

Do not log raw plan JSON: plan variables, values, and provider settings may
contain plaintext secrets. This is preflight only, not post-apply proof.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .engine import digest
from .approval import validate as validate_approval
from .attest import observe_files, validate_expectations

POLICY_SCHEMA = "agent-proof-pack/terraform-policy/v1"
RECEIPT_SCHEMA = "agent-proof-pack/terraform-review/v1"
KNOWN_ACTIONS = frozenset({"no-op", "read", "create", "update", "delete"})
PLAN_ACTION_SEQUENCES = {
    ("no-op",), ("read",), ("create",), ("update",), ("delete",),
    ("delete", "create"), ("create", "delete"),
}
MAX_PLAN_BYTES = 128 * 1024 * 1024


class TerraformGateError(ValueError):
    """Invalid/untrusted input; fail closed."""


def validate_policy(policy: dict) -> None:
    if not isinstance(policy, dict) or policy.get("schema") != POLICY_SCHEMA:
        raise TerraformGateError("invalid Terraform policy schema")
    if not isinstance(policy.get("id"), str) or not policy["id"]:
        raise TerraformGateError("missing policy id")
    keys = {"schema", "id", "allowed_resource_types", "allowed_actions",
            "max_changed_resources", "protected_addresses", "allowed_output_names",
            "allow_resource_drift", "allow_destructive_addresses"}
    if set(policy) - keys:
        raise TerraformGateError("unknown Terraform policy fields")
    for key in ("allowed_resource_types", "allowed_actions", "protected_addresses",
                "allowed_output_names", "allow_destructive_addresses"):
        value = policy.get(key)
        if not isinstance(value, list) or len(value) != len(set(map(str, value))) or any(
                not isinstance(v, str) or not v for v in value):
            raise TerraformGateError(f"{key} must be a unique string list")
    if not policy["allowed_resource_types"]:
        raise TerraformGateError("explicit allowed_resource_types required")
    if not policy["allowed_actions"] or any(a not in KNOWN_ACTIONS for a in policy["allowed_actions"]):
        raise TerraformGateError("unknown or missing allowed actions")
    if "delete" in policy["allowed_actions"] and not policy["allow_destructive_addresses"]:
        raise TerraformGateError("deletion requires exact allow_destructive_addresses")
    maximum = policy.get("max_changed_resources")
    if type(maximum) is not int or maximum < 0 or maximum > 100000:
        raise TerraformGateError("max_changed_resources must be a bounded integer")
    if type(policy.get("allow_resource_drift")) is not bool:
        raise TerraformGateError("allow_resource_drift must be boolean")
    if set(policy["protected_addresses"]) & set(policy["allow_destructive_addresses"]):
        raise TerraformGateError("protected addresses cannot be approved for destruction")


def _actions(change: dict) -> tuple[str, ...]:
    if not isinstance(change, dict) or not isinstance(change.get("change"), dict):
        raise TerraformGateError("invalid resource change structure")
    actions = change["change"].get("actions")
    if not isinstance(actions, list) or any(not isinstance(a, str) for a in actions):
        raise TerraformGateError("missing/invalid change.actions")
    result = tuple(actions)
    if result not in PLAN_ACTION_SEQUENCES:
        raise TerraformGateError("unknown or unsupported action sequence")
    return result


def _address(change: dict) -> str:
    if not isinstance(change, dict) or not isinstance(change.get("address"), str) or not change["address"]:
        raise TerraformGateError("resource address missing")
    return change["address"]


def review_plan(plan: dict, policy: dict, *, plan_sha256: str | None = None,
                expected_sha256: str | None = None, source: str = "json_fixture") -> dict:
    """Review a plan. JSON-only input is unbound to a saved plan and not an authorization token."""
    validate_policy(policy)
    if not isinstance(plan, dict):
        raise TerraformGateError("plan must be an object")
    checks = []
    changes = []

    def check(condition: bool, code: str, reason: str) -> None:
        checks.append({"code": code, "status": "pass" if condition else "fail",
                       **({"reason": reason} if not condition else {})})

    version = plan.get("format_version")
    check(isinstance(version, str) and bool(re.fullmatch(r"1\.\d+", version)),
          "supported-format", "only Terraform plan JSON 1.x supported")
    check(plan.get("errored") is False, "plan-not-errored", "plan errored or status missing")
    check(plan.get("complete") is True, "plan-complete", "plan incomplete or completeness unknown")
    check(plan.get("applyable") is True, "plan-applyable", "plan not applyable or status unknown")
    for name in ("deferred_changes", "deferred_action_invocations", "action_invocations"):
        check(name not in plan or plan[name] in ([], None), "no-" + name.replace("_", "-"),
              name + " needs a separately reviewed policy")
    drift = plan.get("resource_drift", [])
    if not isinstance(drift, list):
        raise TerraformGateError("invalid resource_drift")
    has_drift = any(_actions(item) != ("no-op",) for item in drift)
    check(not has_drift or policy["allow_resource_drift"], "drift-detected",
          "resource drift detected; investigate before applying")
    tfchecks = plan.get("checks", [])
    if not isinstance(tfchecks, list):
        raise TerraformGateError("invalid Terraform checks")
    check(all(isinstance(item, dict) and item.get("status") == "pass" for item in tfchecks),
          "terraform-checks", "Terraform checks pending, unknown or failed")
    resources = plan.get("resource_changes")
    if not isinstance(resources, list):
        raise TerraformGateError("resource_changes required")
    seen = set()
    for item in resources:
        addr = _address(item)
        if addr in seen:
            raise TerraformGateError("duplicate resource address")
        seen.add(addr)
        actions = _actions(item)
        # A no-op can still move a resource address in Terraform state.
        previous = item.get("previous_address")
        check(previous in (None, addr), "no-state-address-move",
              "state address move requires separate authorization: " + addr)
        # Importing modifies state even when actions look benign; never infer
        # import authorization from create/read/no-op permission.
        check(item["change"].get("importing") is None
              and item["change"].get("generated_config") in (None, ""),
              "no-state-import", "Terraform resource import requires separate authorization: " + addr)
        if item.get("mode") not in ("managed", "data") or not isinstance(item.get("type"), str) or not item["type"]:
            raise TerraformGateError("invalid resource mode/type")
        if actions == ("no-op",):
            continue
        rtype = item["type"]
        check(rtype in policy["allowed_resource_types"], "resource-type-allowed",
              "resource type not authorized: " + addr)
        check(all(a in policy["allowed_actions"] for a in actions), "action-allowed",
              "resource action not allowed: " + addr)
        check(addr not in policy["protected_addresses"], "protected-resource",
              "protected address changed: " + addr)
        if "delete" in actions:
            check(addr in policy["allow_destructive_addresses"], "destructive-operation-approved",
                  "deletion/replacement requires exact resource approval: " + addr)
        changes.append({"address": addr, "actions": list(actions), "type": rtype})
    check(len(changes) <= policy["max_changed_resources"], "change-budget",
          "exceeds maximum changed-resource count")
    outputs = plan.get("output_changes", {})
    if not isinstance(outputs, dict):
        raise TerraformGateError("invalid output_changes")
    for key, value in outputs.items():
        if not isinstance(key, str) or not key or not isinstance(value, dict):
            raise TerraformGateError("invalid output change")
        actions = _actions({"change": value.get("change", value)})
        if actions != ("no-op",):
            check(key in policy["allowed_output_names"], "output-change-allowed",
                  "root output change not authorized: " + key)
    if expected_sha256 is not None:
        check(isinstance(expected_sha256, str) and bool(re.fullmatch(r"[a-f0-9]{64}", expected_sha256))
              and expected_sha256 == plan_sha256, "saved-plan-approval-binding",
              "saved plan differs from independently approved SHA-256")
    receipt = {
        "schema": RECEIPT_SCHEMA, "policy_id": policy["id"],
        "policy_sha256": digest(policy), "plan_sha256": plan_sha256,
        "approval_binding_present": expected_sha256 is not None,
        "source": source,
        "verdict": "approve" if all(c["status"] == "pass" for c in checks) else "block",
        "changed_resources": changes, "changed_resource_count": len(changes),
        "checks": checks,
        "limits": "Preflight only; not independent post-apply verification or transactional authorization.",
    }
    receipt["receipt_sha256"] = digest(receipt)
    return receipt


def saved_plan_sha256(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise TerraformGateError("saved plan must be a regular, non-symlink file")
    if path.stat().st_size > MAX_PLAN_BYTES:
        raise TerraformGateError("saved plan too large")
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def review_saved_plan(path: Path, policy: dict, *, expected_sha256: str | None = None,
                      terraform_bin: str = "terraform") -> dict:
    plan_sha = saved_plan_sha256(path)
    try:
        result = subprocess.run([terraform_bin, "show", "-json", str(path)],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                check=False, timeout=90)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TerraformGateError("terraform show could not run") from exc
    if result.returncode != 0 or not result.stdout or len(result.stdout) > MAX_PLAN_BYTES:
        raise TerraformGateError("terraform show failed or returned oversized output")
    try:
        plan = json.loads(result.stdout)
    except (UnicodeDecodeError, ValueError) as exc:
        raise TerraformGateError("terraform show returned invalid JSON") from exc
    return review_plan(plan, policy, plan_sha256=plan_sha,
                       expected_sha256=expected_sha256, source="saved_plan")


def apply_saved_plan(path: Path, policy: dict, *, approval: dict, approval_key: str,
                     environment: str, expectations: dict, observe_root: Path,
                     terraform_bin: str = "terraform") -> dict:
    """Only an independently signed approval can authorize execution.

    Verify a saved-plan snapshot before execution, then read *actual* filesystem
    bytes independent of Terraform state. Never report verified on exit status.
    This prototype observer covers local_file-like workflows only.
    """
    validate_policy(policy)
    validate_expectations(expectations)
    plan_hash = saved_plan_sha256(path)
    validate_approval(approval, plan_sha256=plan_hash, policy=policy,
                      expectations=expectations, environment=environment,
                      key=approval_key)
    with tempfile.TemporaryDirectory(prefix="agentproof-tf-") as folder:
        snapshot = Path(folder) / "reviewed.tfplan"
        with path.open("rb") as reader, snapshot.open("xb") as writer:
            os.chmod(snapshot, 0o600)
            shutil.copyfileobj(reader, writer)
        review = review_saved_plan(snapshot, policy, expected_sha256=plan_hash,
                                   terraform_bin=terraform_bin)
        if review["verdict"] != "approve":
            return {"state": "refused", "executed": False, "review": review}
        if saved_plan_sha256(snapshot) != plan_hash:
            raise TerraformGateError("snapshot changed after review")
        # Fail if the authorization expired while Terraform was inspected.
        validate_approval(approval, plan_sha256=plan_hash, policy=policy,
                          expectations=expectations, environment=environment,
                          key=approval_key)
        try:
            # Do not print provider logs; they may contain plan secrets.
            proc = subprocess.run([terraform_bin, "apply", "-input=false", str(snapshot)],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  check=False, timeout=3600)
        except (OSError, subprocess.TimeoutExpired):
            return {"state": "indeterminate_execution", "executed": True, "review": review}
        if proc.returncode != 0:
            return {"state": "apply_failed_or_partial", "executed": True,
                    "return_code": proc.returncode, "review": review}
        try:
            observed = observe_files(observe_root, expectations)
        except (OSError, ValueError):
            return {"state": "unverifiable_after_action", "executed": True, "review": review}
        return {"state": "verified" if observed["state"] == "verified"
                else "postcondition_failed", "executed": True,
                "return_code": proc.returncode, "review": review,
                "observation": observed,
                "approver": approval["approver"], "environment": environment}
