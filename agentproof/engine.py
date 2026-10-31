"""Fail-closed, dependency-free verification for externally observed agent actions.

This module never executes the proposed action. The caller must collect authority and
post-action state independently of the agent under inspection.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any

VERSION = "0.1.0"
_MISSING = object()
_KINDS = {
    "equals", "exists_in", "required", "decimal_total", "max_amount",
    "unchanged", "tool_permission", "no_destructive_sql", "state_matches",
    "unique_action", "effects_subset",
}
_DESTRUCTIVE_SQL = re.compile(
    r"\b(?:DROP\s+(?:TABLE|COLUMN|DATABASE|SCHEMA|VIEW|INDEX)|"
    r"TRUNCATE\s+(?:TABLE\s+)?|DELETE\s+FROM|ALTER\s+TABLE\s+\S+\s+DROP)\b",
    re.IGNORECASE,
)


class PolicyError(ValueError):
    """Invalid policy: no action may be authorized with this policy."""


class CheckError(ValueError):
    """A rule cannot be proven from the available observed evidence."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def resolve(document: dict, path: str) -> Any:
    if not isinstance(path, str) or not path or any(not part for part in path.split(".")):
        raise CheckError("invalid evidence path")
    obj: Any = document
    for part in path.split("."):
        if not isinstance(obj, dict) or part not in obj:
            raise CheckError(f"missing evidence: {path}")
        obj = obj[part]
    return obj


def decimal(value: Any, *, money: bool = False) -> Decimal:
    # Floats are inherently approximate; never allow silent float rounding.
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise CheckError("amounts must be decimal strings or integers, never floats")
    try:
        result = Decimal(str(value))
    except InvalidOperation as exc:
        raise CheckError("invalid decimal amount") from exc
    if not result.is_finite():
        raise CheckError("non-finite decimal amount")
    if money and result.as_tuple().exponent < -2:
        raise CheckError("money amount has more than two decimal places")
    return result


def _required(rule: dict, name: str) -> str:
    val = rule.get(name)
    if not isinstance(val, str) or not val:
        raise PolicyError(f"rule {rule.get('id', '?')}: {name} must be a nonempty string")
    return val


def validate_policy(policy: dict) -> None:
    if not isinstance(policy, dict) or not isinstance(policy.get("id"), str) or not policy["id"]:
        raise PolicyError("policy requires nonempty id")
    rules = policy.get("rules")
    if not isinstance(rules, list) or not rules:
        raise PolicyError("empty rule sets fail closed")
    seen = set()
    for r in rules:
        if not isinstance(r, dict):
            raise PolicyError("each rule must be an object")
        rid = _required(r, "id")
        if rid in seen:
            raise PolicyError(f"duplicate rule id: {rid}")
        seen.add(rid)
        kind = r.get("kind")
        if kind not in _KINDS:
            raise PolicyError(f"unsupported rule kind: {kind}")
        if r.get("on_fail", "block") not in ("block", "escalate"):
            raise PolicyError(f"invalid failure treatment: {rid}")
        for attr in {
            "equals": ("left", "right"), "exists_in": ("value", "collection"),
            "required": ("path",), "decimal_total": ("lines", "tax", "total"),
            "max_amount": ("value", "limit"), "unchanged": ("before", "proposed"),
            "tool_permission": ("tool", "resource", "allowed_tools", "allowed_resources"),
            "no_destructive_sql": ("sql",), "state_matches": ("expected", "observed"),
            "unique_action": ("action_id", "processed_ids"),
            "effects_subset": ("observed", "allowed"),
        }[kind]:
            _required(r, attr)


def _check(rule: dict, evidence: dict) -> None:
    kind = rule["kind"]
    p = lambda key: resolve(evidence, rule[key])
    if kind in ("equals", "state_matches"):
        left = p("left" if kind == "equals" else "expected")
        right = p("right" if kind == "equals" else "observed")
        if left != right:
            raise CheckError("observed values differ")
    elif kind == "unchanged":
        if p("before") != p("proposed"):
            raise CheckError("protected field was modified")
    elif kind == "required":
        value = p("path")
        if value is None or value == "" or value == [] or value == {}:
            raise CheckError("required evidence is empty")
    elif kind == "exists_in":
        items = p("collection")
        if not isinstance(items, list):
            raise CheckError("authoritative membership collection is not a list")
        if p("value") not in items:
            raise CheckError("identifier not in authoritative collection")
    elif kind == "decimal_total":
        lines = p("lines")
        if not isinstance(lines, list) or not lines:
            raise CheckError("invoice has no line items")
        subtotal = Decimal("0")
        for line in lines:
            if not isinstance(line, dict) or "quantity" not in line or "unit_price" not in line:
                raise CheckError("invalid invoice line")
            qty = decimal(line["quantity"])
            price = decimal(line["unit_price"], money=True)
            if qty <= 0 or price < 0:
                raise CheckError("quantity/price outside this policy's supported range")
            subtotal += qty * price
        expected = (subtotal + decimal(p("tax"), money=True)).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP)
        actual = decimal(p("total"), money=True)
        if actual != expected:
            raise CheckError("line items + explicit tax do not equal invoice total")
    elif kind == "max_amount":
        if decimal(p("value"), money=True) > decimal(p("limit"), money=True):
            raise CheckError("amount exceeds authorized cap")
    elif kind == "tool_permission":
        tools, resources = p("allowed_tools"), p("allowed_resources")
        if not isinstance(tools, list) or not isinstance(resources, list):
            raise CheckError("permission grants must be lists")
        if p("tool") not in tools or p("resource") not in resources:
            raise CheckError("tool or resource is outside explicit grants")
    elif kind == "no_destructive_sql":
        sql = p("sql")
        if not isinstance(sql, str):
            raise CheckError("SQL must be text")
        if _DESTRUCTIVE_SQL.search(sql):
            raise CheckError("destructive SQL token detected; block for review")
    elif kind == "unique_action":
        ids = p("processed_ids")
        if not isinstance(ids, list):
            raise CheckError("processed action IDs must be a list")
        if p("action_id") in ids:
            raise CheckError("action was already processed")
    elif kind == "effects_subset":
        observed, allowed = p("observed"), p("allowed")
        if not isinstance(observed, list) or not isinstance(allowed, list):
            raise CheckError("observed effects and allowed effects must be lists")
        if any(effect not in allowed for effect in observed):
            raise CheckError("unapproved side effect observed")
    else:
        raise PolicyError("unimplemented rule kind")


def evaluate(policy: dict, evidence: dict, *, signing_key: str | None = None,
             evaluated_at: str | None = None) -> dict:
    """Return a deterministic verdict plus a receipt; never execute actions.

    signing_key (optional) is a secret held by the verifier, not the agent.
    """
    validate_policy(policy)
    if not isinstance(evidence, dict):
        raise PolicyError("evidence must be an object")
    results = []
    for rule in policy["rules"]:
        try:
            _check(rule, evidence)
            results.append({"id": rule["id"], "status": "pass"})
        except (CheckError, TypeError, KeyError, ValueError) as exc:
            results.append({"id": rule["id"], "status": "fail",
                            "on_fail": rule.get("on_fail", "block"),
                            "reason": str(exc)})
    failures = [x for x in results if x["status"] == "fail"]
    verdict = ("block" if any(x["on_fail"] == "block" for x in failures)
               else "escalate" if failures else "approve")
    receipt = {
        "schema": "agent-proof-pack/receipt/v1",
        "verifier_version": VERSION,
        "policy_id": policy["id"],
        "policy_sha256": digest(policy),
        "evidence_sha256": digest(evidence),
        "action_id": evidence.get("action", {}).get("id") if isinstance(evidence.get("action"), dict) else None,
        "phase": evidence.get("phase"),
        "evaluated_at": evaluated_at or datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "checks": results,
        "limits": "Checks attest only to supplied evidence; trusted collection and enforcement are external.",
    }
    receipt["receipt_sha256"] = digest(receipt)
    if signing_key is not None:
        if not signing_key:
            raise PolicyError("empty signing key rejected")
        receipt["hmac_sha256"] = hmac.new(signing_key.encode("utf-8"),
                                          canonical(receipt), hashlib.sha256).hexdigest()
    return receipt


def verify_signature(receipt: dict, key: str) -> bool:
    sig = receipt.get("hmac_sha256")
    if not isinstance(sig, str) or not key:
        return False
    body = {k: v for k, v in receipt.items() if k != "hmac_sha256"}
    expected = hmac.new(key.encode("utf-8"), canonical(body), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected) and body.get("receipt_sha256") == digest(
        {k: v for k, v in body.items() if k != "receipt_sha256"})
