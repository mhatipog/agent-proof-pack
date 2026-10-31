"""Short-lived HMAC authorization for a single Terraform plan, policy and expected state.

The key must live with a protected independent approver, never the agent.
"""
import hashlib
import hmac
import re
import secrets
import time
from .engine import canonical, digest

SCHEMA = "agent-proof-pack/terraform-approval/v1"
FIELDS = {"schema", "plan_sha256", "policy_sha256", "expectations_sha256",
          "environment", "approver", "issued_at", "expires_at", "nonce"}
HEX = re.compile(r"^[0-9a-f]{64}$")
MAX_TTL = 3600


class ApprovalError(ValueError):
    """Approval failed closed."""


def _mac(body, key):
    if not isinstance(key, str) or len(key.encode("utf8")) < 32:
        raise ApprovalError("approval key must contain at least 32 bytes")
    return hmac.new(key.encode("utf8"), canonical(body), hashlib.sha256).hexdigest()


def issue(*, plan_sha256, policy, expectations, environment, approver, key,
          ttl_seconds=900, now=None):
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= MAX_TTL:
        raise ApprovalError("TTL must be 1–3600 seconds")
    if not isinstance(plan_sha256, str) or not HEX.fullmatch(plan_sha256):
        raise ApprovalError("invalid plan hash")
    if any(not isinstance(v, str) or not v.strip() or len(v) > 128
           for v in (environment, approver)):
        raise ApprovalError("invalid approval identity/environment")
    issued = int(time.time()) if now is None else now
    if type(issued) is not int or issued < 0:
        raise ApprovalError("invalid issue time")
    body = {"schema": SCHEMA, "plan_sha256": plan_sha256,
            "policy_sha256": digest(policy),
            "expectations_sha256": digest(expectations),
            "environment": environment, "approver": approver,
            "issued_at": issued, "expires_at": issued + ttl_seconds,
            "nonce": secrets.token_hex(16)}
    return {**body, "hmac_sha256": _mac(body, key)}


def validate(approval, *, plan_sha256, policy, expectations, environment, key, now=None):
    if not isinstance(approval, dict) or set(approval) != FIELDS | {"hmac_sha256"}:
        raise ApprovalError("approval has unknown/missing fields")
    body = {k: v for k, v in approval.items() if k != "hmac_sha256"}
    if (body["schema"] != SCHEMA or
        any(not isinstance(body[k], str) or not HEX.fullmatch(body[k])
            for k in ("plan_sha256", "policy_sha256", "expectations_sha256")) or
        not isinstance(body["nonce"], str) or
        not re.fullmatch(r"[0-9a-f]{32}", body["nonce"]) or
        any(not isinstance(body[k], str) or not body[k] or len(body[k]) > 128
            for k in ("approver", "environment"))):
        raise ApprovalError("malformed approval")
    t = int(time.time()) if now is None else now
    start, end = body["issued_at"], body["expires_at"]
    if (type(start) is not int or type(end) is not int or type(t) is not int or
        start > t or end <= t or end <= start or end - start > MAX_TTL):
        raise ApprovalError("approval expired, premature or too long-lived")
    signature = approval["hmac_sha256"]
    if (not isinstance(signature, str) or not HEX.fullmatch(signature) or
        not hmac.compare_digest(signature, _mac(body, key))):
        raise ApprovalError("invalid signature")
    if (body["plan_sha256"] != plan_sha256 or
        body["policy_sha256"] != digest(policy) or
        body["expectations_sha256"] != digest(expectations) or
        body["environment"] != environment):
        raise ApprovalError("plan, policy, expectation or environment changed")

OUTCOME_SCHEMA = "agent-proof-pack/terraform-outcome/v1"


def seal_outcome(result, key):
    """Authenticate the complete outcome at the trusted executor boundary."""
    if not isinstance(result, dict) or "state" not in result:
        raise ApprovalError("invalid outcome")
    body = {**result, "schema": OUTCOME_SCHEMA, "sealed_at": int(time.time())}
    if "receipt_hmac_sha256" in body:
        raise ApprovalError("outcome already has signature")
    return {**body, "receipt_hmac_sha256": _mac(body, key)}


def verify_outcome(receipt, key):
    """Verify HMAC covering the whole outcome, including observed hashes."""
    if not isinstance(receipt, dict) or receipt.get("schema") != OUTCOME_SCHEMA:
        return False
    signature = receipt.get("receipt_hmac_sha256")
    if not isinstance(signature, str) or not HEX.fullmatch(signature):
        return False
    body = {k: v for k, v in receipt.items() if k != "receipt_hmac_sha256"}
    try:
        return hmac.compare_digest(signature, _mac(body, key))
    except (ApprovalError, TypeError, ValueError):
        return False
