"""Database-enforced witness admission for a *disposable* PostgreSQL transaction gate.

The independent witness mints a short-lived HMAC over a previously committed,
Ed25519-signed receipt. The agent/gateway never sees the symmetric MAC key.
PostgreSQL independently verifies that MAC inside a SECURITY DEFINER wrapper,
then invokes its existing one-use, row-bound grant function in the same transaction.

This is a reference protocol, not a general-purpose production DB firewall.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from uuid import UUID

from .witness_reservations import WitnessDenied, action_hash, receipt_hash

SCHEMA = "agent-proof-pack/witness-db-admission/v1"
_PREFIX = "AgentProof/witness-db/v1"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_TOKEN_AGE_SECONDS = 120
FUTURE_CLOCK_SKEW_SECONDS = 30


def _action(value: str) -> str:
    try:
        if type(value) is not str or str(UUID(value)) != value:
            raise ValueError()
    except (TypeError, ValueError, AttributeError) as exc:
        raise WitnessDenied("invalid witness action") from exc
    return value


def _payload(action_id: str, signed_receipt_sha256: str, issued_at_epoch: int) -> bytes:
    if (not isinstance(signed_receipt_sha256, str)
            or _HEX64.fullmatch(signed_receipt_sha256) is None
            or type(issued_at_epoch) is not int or issued_at_epoch <= 0):
        raise WitnessDenied("malformed database admission")
    return (f"{_PREFIX}\n{_action(action_id)}\n"
            f"{signed_receipt_sha256}\n{issued_at_epoch}").encode("ascii")


def mint_db_admission(receipt: dict, *, action_id: str, mac_key_hex: str) -> dict:
    """Only run inside the independent witness, after durable receipt commit.

    HMAC key is separately installed by a trusted operator in PostgreSQL. It
    must never be configured in the agent process or gateway service.
    """
    if type(mac_key_hex) is not str or _HEX64.fullmatch(mac_key_hex) is None:
        raise WitnessDenied("independent database MAC key missing")
    if (not isinstance(receipt, dict) or set(receipt) != {"record", "signature"}
            or not isinstance(receipt["record"], dict)
            or receipt["record"].get("action_sha256") != action_hash(action_id)
            or type(receipt["record"].get("created_at_ns")) is not int
            or receipt["record"]["created_at_ns"] <= 0):
        raise WitnessDenied("witness receipt action mismatch")
    epoch = receipt["record"]["created_at_ns"] // 1_000_000_000
    r_hash = receipt_hash(receipt)
    mac = hmac.new(bytes.fromhex(mac_key_hex),
                   _payload(action_id, r_hash, epoch), hashlib.sha256).hexdigest()
    return {"schema": SCHEMA, "receipt_sha256": r_hash,
            "issued_at_epoch": epoch, "mac_sha256": mac}


def validate_db_admission(admission: object, *, signed_receipt_sha256: str) -> dict:
    """Gateway checks shape and hash-binding; only PostgreSQL checks the MAC."""
    if (not isinstance(admission, dict) or
            set(admission) != {"schema", "receipt_sha256", "issued_at_epoch", "mac_sha256"} or
            admission["schema"] != SCHEMA or
            admission["receipt_sha256"] != signed_receipt_sha256 or
            type(admission["issued_at_epoch"]) is not int or
            admission["issued_at_epoch"] <= 0 or
            not isinstance(admission["mac_sha256"], str) or
            _HEX64.fullmatch(admission["mac_sha256"]) is None):
        raise WitnessDenied("invalid database-bound witness admission")
    return admission


def apply_with_db_witness(conninfo: str, action_id: str, admission: dict) -> dict:
    """Restricted gateway calls a DB function that validates witness proof.

    The old one-argument generic apply function MUST be revoked from the actor
    role, otherwise that direct route bypasses witness enforcement.
    """
    _action(action_id)
    validate_db_admission(admission, signed_receipt_sha256=admission.get("receipt_sha256")
                          if isinstance(admission, dict) else "")
    if not isinstance(conninfo, str) or not conninfo:
        raise WitnessDenied("protected DB credential required")
    try:
        import psycopg
    except ImportError as exc:
        raise WitnessDenied("PostgreSQL driver unavailable") from exc
    try:
        with psycopg.connect(conninfo, connect_timeout=3) as conn:
            state = conn.execute(
                "SELECT agentproof_witnessed.apply(%s,%s,%s,%s)",
                (UUID(action_id), admission["receipt_sha256"],
                 admission["issued_at_epoch"], admission["mac_sha256"])
            ).fetchone()
            if state is None or state[0] != "applied":
                raise WitnessDenied("witnessed transaction refused")
        return {"action_id": action_id, "state": "submitted_unverified"}
    except psycopg.Error as exc:
        # A disconnected session can be ambiguous after the server committed.
        # Never classify a transport failure as evidence of rollback.
        raise WitnessDenied("witnessed database action unavailable") from exc
