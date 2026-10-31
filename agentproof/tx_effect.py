"""Verify a transaction-bound PostgreSQL row effect without whole-table scans.

Experimental, specific to the two-table guarded sandbox. Only a separate
SELECT-only observer sees protected grant, row-effect and committed-action
records. These rows are transactional evidence, not immutable audit history
or proof of effects on tables not covered by the installed SQL gate.
"""
from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import sys
from uuid import UUID

from .effect import EffectError, _mac, _secret
from .engine import canonical, digest

CONTRACT_SCHEMA = "agent-proof-pack/transaction-effect-contract/v1"
PREDICATE_SCHEMA = "agent-proof-pack/transaction-effect-predicate/v1"
PREDICATE_TYPE = (
    "https://github.com/mhatipog/agent-proof-pack/blob/main/"
    "docs/TRANSACTION_EVIDENCE.md#predicate-v1"
)
FIELDS = {"schema", "id", "action_id", "executor_role", "customer_id",
          "from_status", "to_status"}
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


def _validate_contract(contract: dict) -> str:
    if not isinstance(contract, dict) or set(contract) != FIELDS:
        raise EffectError("invalid transaction effect contract fields")
    if contract["schema"] != CONTRACT_SCHEMA:
        raise EffectError("unsupported transaction effect contract version")
    if not isinstance(contract["id"], str) or not IDENT.fullmatch(contract["id"]):
        raise EffectError("invalid transaction effect contract identity")
    if not isinstance(contract["executor_role"], str) or not IDENT.fullmatch(contract["executor_role"]):
        raise EffectError("invalid expected executor role")
    for name in ("customer_id", "from_status", "to_status"):
        value = contract[name]
        if not isinstance(value, str) or not (1 <= len(value.encode("utf8")) <= 1024):
            raise EffectError("invalid expected transaction value")
    if contract["from_status"] == contract["to_status"]:
        raise EffectError("transaction contract must demand a status transition")
    action_id = contract["action_id"]
    if not isinstance(action_id, str):
        raise EffectError("invalid action identifier")
    try:
        exact = str(UUID(action_id))
    except (ValueError, AttributeError) as exc:
        raise EffectError("invalid UUID action identifier") from exc
    if action_id != exact:
        raise EffectError("action identifier must be canonical lowercase UUID")
    return exact


def _read_records(conninfo: str, action_id: str):
    """All three protected records come from one repeatable-read snapshot."""
    if not isinstance(conninfo, str) or not conninfo:
        raise EffectError("protected read-only PostgreSQL DSN required")
    try:
        import psycopg
    except ImportError as exc:
        raise EffectError("transaction observer requires optional psycopg3") from exc
    try:
        with psycopg.connect(conninfo, autocommit=True, connect_timeout=3) as conn:
            conn.execute("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            try:
                conn.execute("SET LOCAL statement_timeout = '5000ms'")
                conn.execute("SET LOCAL lock_timeout = '2000ms'")
                grant = conn.execute("""
                    SELECT executor_role::text, customer_id, from_status,
                           to_status, consumed_at
                      FROM agentproof_guard.action_grants WHERE action_id = %s
                """, (UUID(action_id),)).fetchone()
                committed = conn.execute("""
                    SELECT transaction_id, executor_role::text, customer_id,
                           from_status, to_status
                      FROM agentproof_guard.committed_actions WHERE action_id = %s
                """, (UUID(action_id),)).fetchone()
                effect = conn.execute("""
                    SELECT transaction_id, customer_id, from_status, to_status
                      FROM agentproof_guard.row_effects WHERE action_id = %s
                """, (UUID(action_id),)).fetchone()
                conn.execute("COMMIT")
                return grant, committed, effect
            except Exception:
                conn.execute("ROLLBACK")
                raise
    except psycopg.Error as exc:
        raise EffectError("independent transaction evidence unavailable") from exc


def observe_transaction(conninfo: str, contract: dict, key: str) -> dict:
    """Independently inspect committed action and exact guarded row effect.

    The *operator* supplies the contract. The writer cannot access the
    verifier's credentials, HMAC key or independently approved contract.
    """
    action_id = _validate_contract(contract)
    secret = _secret(key)
    grant, committed, effect = _read_records(conninfo, action_id)
    checks = []

    def check(name: str, value: bool):
        checks.append({"id": name, "status": "pass" if value else "fail"})

    expect = (contract["executor_role"], contract["customer_id"],
              contract["from_status"], contract["to_status"])
    check("grant-exists", grant is not None)
    check("grant-matches-operator-contract",
          grant is not None and tuple(grant[:4]) == expect)
    check("grant-consumed", grant is not None and grant[4] is not None)
    check("committed-action-exists", committed is not None)
    check("committed-action-matches", committed is not None and tuple(committed[1:]) == expect)
    check("guarded-row-effect-exists", effect is not None)
    check("guarded-row-transition-matches",
          effect is not None and tuple(effect[1:]) == expect[1:])
    check("same-transaction",
          committed is not None and effect is not None and
          isinstance(committed[0], int) and committed[0] == effect[0])
    verified = all(c["status"] == "pass" for c in checks)
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "postgresql/guarded-action",
                     "digest": {"sha256": digest(contract)}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "schema": PREDICATE_SCHEMA,
            "backend": "postgresql",
            "status": "verified" if verified else "failed",
            "contract_sha256": digest(contract),
            "checks": checks,
            "scope": {
                "guard": "postgres_tx_guard/v1",
                "protected_tables": ["customers", "invoices"],
                "evidence": "transaction-bound; no current-row read",
            },
            "limitations": [
                "Database owner can modify or erase receipt tables",
                "Only installed triggers and privileges bound the protected scope",
                "Does not assert the current state of a subsequently changed row",
                "Not external append-only storage or a proof of human identity",
            ],
        },
    }
    return {"statement": statement,
            "witness_hmac_sha256": _mac(secret, canonical(statement))}


def verify_transaction_receipt(receipt: dict, key: str) -> bool:
    """Authenticate the issued statement; this cannot re-observe database truth."""
    try:
        if not isinstance(receipt, dict) or set(receipt) != {"statement", "witness_hmac_sha256"}:
            return False
        statement = receipt["statement"]
        if not isinstance(statement, dict) or set(statement) != {
                "_type", "subject", "predicateType", "predicate"}:
            return False
        predicate = statement["predicate"]
        if (statement["_type"] != "https://in-toto.io/Statement/v1"
                or statement["predicateType"] != PREDICATE_TYPE
                or not isinstance(predicate, dict)
                or predicate.get("schema") != PREDICATE_SCHEMA
                or predicate.get("status") not in ("verified", "failed")):
            return False
        mac = receipt["witness_hmac_sha256"]
        return (isinstance(mac, str) and bool(re.fullmatch(r"[0-9a-f]{64}", mac))
                and hmac.compare_digest(mac, _mac(_secret(key), canonical(statement))))
    except (EffectError, TypeError, ValueError, KeyError, OverflowError):
        return False


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent-tx-effect",
        description="Independent transaction-bound PostgreSQL witness (experimental sandbox)")
    parser.add_argument("--contract", required=True, help="operator-owned JSON contract")
    parser.add_argument("--dsn-env", required=True, help="name of protected SELECT-only PG DSN env var")
    parser.add_argument("--key-env", required=True, help="name of verifier-held HMAC key env var")
    parser.add_argument("--output", help="exclusive output path for authenticated receipt")
    args = parser.parse_args(argv)
    try:
        if not args.dsn_env.startswith("AGENTPROOF_") or args.dsn_env == args.key_env:
            raise EffectError("use separate AGENTPROOF_-prefixed environment secrets")
        with open(args.contract, encoding="utf8") as source:
            contract = json.load(source)
        result = observe_transaction(
            os.environ.get(args.dsn_env, ""), contract, os.environ.get(args.key_env, ""))
        if not verify_transaction_receipt(result, os.environ.get(args.key_env, "")):
            raise EffectError("receipt integrity check failed")
        if args.output:
            fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "w", encoding="utf8") as dest:
                json.dump(result, dest, indent=2)
                dest.write("\n")
        else:
            print(json.dumps(result, indent=2))
        return 0 if result["statement"]["predicate"]["status"] == "verified" else 4
    except (EffectError, ValueError, OSError, TypeError, json.JSONDecodeError) as exc:
        print("transaction effect unavailable: " + str(exc), file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
