"""Minimal usable boundary for the configurable PostgreSQL transaction gate.

Writer: receives only a previously issued UUID; NEVER an SQL string or grant.
Witness: separate role and HMAC key; checks protected committed records AND
the actual current database row under one consistent read-only transaction.
All SQL identifiers originate from PostgreSQL's catalog and are quoted.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hmac
import json
import os
import re
import sys
from uuid import UUID

from .effect import EffectError, _secret, _mac
from .engine import canonical, digest

CONTRACT_SCHEMA = "agent-proof-pack/generic-transaction-contract/v1"
PREDICATE_TYPE = ("https://github.com/mhatipog/agent-proof-pack/blob/main/"
                  "docs/GENERIC_TRANSACTION_GATE.md#outcome-v1")
HEX = re.compile(r"^[a-f0-9]{64}$")
IDENT = re.compile(r"^[A-Za-z_][A-Za-z_0-9]{0,62}$")
FIELDS = {"schema", "id", "action_id", "executor_role", "table",
          "key_column", "key_value", "update_column", "old_value", "new_value"}


def _uuid(value):
    if not isinstance(value, str):
        raise EffectError("action id must be canonical UUID")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exc:
        raise EffectError("invalid action UUID") from exc
    if str(parsed) != value:
        raise EffectError("action UUID must be lowercase and canonical")
    return parsed


def validate_contract(contract):
    if not isinstance(contract, dict) or set(contract) != FIELDS:
        raise EffectError("invalid generic action contract fields")
    if contract["schema"] != CONTRACT_SCHEMA:
        raise EffectError("unsupported generic action contract")
    _uuid(contract["action_id"])
    if not all(isinstance(contract[k], str) and IDENT.fullmatch(contract[k])
               for k in ("id", "executor_role", "key_column", "update_column")):
        raise EffectError("invalid table or role identifier")
    table = contract["table"]
    if (not isinstance(table, str) or len(table.split(".")) != 2 or
        not all(IDENT.fullmatch(part) for part in table.split("."))):
        raise EffectError("table must be explicit schema.table")
    if contract["key_column"] == contract["update_column"]:
        raise EffectError("primary key cannot be the changed column")
    for name in ("key_value", "old_value", "new_value"):
        val = contract[name]
        if not isinstance(val, str) or not val or len(val.encode("utf8")) > 1024:
            raise EffectError("invalid expected transaction value")
    if contract["old_value"] == contract["new_value"]:
        raise EffectError("contract must specify an actual transition")


def apply_approved(conninfo: str, action_id: str) -> dict:
    """Use an agent-only DB identity with EXECUTE, not table/grant privileges."""
    identifier = _uuid(action_id)
    if not isinstance(conninfo, str) or not conninfo:
        raise EffectError("agent EXECUTE-only DSN is missing")
    try:
        import psycopg
    except ImportError as exc:
        raise EffectError("install psycopg optional extra") from exc
    try:
        with psycopg.connect(conninfo, connect_timeout=3) as conn:
            # No raw agent SQL or arbitrary table/column name accepted.
            state = conn.execute(
                "SELECT agentproof_generic.apply_text_change(%s)", (identifier,)
            ).fetchone()
            if not state or state[0] != "applied":
                raise EffectError("protected SQL function refused the action")
        return {"action_id": action_id, "state": "submitted_unverified",
                "note": "Committed by restricted writer; check via separate witness"}
    except psycopg.Error as exc:
        raise EffectError("database refused or could not commit requested action") from exc


def _read(conninfo, contract):
    try:
        import psycopg
        from psycopg import sql
    except ImportError as exc:
        raise EffectError("install psycopg optional extra") from exc
    if not isinstance(conninfo, str) or not conninfo:
        raise EffectError("independent SELECT-only DSN missing")
    identifier = _uuid(contract["action_id"])
    try:
        with psycopg.connect(conninfo, connect_timeout=3, autocommit=True) as conn:
            conn.execute("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            conn.execute("SET LOCAL statement_timeout = '5000ms'")
            grant = conn.execute("""
                SELECT target_oid, key_column::text, key_value,
                       update_column::text, old_value, new_value,
                       executor_role::text, consumed_at, revoked_at
                FROM agentproof_generic.grants WHERE action_id = %s
            """, (identifier,)).fetchone()
            committed = conn.execute("""
                SELECT target_oid, key_column::text, key_value,
                       update_column::text, old_value, new_value,
                       executor_role::text, txid
                FROM agentproof_generic.committed WHERE action_id = %s
            """, (identifier,)).fetchone()
            current = None
            relation = None
            if grant is not None:
                relation = conn.execute("""
                    SELECT n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity
                    FROM pg_catalog.pg_class c
                    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                    WHERE c.oid = %s AND c.relkind = 'r'
                """, (grant[0],)).fetchone()
                if relation and (relation[2] or relation[3]):
                    raise EffectError("row-level security can conceal an effect")
                if relation and f"{relation[0]}.{relation[1]}" == contract["table"]:
                    q = sql.SQL("SELECT {}::text FROM {} WHERE {}::text = %s").format(
                        sql.Identifier(contract["update_column"]),
                        sql.Identifier(relation[0], relation[1]),
                        sql.Identifier(contract["key_column"]),
                    )
                    rows = conn.execute(q, (contract["key_value"],)).fetchmany(2)
                    current = rows[0][0] if len(rows) == 1 else None
            conn.execute("COMMIT")
            return grant, committed, relation, current
    except psycopg.Error as exc:
        raise EffectError("independent database query failed") from exc


def observe_approved(conninfo, contract, key):
    validate_contract(contract)
    secret = _secret(key)
    grant, committed, relation, current = _read(conninfo, contract)
    checks = []

    def check(name, ok):
        checks.append({"id": name, "status": "pass" if ok else "fail"})

    expected = (contract["key_column"], contract["key_value"],
                contract["update_column"], contract["old_value"],
                contract["new_value"], contract["executor_role"])
    check("grant-exists", grant is not None)
    check("grant-matches-contract", grant is not None and tuple(grant[1:7]) == expected)
    check("grant-consumed-and-not-revoked",
          grant is not None and grant[7] is not None and grant[8] is None)
    check("committed-action-exists", committed is not None)
    check("committed-action-matches",
          committed is not None and tuple(committed[1:7]) == expected)
    check("same-target-relation", grant is not None and committed is not None and
          grant[0] == committed[0])
    check("relation-matches-contract", relation is not None and
          f"{relation[0]}.{relation[1]}" == contract["table"])
    check("current-row-matches", current == contract["new_value"])
    check("committed-transaction-recorded", committed is not None and
          type(committed[7]) is int and committed[7] > 0)
    status = "verified" if all(c["status"] == "pass" for c in checks) else "failed"
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "postgresql/approved-row-effect",
                     "digest": {"sha256": digest(contract)}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "schema": "agent-proof-pack/generic-transaction-outcome/v1",
            "contract_sha256": digest(contract), "status": status,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "checks": checks,
            "limitations": [
                "Confirms the current watched row and committed-action record at observation time",
                "Only explicitly enrolled tables; no external side effect guarantee",
                "Database owners may bypass enforcement or modify evidence",
                "Not proof of the identity of a human approver",
            ],
        },
    }
    return {"statement": statement,
            "witness_hmac_sha256": _mac(secret, canonical(statement))}


def verify_outcome(receipt, key):
    try:
        if not isinstance(receipt, dict) or set(receipt) != {"statement", "witness_hmac_sha256"}:
            return False
        statement = receipt["statement"]
        if (not isinstance(statement, dict) or
            statement.get("_type") != "https://in-toto.io/Statement/v1" or
            statement.get("predicateType") != PREDICATE_TYPE or
            not isinstance(statement.get("predicate"), dict) or
            statement["predicate"].get("schema") != "agent-proof-pack/generic-transaction-outcome/v1" or
            statement["predicate"].get("status") not in ("verified", "failed")):
            return False
        mac = receipt["witness_hmac_sha256"]
        return (isinstance(mac, str) and bool(HEX.fullmatch(mac)) and
                hmac.compare_digest(mac, _mac(_secret(key), canonical(statement))))
    except (TypeError, ValueError, KeyError):
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(prog="agent-guarded",
                                     description="One-use PostgreSQL action, separate independent outcome witness")
    sub = parser.add_subparsers(dest="command", required=True)
    apply = sub.add_parser("apply", help="agent-side, only a preapproved UUID; no agent SQL")
    apply.add_argument("--action-id", required=True)
    # Actor credentials come from exactly one fixed protected variable; an
    # untrusted agent cannot choose another environment secret to use.
    obs = sub.add_parser("observe", help="trusted verifier: read-only after-state and transaction record")
    obs.add_argument("--contract", required=True)
    obs.add_argument("--dsn-env", required=True)
    obs.add_argument("--key-env", required=True)
    obs.add_argument("--output", required=True)
    check = sub.add_parser("check", help="authenticate a previously captured receipt")
    check.add_argument("--receipt", required=True)
    check.add_argument("--key-env", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "apply":
            result = apply_approved(os.environ.get("AGENTPROOF_ACTOR_DSN"), args.action_id)
        elif args.command == "observe":
            if args.dsn_env == args.key_env:
                raise EffectError("reader DSN and witness key must be separate")
            with open(args.contract, encoding="utf8") as f:
                contract = json.load(f)
            result = observe_approved(os.environ.get(args.dsn_env), contract,
                                      os.environ.get(args.key_env))
            # Exclusive creation with owner-only permissions; must be protected
            # from the agent, preferably stored outside agent working directory.
            fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "w", encoding="utf8") as file:
                json.dump(result, file, indent=2)
                file.write("\n")
        else:
            with open(args.receipt, encoding="utf8") as f:
                result = json.load(f)
            good = verify_outcome(result, os.environ.get(args.key_env))
            print("VALID" if good else "INVALID")
            return 0 if good else 4
        print(json.dumps(result, indent=2))
        if args.command == "apply":
            return 0
        return 0 if result["statement"]["predicate"]["status"] == "verified" else 4
    except (EffectError, OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print("guarded action unavailable: " + str(exc), file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
