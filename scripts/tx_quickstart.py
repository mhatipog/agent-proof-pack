"""Run a complete transaction-proof pilot on a fresh disposable Docker PostgreSQL.

No production DSN is accepted. A private container and randomized roles are
created on 127.0.0.1 and removed on exit. Docker + psycopg3 are required.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import pathlib
import secrets
import subprocess
import sys
import time
import uuid

from agentproof.tx_effect import CONTRACT_SCHEMA, observe_transaction, verify_transaction_receipt

ROOT = pathlib.Path(__file__).resolve().parents[1]


def docker(*args: str) -> str:
    result = subprocess.run(
        ["docker", *args], check=True, capture_output=True, text=True, timeout=35)
    return result.stdout.strip()


def wait_for_database(dsn: str):
    import psycopg
    for _ in range(45):
        try:
            with psycopg.connect(dsn, connect_timeout=1):
                return
        except psycopg.OperationalError:
            time.sleep(0.3)
    raise RuntimeError("disposable PostgreSQL service did not become ready")


def issue_grant(dsn: str, action: uuid.UUID, customer_id: str):
    import psycopg
    with psycopg.connect(dsn) as conn:
        conn.execute("""
            INSERT INTO agentproof_guard.action_grants
              (action_id, customer_id, executor_role, from_status, to_status, expires_at)
            VALUES (%s, %s, 'effect_actor', 'open', 'won', %s)
        """, (action, customer_id, datetime.now(timezone.utc) + timedelta(minutes=3)))


def contract(action: uuid.UUID, customer_id: str) -> dict:
    return {
        "schema": CONTRACT_SCHEMA, "id": "crm_status",
        "action_id": str(action), "executor_role": "effect_actor",
        "customer_id": customer_id, "from_status": "open", "to_status": "won",
    }


def demo(*, show_receipt: bool = False) -> dict:
    try:
        import psycopg
        from psycopg import sql
    except ImportError as exc:
        raise RuntimeError("Install the PostgreSQL extra: pip install -e '.[postgresql]'") from exc
    token = uuid.uuid4().hex[:12]
    name = "agentproof-demo-" + token
    password = secrets.token_urlsafe(24)
    actor_password = secrets.token_urlsafe(24)
    reader_password = secrets.token_urlsafe(24)
    # No externally supplied connection strings, and Docker publishes on
    # localhost only. The demo never touches an existing database.
    cid = None
    try:
        cid = docker("run", "--detach", "--rm", "--name", name,
                     "--publish", "127.0.0.1::5432",
                     "--env", "POSTGRES_PASSWORD=" + password,
                     "--env", "POSTGRES_DB=agentproof_demo", "postgres:16")
        address = docker("port", cid, "5432/tcp").splitlines()[0]
        port = int(address.rsplit(":", 1)[1])
        admin = f"postgresql://postgres:{password}@127.0.0.1:{port}/agentproof_demo"
        actor = f"postgresql://effect_actor:{actor_password}@127.0.0.1:{port}/agentproof_demo"
        reader = f"postgresql://effect_reader:{reader_password}@127.0.0.1:{port}/agentproof_demo"
        wait_for_database(admin)
        with psycopg.connect(admin) as conn:
            conn.execute(sql.SQL("CREATE ROLE effect_actor LOGIN PASSWORD {}").format(
                sql.Literal(actor_password)))
            conn.execute(sql.SQL("CREATE ROLE effect_reader LOGIN PASSWORD {}").format(
                sql.Literal(reader_password)))
            conn.execute("GRANT CONNECT ON DATABASE agentproof_demo TO effect_actor, effect_reader")
            conn.execute("GRANT USAGE ON SCHEMA public TO effect_actor, effect_reader")
            conn.execute("CREATE TABLE public.customers(id text PRIMARY KEY, status text NOT NULL, owner text NOT NULL)")
            conn.execute("CREATE TABLE public.invoices(id text PRIMARY KEY, amount integer NOT NULL)")
            conn.execute("INSERT INTO public.customers VALUES ('C-42','open','ada'),('C-99','open','ben')")
            conn.execute("INSERT INTO public.invoices VALUES ('I-1',100)")
        with psycopg.connect(admin, autocommit=True) as conn:
            conn.execute((ROOT / "examples/postgres_tx_guard/install.sql").read_text(encoding="utf8"))
            conn.execute("REVOKE ALL ON public.customers, public.invoices FROM PUBLIC")
            conn.execute("GRANT USAGE ON SCHEMA agentproof_guard TO effect_actor, effect_reader")
            conn.execute("GRANT EXECUTE ON FUNCTION agentproof_guard.apply_customer_status(uuid) TO effect_actor")
            conn.execute("GRANT SELECT ON agentproof_guard.action_grants, agentproof_guard.row_effects, agentproof_guard.committed_actions TO effect_reader")
        key = secrets.token_urlsafe(48)  # verifier-held, generated for this disposable demo
        first = uuid.uuid4()
        second = uuid.uuid4()
        issue_grant(admin, first, "C-42")
        issue_grant(admin, second, "C-99")
        before = observe_transaction(reader, contract(first, "C-42"), key)
        if before["statement"]["predicate"]["status"] != "failed":
            raise RuntimeError("pre-commit evidence should be absent")
        # Truly concurrent, separate approved transactions (different rows).
        # One connection per action; database commit occurs on context exit.
        def apply(action):
            with psycopg.connect(actor) as conn:
                return conn.execute(
                    "SELECT agentproof_guard.apply_customer_status(%s)", (action,)
                ).fetchone()[0]

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(apply, (first, second)))
        if results != ["applied", "applied"]:
            raise RuntimeError("concurrent authorized actions were not applied")
        receipt1 = observe_transaction(reader, contract(first, "C-42"), key)
        receipt2 = observe_transaction(reader, contract(second, "C-99"), key)
        for receipt in (receipt1, receipt2):
            if not verify_transaction_receipt(receipt, key):
                raise RuntimeError("signed receipt failed authentication")
            if receipt["statement"]["predicate"]["status"] != "verified":
                raise RuntimeError("committed action lacks independent row evidence")
        refused = False
        try:
            with psycopg.connect(actor) as conn:
                conn.execute("UPDATE public.invoices SET amount=0 WHERE id='I-1'")
        except psycopg.Error:
            refused = True
        if not refused:
            raise RuntimeError("restricted actor unexpectedly modified invoice")
        with psycopg.connect(admin) as conn:
            states = conn.execute("SELECT id,status FROM public.customers ORDER BY id").fetchall()
            amount = conn.execute("SELECT amount FROM public.invoices WHERE id='I-1'").fetchone()[0]
        if states != [("C-42", "won"), ("C-99", "won")] or amount != 100:
            raise RuntimeError("business data does not match the independent evidence")
        result = {
            "sandbox": "docker-postgresql-16",
            "first_action": receipt1["statement"]["predicate"]["status"],
            "second_action": receipt2["statement"]["predicate"]["status"],
            "approved_actions_executed_concurrently": True,
            "unauthorized_invoice_write": "blocked",
            "invoice_amount_unchanged": True,
            "current_state": "both approved customer changes committed",
            "note": "Only the protected two-table demonstration is covered",
        }
        if show_receipt:
            result["redacted_receipt"] = receipt1
        return result
    finally:
        if cid:
            try:
                docker("rm", "--force", cid)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                print("WARNING: could not remove disposable container " + cid, file=sys.stderr)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--show-receipt", action="store_true",
                        help="include a demo-only authenticated, value-redacted receipt")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(demo(show_receipt=args.show_receipt), indent=2))
        return 0
    except (RuntimeError, OSError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, ValueError) as exc:
        print("disposable demo failed: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
