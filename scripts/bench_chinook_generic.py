"""Honest microbenchmark of the protected function vs ordinary SQL.

ONLY run inside the disposable Chinook GitHub test container AFTER generic
gate integration tests. Never touch real customer databases. The baseline
intentionally disables user triggers, which is acceptable only here.
Figures are observations, not a stable throughput guarantee or SLA.
"""
import json
import os
import statistics
import time
import uuid
from datetime import datetime, timedelta, timezone

import psycopg

from agentproof.generic_cli import apply_approved


def median_ms(samples):
    return round(statistics.median(samples) * 1000, 3)


def run():
    admin = os.environ["AGENTPROOF_CHINOOK_ADMIN_DSN"]
    actor = os.environ["AGENTPROOF_CHINOOK_WRITER_DSN"]
    with psycopg.connect(admin) as conn:
        people = conn.execute(
            "SELECT customer_id,email FROM public.customer "
            "WHERE customer_id BETWEEN 3 AND 52 ORDER BY customer_id"
        ).fetchall()
    if len(people) != 50:
        raise RuntimeError("expected 50 independent upstream Chinook customers")
    baseline_people, gated_people = people[:25], people[25:]
    baseline = []
    # Benchmark the native PostgreSQL path without row gate in a throwaway
    # sandbox only. This must never be copied as a production configuration.
    with psycopg.connect(admin) as conn:
        conn.execute("ALTER TABLE public.customer DISABLE TRIGGER USER")
    try:
        for pk, _old in baseline_people:
            start = time.perf_counter()
            with psycopg.connect(admin) as conn:
                conn.execute("UPDATE public.customer SET email=%s WHERE customer_id=%s",
                             (f"baseline-{pk}@local.invalid", pk))
            baseline.append(time.perf_counter() - start)
    finally:
        with psycopg.connect(admin) as conn:
            conn.execute("ALTER TABLE public.customer ENABLE TRIGGER USER")

    approvals = []
    with psycopg.connect(admin) as conn:
        for pk, old in gated_people:
            action = uuid.uuid4()
            after = f"approved-{pk}@local.invalid"
            conn.execute("""
                INSERT INTO agentproof_generic.grants (
                    action_id,target_oid,key_column,key_value,update_column,
                    old_value,new_value,executor_role,expires_at)
                VALUES (%s, 'public.customer'::regclass::oid,
                        'customer_id', %s, 'email', %s, %s,
                        'incident_prod_actor', %s)
            """, (action, str(pk), old, after,
                  datetime.now(timezone.utc) + timedelta(minutes=5)))
            approvals.append((action, pk, after))
    protected = []
    for action, _pk, _after in approvals:
        start = time.perf_counter()
        result = apply_approved(actor, str(action))
        if result["state"] != "submitted_unverified":
            raise RuntimeError("protected action not committed")
        protected.append(time.perf_counter() - start)
    with psycopg.connect(admin) as conn:
        for action, pk, expected in approvals:
            current = conn.execute(
                "SELECT email FROM public.customer WHERE customer_id=%s", (pk,)
            ).fetchone()
            logged = conn.execute(
                "SELECT count(*) FROM agentproof_generic.committed WHERE action_id=%s",
                (action,)
            ).fetchone()[0]
            if current != (expected,) or logged != 1:
                raise RuntimeError("gated benchmark transaction failed independent data check")
    a, b = median_ms(baseline), median_ms(protected)
    return {
        "benchmark": "ephemeral-postgresql-16-chinook-single-row-updates",
        "samples_per_path": 25,
        "native_sql_median_ms": a,
        "gated_sql_median_ms": b,
        "observed_ratio": round(b / a, 2) if a else None,
        "scope": "client connection + one update + commit; does not include witness signing",
        "warning": "Uncontrolled shared CI runner; indicative only, not a production SLA.",
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
