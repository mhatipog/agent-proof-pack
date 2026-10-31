"""PostgreSQL read-only effect witness: reuse the exact SQLite reconciliation contract.

Requires optional psycopg3. Intended for a separate role with SELECT-only grants
on *all* watched tables, no row-level-security filtering and no write privileges.
No agent SQL is accepted, and connection errors are redacted.
"""
from __future__ import annotations

import re
from .engine import digest
from .effect import (
    EffectError, _validate_contract, _cell_hash, _pk_hash,
    MAX_ROWS, MAX_CELLS, capture, reconcile,
)

IDENT = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$')


def _pg_snapshot(conninfo: str, contract: dict, key: bytes, *, schema: str = 'public') -> dict:
    try:
        import psycopg
        from psycopg import sql
    except ImportError as exc:
        raise EffectError('PostgreSQL support requires optional psycopg3') from exc
    if not isinstance(conninfo, str) or not conninfo:
        raise EffectError('trusted PostgreSQL connection string required')
    if not isinstance(schema, str) or not IDENT.fullmatch(schema):
        raise EffectError('invalid trusted database schema')
    tables = {}
    cell_count = 0
    try:
        # This observer has no write intent. REPEATABLE READ means every table
        # is observed at the same database snapshot, not mixed time instants.
        with psycopg.connect(conninfo, autocommit=True, connect_timeout=3) as conn:
            conn.execute('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            try:
                conn.execute("SET LOCAL statement_timeout = '5000ms'")
                conn.execute("SET LOCAL lock_timeout = '2000ms'")
                for table in contract['watch_tables']:
                    rel = conn.execute("""
                        SELECT c.oid, c.relrowsecurity, c.relforcerowsecurity
                        FROM pg_catalog.pg_class AS c
                        JOIN pg_catalog.pg_namespace AS n ON c.relnamespace = n.oid
                        WHERE n.nspname = %s AND c.relname = %s AND c.relkind = 'r'
                    """, (schema, table)).fetchone()
                    if rel is None:
                        raise EffectError('watched table missing or not ordinary table')
                    oid, rls, force_rls = rel
                    if rls or force_rls:
                        raise EffectError('RLS could conceal rows; decline incomplete observation')
                    columns_info = conn.execute("""
                        SELECT a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod),
                               a.attnotnull, a.attnum, a.attgenerated, a.attidentity
                        FROM pg_catalog.pg_attribute AS a
                        WHERE a.attrelid = %s AND a.attnum > 0 AND NOT a.attisdropped
                        ORDER BY a.attnum
                    """, (oid,)).fetchall()
                    columns = [r[0] for r in columns_info]
                    if not columns or any(not IDENT.fullmatch(c) for c in columns):
                        raise EffectError('unsupported PostgreSQL column name/schema')
                    pks = conn.execute("""
                        SELECT a.attname
                        FROM pg_catalog.pg_index AS i
                        JOIN LATERAL pg_catalog.unnest(i.indkey)
                          WITH ORDINALITY AS k(attnum, ord) ON true
                        JOIN pg_catalog.pg_attribute AS a
                          ON a.attrelid = i.indrelid AND a.attnum = k.attnum
                        WHERE i.indrelid = %s AND i.indisprimary
                        ORDER BY k.ord
                    """, (oid,)).fetchall()
                    if len(pks) != 1:
                        raise EffectError('watched PostgreSQL table requires a single-column primary key')
                    pk = pks[0][0]
                    if table == contract['target']['table'] and (
                        pk != contract['target']['key_column'] or
                        not set(contract['target']['allowed_columns']).issubset(columns)
                    ):
                        raise EffectError('target primary key or allowed columns do not match schema')
                    indexes = conn.execute("""
                        SELECT pg_catalog.pg_get_indexdef(i.indexrelid)
                        FROM pg_catalog.pg_index AS i
                        WHERE i.indrelid = %s ORDER BY i.indexrelid
                    """, (oid,)).fetchall()
                    triggers = conn.execute("""
                        SELECT t.tgname, pg_catalog.pg_get_triggerdef(t.oid)
                        FROM pg_catalog.pg_trigger AS t
                        WHERE t.tgrelid = %s AND NOT t.tgisinternal
                        ORDER BY t.tgname
                    """, (oid,)).fetchall()
                    constraints = conn.execute("""
                        SELECT conname, pg_catalog.pg_get_constraintdef(oid)
                        FROM pg_catalog.pg_constraint
                        WHERE conrelid = %s ORDER BY conname
                    """, (oid,)).fetchall()
                    table_rows = {}
                    query = sql.SQL('SELECT * FROM {} ORDER BY {}').format(
                        sql.Identifier(schema, table), sql.Identifier(pk))
                    with conn.cursor() as cursor:
                        cursor.execute(query)
                        for n, row in enumerate(cursor, 1):
                            if n > MAX_ROWS:
                                raise EffectError('watched table exceeds bounded row limit')
                            values = dict(zip(columns, row))
                            raw_pk = values[pk]
                            if raw_pk is None:
                                raise EffectError('null primary key encountered')
                            identifier = _pk_hash(key, table, raw_pk)
                            if identifier in table_rows:
                                raise EffectError('duplicate primary key fingerprint')
                            table_rows[identifier] = {
                                column: _cell_hash(key, table, raw_pk, column, values[column])
                                for column in columns
                            }
                            cell_count += len(columns)
                            if cell_count > MAX_CELLS:
                                raise EffectError('watch set exceeds bounded cell count')
                    tables[table] = {
                        'primary_key': pk,
                        'schema_sha256': digest([columns_info, indexes, triggers, constraints]),
                        'rows': table_rows,
                    }
                conn.execute('COMMIT')
            except Exception:
                conn.execute('ROLLBACK')
                raise
    except psycopg.Error as exc:
        raise EffectError('independent PostgreSQL observation unavailable') from exc
    return tables


def capture_postgres(conninfo: str, contract: dict, key: str, *,
                     schema: str = 'public', now: int | None = None) -> dict:
    _validate_contract(contract)
    return capture(None, contract, key, now=now, backend='postgresql',
                   reader=lambda _db, c, k: _pg_snapshot(conninfo, c, k, schema=schema))


def reconcile_postgres(conninfo: str, contract: dict, before: dict, key: str, *,
                       schema: str = 'public', now: int | None = None) -> dict:
    _validate_contract(contract)
    return reconcile(None, contract, before, key, now=now, backend='postgresql',
                     reader=lambda _db, c, k: _pg_snapshot(conninfo, c, k, schema=schema))
