"""Independent, bounded SQLite effect witness.

Captures signed, value-redacted before-state, then reconciles a read-only
snapshot of the system of record against a narrow, operator-owned contract.
No SQL from agents is executed. No raw values enter published evidence.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import sqlite3
import time
from pathlib import Path
from typing import Any

from .engine import canonical, digest

SCHEMA = 'agent-proof-pack/sqlite-effect-contract/v1'
SNAPSHOT_SCHEMA = 'agent-proof-pack/effect-snapshot/v2'
PREDICATE_TYPE = 'https://github.com/mhatipog/agent-proof-pack/blob/main/docs/PROOF_OF_EFFECT.md#predicate-v1'
IDENT = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$')
MAX_TABLES = 8
MAX_ROWS = 10000
MAX_CELLS = 200000
MAX_VALUE_BYTES = 1_000_000
MAX_AGE_SECONDS = 600


class EffectError(ValueError):
    """A trustworthy effect witness could not be established (fail closed)."""


def _secret(key: str) -> bytes:
    if not isinstance(key, str) or len(key.encode('utf8')) < 32:
        raise EffectError('verifier key must contain at least 32 bytes')
    return key.encode('utf8')


def _validate_contract(contract: dict) -> None:
    if not isinstance(contract, dict) or set(contract) != {'schema', 'id', 'watch_tables', 'target'}:
        raise EffectError('invalid contract schema or fields')
    if contract['schema'] != SCHEMA or not isinstance(contract['id'], str) or not IDENT.fullmatch(contract['id']):
        raise EffectError('invalid contract identity')
    tables = contract['watch_tables']
    if not isinstance(tables, list) or not (1 <= len(tables) <= MAX_TABLES) or len(set(tables)) != len(tables):
        raise EffectError('watched table set is missing, repeated or oversized')
    if any(not isinstance(name, str) or not IDENT.fullmatch(name) or name.startswith('sqlite_') for name in tables):
        raise EffectError('unsafe table identifier')
    target = contract['target']
    if not isinstance(target, dict) or set(target) != {'table', 'key_column', 'key', 'expected', 'allowed_columns', 'require_change'}:
        raise EffectError('invalid target contract fields')
    if target['table'] not in tables or not isinstance(target['key_column'], str) or not IDENT.fullmatch(target['key_column']):
        raise EffectError('target table/key column not covered')
    if not isinstance(target['key'], (str, int)) or isinstance(target['key'], bool):
        raise EffectError('target key must be an exact string or integer')
    if not isinstance(target['expected'], dict) or not target['expected']:
        raise EffectError('expected result required')
    columns = target['allowed_columns']
    if not isinstance(columns, list) or not columns or len(set(columns)) != len(columns):
        raise EffectError('allowed columns required')
    if any(not isinstance(x, str) or not IDENT.fullmatch(x) for x in columns):
        raise EffectError('unsafe allowed column')
    if (any(not isinstance(x, str) or not IDENT.fullmatch(x) for x in target['expected']) or
        not set(target['expected']).issubset(columns) or target['key_column'] in columns):
        raise EffectError('expected fields must be allowed non-key columns')
    if type(target['require_change']) is not bool:
        raise EffectError('require_change must be boolean')
    for value in [target['key'], *target['expected'].values()]:
        _encode_value(value)


def _encode_value(value: Any) -> bytes:
    # Explicit type tagging avoids '1' vs 1 collisions and plaintext leakage.
    if value is None:
        obj = ['null', None]
    elif isinstance(value, bool):
        # SQLite stores booleans as integers; require canonical integer expectations.
        raise EffectError('SQLite bool expectation is ambiguous; use integer 0/1')
    elif isinstance(value, int):
        obj = ['int', value]
    elif isinstance(value, str):
        obj = ['text', value]
    elif isinstance(value, bytes):
        obj = ['blob', base64.b64encode(value).decode('ascii')]
    elif isinstance(value, float) and math.isfinite(value):
        obj = ['real', value]
    else:
        raise EffectError('unsupported or non-finite database value')
    encoded = canonical(obj)
    if len(encoded) > MAX_VALUE_BYTES:
        raise EffectError('oversized value')
    return encoded


def _mac(key: bytes, value: bytes) -> str:
    return hmac.new(key, value, hashlib.sha256).hexdigest()


def _cell_hash(key: bytes, table: str, pk: Any, column: str, value: Any) -> str:
    return _mac(key, canonical(['cell', table, _encode_value(pk).decode('utf8'), column,
                                _encode_value(value).decode('utf8')]))


def _pk_hash(key: bytes, table: str, pk: Any) -> str:
    return _mac(key, canonical(['pk', table, _encode_value(pk).decode('utf8')]))


def _snapshot(db: Path, contract: dict, key: bytes) -> dict:
    # URI read-only mode prevents changing the database. Separate observer access
    # controls are deployment obligations; the agent must not control this path.
    db = Path(db)
    if not db.is_file() or db.is_symlink():
        raise EffectError('database must be an existing non-symlink file')
    conn = None
    try:
        conn = sqlite3.connect(db.resolve().as_uri() + '?mode=ro', uri=True, timeout=2)
        conn.execute('PRAGMA query_only = ON')
        conn.execute('BEGIN')
        found = {}
        cell_count = 0
        for table in contract['watch_tables']:
            # sqlite_master inspection guarantees a physical table, not a view.
            kind = conn.execute('SELECT type FROM sqlite_master WHERE name=?', (table,)).fetchone()
            if kind != ('table',):
                raise EffectError('watched resource is not a physical table')
            info = conn.execute(f'PRAGMA table_info("{table}")').fetchall()
            if not info or any(not IDENT.fullmatch(row[1]) for row in info):
                raise EffectError('unsupported table schema')
            pks = [item[1] for item in info if item[5] > 0]
            if len(pks) != 1:
                raise EffectError('each watched table requires a single declared primary key')
            pk_name = pks[0]
            if table == contract['target']['table'] and pk_name != contract['target']['key_column']:
                raise EffectError('target key is not authoritative declared primary key')
            columns = [item[1] for item in info]
            if table == contract['target']['table'] and not set(
                    contract['target']['allowed_columns']).issubset(columns):
                raise EffectError('allowed target columns must exist in actual schema')
            table_rows = {}
            query = f'SELECT * FROM "{table}" ORDER BY "{pk_name}"'
            cursor = conn.execute(query)
            for n, row in enumerate(cursor, 1):
                if n > MAX_ROWS:
                    raise EffectError('watched table exceeds bounded row limit')
                data = dict(zip(columns, row))
                pk = data[pk_name]
                if pk is None:
                    raise EffectError('primary key cannot be null')
                hashed_pk = _pk_hash(key, table, pk)
                if hashed_pk in table_rows:
                    raise EffectError('duplicate key encountered')
                table_rows[hashed_pk] = {column: _cell_hash(key, table, pk, column, data[column])
                                         for column in columns}
                cell_count += len(columns)
                if cell_count > MAX_CELLS:
                    raise EffectError('snapshot exceeds bounded cell limit')
            found[table] = {'primary_key': pk_name, 'schema_sha256': digest(info),
                            'rows': table_rows}
        conn.commit()
        return found
    except (sqlite3.Error, OSError) as exc:
        raise EffectError('independent database observation unavailable') from exc
    finally:
        if conn is not None:
            conn.close()


def _payload(contract: dict, tables: dict, at: int, backend: str) -> dict:
    return {'schema': SNAPSHOT_SCHEMA, 'contract_sha256': digest(contract),
            'captured_at': at, 'backend': backend, 'tables': tables}


def capture(db: Path, contract: dict, key: str, *, now: int | None = None,
            reader=None, backend: str = 'sqlite') -> dict:
    """Issue a signed redacted before-snapshot. Run outside the agent runtime."""
    _validate_contract(contract)
    secret = _secret(key)
    at = int(time.time()) if now is None else now
    if type(at) is not int or at < 0:
        raise EffectError('invalid capture time')
    if not isinstance(backend, str) or backend not in ('sqlite', 'postgresql'):
        raise EffectError('unsupported observer backend')
    p = _payload(contract, (reader or _snapshot)(db, contract, secret), at, backend)
    return {**p, 'hmac_sha256': _mac(secret, canonical(p))}


def _verify_before(before: dict, contract: dict, key: bytes, *, now: int, backend: str):
    if not isinstance(before, dict) or set(before) != {'schema', 'contract_sha256',
                                                        'captured_at', 'backend', 'tables', 'hmac_sha256'}:
        raise EffectError('invalid signed snapshot fields')
    body = {k: v for k, v in before.items() if k != 'hmac_sha256'}
    sig = before['hmac_sha256']
    if (not isinstance(sig, str) or not re.fullmatch(r'[a-f0-9]{64}', sig) or
        not hmac.compare_digest(sig, _mac(key, canonical(body))) or
        body['schema'] != SNAPSHOT_SCHEMA or body['contract_sha256'] != digest(contract) or
        body['backend'] != backend):
        raise EffectError('before snapshot signature/contract invalid')
    at = body['captured_at']
    if type(at) is not int or not (at <= now <= at + MAX_AGE_SECONDS):
        raise EffectError('snapshot expired or issued in future')
    if not isinstance(body['tables'], dict) or set(body['tables']) != set(contract['watch_tables']):
        raise EffectError('signed snapshot table set invalid')


def reconcile(db: Path, contract: dict, before: dict, key: str, *, now: int | None = None,
              reader=None, backend: str = 'sqlite') -> dict:
    """Return a signed in-toto-shaped statement, or fail if evidence is invalid.

    This checks one explicitly expected UPDATE and *every* row/column in
    watched tables for collateral effects. Unwatched tables are out of scope.
    """
    _validate_contract(contract)
    secret = _secret(key)
    at = int(time.time()) if now is None else now
    if type(at) is not int or at < 0:
        raise EffectError('invalid verifier time')
    if not isinstance(backend, str) or backend not in ('sqlite', 'postgresql'):
        raise EffectError('unsupported observer backend')
    _verify_before(before, contract, secret, now=at, backend=backend)
    after = (reader or _snapshot)(db, contract, secret)
    checks = []
    def check(condition: bool, code: str):
        checks.append({'id': code, 'status': 'pass' if condition else 'fail'})

    target = contract['target']
    target_pk = _pk_hash(secret, target['table'], target['key'])
    changed_cells = 0
    changed_rows = 0
    for table in contract['watch_tables']:
        old = before['tables'][table]
        new = after[table]
        check(old['schema_sha256'] == new['schema_sha256'], 'schema-unchanged:' + table)
        check(old['primary_key'] == new['primary_key'], 'primary-key-unchanged:' + table)
        old_rows, new_rows = old['rows'], new['rows']
        if not isinstance(old_rows, dict):
            raise EffectError('malformed before snapshot rows')
        check(set(old_rows) == set(new_rows), 'row-set-unchanged:' + table)
        for row_hash in set(old_rows) | set(new_rows):
            before_cells = old_rows.get(row_hash, {})
            after_cells = new_rows.get(row_hash, {})
            if not isinstance(before_cells, dict):
                raise EffectError('malformed before snapshot cells')
            diff = {col for col in set(before_cells) | set(after_cells)
                    if before_cells.get(col) != after_cells.get(col)}
            if diff:
                changed_rows += 1
                changed_cells += len(diff)
                permitted = (table == target['table'] and row_hash == target_pk and
                             diff.issubset(set(target['allowed_columns'])) and
                             row_hash in old_rows and row_hash in new_rows)
                check(permitted, 'no-unapproved-effect:' + table + ':' + row_hash[:12])
    target_before = before['tables'][target['table']]['rows'].get(target_pk)
    target_after = after[target['table']]['rows'].get(target_pk)
    check(isinstance(target_before, dict) and isinstance(target_after, dict), 'target-exists')
    for col, value in target['expected'].items():
        actual_hash = target_after.get(col) if isinstance(target_after, dict) else None
        check(actual_hash == _cell_hash(secret, target['table'], target['key'], col, value),
              'expected-value:' + col)
    # A mutation elsewhere, or of another permitted field, must not count as
    # proof that the specifically expected value transitioned.
    expected_transition = any(
        isinstance(target_before, dict) and
        target_before.get(col) != _cell_hash(secret, target['table'], target['key'], col, val)
        for col, val in target['expected'].items()
    )
    check(not target['require_change'] or expected_transition, 'expected-value-transitioned')
    verified = all(c['status'] == 'pass' for c in checks)
    before_digest = digest({k: v for k, v in before.items() if k != 'hmac_sha256'})
    after_digest = digest(after)
    predicate = {'schema': 'agent-proof-pack/effect-predicate/v1',
                 'contract_sha256': digest(contract), 'backend': backend, 'before_sha256': before_digest,
                 'after_sha256': after_digest, 'status': 'verified' if verified else 'failed',
                 'changed_rows': changed_rows, 'changed_cells': changed_cells,
                 'watched_tables': contract['watch_tables'], 'checks': checks,
                 'limitations': 'Only watched SQLite tables; observation is time-bounded, not a proof of all external side effects.'}
    statement = {'_type': 'https://in-toto.io/Statement/v1',
                 'subject': [{'name': 'effect:' + contract['id'],
                              'digest': {'sha256': digest({'contract': digest(contract),
                                                         'before': before_digest, 'after': after_digest})}}],
                 'predicateType': PREDICATE_TYPE, 'predicate': predicate}
    # The in-toto statement format is portable but NOT itself a DSSE signature.
    # Locally authenticate it with a witness-only HMAC; an external trusted
    # Sigstore/GitHub workflow can issue a standard signed attestation.
    return {'statement': statement, 'witness_hmac_sha256': _mac(secret, canonical(statement))}


def verify_witness(receipt: dict, key: str) -> bool:
    try:
        secret = _secret(key)
        if not isinstance(receipt, dict) or set(receipt) != {'statement', 'witness_hmac_sha256'}:
            return False
        s = receipt['statement']
        mac = receipt['witness_hmac_sha256']
        return (isinstance(mac, str) and bool(re.fullmatch(r'[a-f0-9]{64}', mac)) and
                isinstance(s, dict) and s.get('_type') == 'https://in-toto.io/Statement/v1' and
                s.get('predicateType') == PREDICATE_TYPE and
                hmac.compare_digest(mac, _mac(secret, canonical(s))))
    except (ValueError, TypeError, KeyError):
        return False
