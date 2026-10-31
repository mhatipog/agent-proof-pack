"""Small standalone CLI for the independent SQLite effect witness."""
import argparse
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

from .effect import EffectError, capture, reconcile, verify_witness
from .postgres_effect import capture_postgres, reconcile_postgres


def _json(path):
    with open(path, encoding='utf8') as f:
        return json.load(f)


def _write(path, value):
    # Exclusive creation rather than overwrite protects earlier evidence.
    # Do not use a directory controlled by the executing agent.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf8') as f:
        json.dump(value, f, indent=2, ensure_ascii=False)
        f.write('\n')


def _secret(name):
    value = os.environ.get(name)
    if not value:
        raise EffectError('witness key environment variable not available')
    return value


def demo(mode='correct'):
    """Real, isolated database update; no agents, cloud accounts or secrets."""
    contract = {
        'schema': 'agent-proof-pack/sqlite-effect-contract/v1', 'id': 'crm_status',
        'watch_tables': ['customers', 'invoices'],
        'target': {'table': 'customers', 'key_column': 'id', 'key': 'C-42',
                   'expected': {'status': 'won'}, 'allowed_columns': ['status'],
                   'require_change': True}}
    synthetic_key = 'demonstration-only-key-not-a-production-credential'
    with tempfile.TemporaryDirectory() as root:
        db = Path(root) / 'crm.sqlite'
        with sqlite3.connect(db) as conn:
            conn.execute('CREATE TABLE customers (id TEXT PRIMARY KEY, status TEXT, owner TEXT)')
            conn.execute('CREATE TABLE invoices (id TEXT PRIMARY KEY, amount INTEGER)')
            conn.execute('INSERT INTO customers VALUES (?,?,?)', ('C-42', 'open', 'ada'))
            conn.execute('INSERT INTO invoices VALUES (?,?)', ('I-1', 100))
        before = capture(db, contract, synthetic_key)
        if mode != 'no-op':
            with sqlite3.connect(db) as conn:
                conn.execute('UPDATE customers SET status=? WHERE id=?', ('won', 'C-42'))
                if mode == 'collateral':
                    conn.execute('UPDATE invoices SET amount=0 WHERE id=?', ('I-1',))
        result = reconcile(db, contract, before, synthetic_key)
        if not verify_witness(result, synthetic_key):
            raise EffectError('witness authentication failed')
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(prog='agent-effect', description='Independent SQLite effect witness (no SQL execution)')
    sub = parser.add_subparsers(dest='command', required=True)
    for action in ('capture', 'reconcile'):
        p = sub.add_parser(action)
        p.add_argument('--backend', choices=['sqlite', 'postgresql'], default='sqlite')
        p.add_argument('--db', help='SQLite path (for SQLite backend only)')
        p.add_argument('--dsn-env', help='environment variable name containing PostgreSQL read-only DSN')
        p.add_argument('--schema', default='public', help='explicit PostgreSQL schema')
        p.add_argument('--contract', required=True)
        p.add_argument('--key-env', required=True)
        p.add_argument('--output', required=True)
        if action == 'reconcile':
            p.add_argument('--before', required=True)
    verify = sub.add_parser('verify-witness')
    verify.add_argument('--receipt', required=True)
    verify.add_argument('--key-env', required=True)
    trial = sub.add_parser('demo', help='real SQLite updates in temporary isolated database')
    trial.add_argument('--mode', choices=['correct', 'no-op', 'collateral'], default='correct')
    trial.add_argument('--output', help='write in-toto statement and HMAC witness bundle')
    args = parser.parse_args(argv)
    try:
        if args.command == 'verify-witness':
            good = verify_witness(_json(args.receipt), _secret(args.key_env))
            print('VALID' if good else 'INVALID')
            return 0 if good else 4
        if args.command == 'demo':
            result = demo(args.mode)
        elif args.command in ('capture', 'reconcile'):
            contract = _json(args.contract)
            key = _secret(args.key_env)
            if args.backend == 'postgresql':
                if args.db or not args.dsn_env or not os.environ.get(args.dsn_env):
                    raise EffectError('PostgreSQL mode needs --dsn-env with a protected read-only DSN; not --db')
                dsn = os.environ[args.dsn_env]
                if args.command == 'capture':
                    result = capture_postgres(dsn, contract, key, schema=args.schema)
                else:
                    result = reconcile_postgres(dsn, contract, _json(args.before), key, schema=args.schema)
            else:
                if not args.db or args.dsn_env:
                    raise EffectError('SQLite mode requires --db only')
                if args.command == 'capture':
                    result = capture(Path(args.db), contract, key)
                else:
                    result = reconcile(Path(args.db), contract, _json(args.before), key)
        if getattr(args, 'output', None):
            _write(args.output, result)
        else:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        if args.command == 'capture':
            return 0
        return 0 if result['statement']['predicate']['status'] == 'verified' else 4
    except (EffectError, OSError, ValueError, sqlite3.Error, json.JSONDecodeError) as exc:
        print('independent witness unavailable: ' + str(exc), file=sys.stderr)
        return 4


if __name__ == '__main__':
    sys.exit(main())
