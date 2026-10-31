"""Regression tests use real SQLite transactions, not agent success strings."""
import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from agentproof.effect import EffectError, capture, reconcile, verify_witness

KEY = 'separate-verifier-only-reproducible-test-key-2026'
CONTRACT = {
    'schema': 'agent-proof-pack/sqlite-effect-contract/v1',
    'id': 'crm_won', 'watch_tables': ['customers', 'invoices'],
    'target': {'table': 'customers', 'key_column': 'id', 'key': 'C-42',
               'expected': {'status': 'won'}, 'allowed_columns': ['status'],
               'require_change': True}}


class EffectTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)
        self.db = Path(self.d.name) / 'app.db'
        with sqlite3.connect(self.db) as c:
            c.execute('CREATE TABLE customers (id TEXT PRIMARY KEY, status TEXT NOT NULL, owner TEXT NOT NULL)')
            c.execute('CREATE TABLE invoices (id TEXT PRIMARY KEY, amount INTEGER NOT NULL)')
            c.executemany('INSERT INTO customers VALUES (?,?,?)',
                          [('C-42', 'open', 'ada'), ('C-99', 'open', 'ben')])
            c.execute('INSERT INTO invoices VALUES (?,?)', ('I-1', 100))
        self.before = capture(self.db, CONTRACT, KEY, now=1000)

    def mutate(self, stmt, params=()):
        with sqlite3.connect(self.db) as c:
            c.execute(stmt, params)

    def proof(self, contract=CONTRACT, before=None, key=KEY, now=1001):
        return reconcile(self.db, contract, self.before if before is None else before, key, now=now)

    def is_pass(self, receipt):
        return receipt['statement']['predicate']['status'] == 'verified'

    def test_valid_update_and_authentication(self):
        self.mutate('UPDATE customers SET status=? WHERE id=?', ('won', 'C-42'))
        result = self.proof()
        self.assertTrue(self.is_pass(result))
        self.assertTrue(verify_witness(result, KEY))
        self.assertEqual(result['statement']['predicate']['changed_rows'], 1)
        self.assertEqual(result['statement']['predicate']['changed_cells'], 1)
        self.assertNotIn('C-42', json.dumps(result))
        self.assertNotIn('"won"', json.dumps(result))
        self.assertEqual(result['statement']['_type'], 'https://in-toto.io/Statement/v1')

    def test_noop_reported_success(self):
        self.assertFalse(self.is_pass(self.proof()))

    def test_wrong_value(self):
        self.mutate('UPDATE customers SET status=? WHERE id=?', ('lost', 'C-42'))
        self.assertFalse(self.is_pass(self.proof()))

    def test_wrong_row_even_if_claimed_correct(self):
        self.mutate('UPDATE customers SET status=? WHERE id=?', ('won', 'C-99'))
        self.assertFalse(self.is_pass(self.proof()))

    def test_correct_target_plus_unauthorized_customer(self):
        self.mutate('UPDATE customers SET status=? WHERE id=?', ('won', 'C-42'))
        self.mutate('UPDATE customers SET status=? WHERE id=?', ('deleted', 'C-99'))
        self.assertFalse(self.is_pass(self.proof()))

    def test_correct_target_plus_cross_table_collateral_damage(self):
        self.mutate('UPDATE customers SET status=? WHERE id=?', ('won', 'C-42'))
        self.mutate('UPDATE invoices SET amount=0 WHERE id=?', ('I-1',))
        self.assertFalse(self.is_pass(self.proof()))

    def test_correct_target_but_owner_changed(self):
        self.mutate('UPDATE customers SET status=?,owner=? WHERE id=?', ('won', 'eve', 'C-42'))
        self.assertFalse(self.is_pass(self.proof()))

    def test_row_insert_is_collateral(self):
        self.mutate('INSERT INTO customers VALUES (?,?,?)', ('C-101', 'open', 'x'))
        self.mutate('UPDATE customers SET status=? WHERE id=?', ('won', 'C-42'))
        self.assertFalse(self.is_pass(self.proof()))

    def test_row_delete_is_collateral(self):
        self.mutate('UPDATE customers SET status=? WHERE id=?', ('won', 'C-42'))
        self.mutate('DELETE FROM customers WHERE id=?', ('C-99',))
        self.assertFalse(self.is_pass(self.proof()))

    def test_schema_modification_denied(self):
        self.mutate('ALTER TABLE customers ADD COLUMN note TEXT')
        self.mutate('UPDATE customers SET status=? WHERE id=?', ('won', 'C-42'))
        self.assertFalse(self.is_pass(self.proof()))

    def test_tampered_before_snapshot_denied(self):
        forged = copy.deepcopy(self.before)
        forged['tables']['customers']['rows'].clear()
        with self.assertRaises(EffectError):
            self.proof(before=forged)

    def test_tampered_contract_denied(self):
        forged = copy.deepcopy(CONTRACT)
        forged['target']['allowed_columns'].append('owner')
        with self.assertRaises(EffectError):
            self.proof(contract=forged)

    def test_expired_snapshot_denied(self):
        with self.assertRaises(EffectError):
            self.proof(now=1601)

    def test_future_snapshot_denied(self):
        with self.assertRaises(EffectError):
            self.proof(now=999)

    def test_modified_result_fails_witness_signature(self):
        self.mutate('UPDATE customers SET status=? WHERE id=?', ('won', 'C-42'))
        result = self.proof()
        result['statement']['predicate']['status'] = 'failed'
        self.assertFalse(verify_witness(result, KEY))

    def test_modified_failure_cannot_be_forged_to_pass(self):
        result = self.proof()
        result['statement']['predicate']['status'] = 'verified'
        self.assertFalse(verify_witness(result, KEY))

    def test_wrong_key_fails(self):
        self.mutate('UPDATE customers SET status=? WHERE id=?', ('won', 'C-42'))
        self.assertFalse(verify_witness(self.proof(), KEY + '-wrong'))

    def test_allowed_column_not_in_real_schema_rejected(self):
        forged = copy.deepcopy(CONTRACT)
        forged['target']['allowed_columns'].append('nonexistent')
        with self.assertRaises(EffectError):
            capture(self.db, forged, KEY, now=1000)

    def test_sql_injection_like_identifier_rejected(self):
        forged = copy.deepcopy(CONTRACT)
        forged['watch_tables'] = ['customers; DROP TABLE invoices;--']
        with self.assertRaises(EffectError):
            capture(self.db, forged, KEY, now=1000)

    def test_unmonitored_table_is_explicit_limitation(self):
        self.mutate('UPDATE customers SET status=? WHERE id=?', ('won', 'C-42'))
        self.mutate('CREATE TABLE hidden (id TEXT PRIMARY KEY, data TEXT)')
        result = self.proof()
        self.assertTrue(self.is_pass(result))
        self.assertIn('Only watched SQLite tables', result['statement']['predicate']['limitations'])

    def test_unsupported_pk_schema_refused(self):
        self.mutate('CREATE TABLE broken (foo TEXT, bar TEXT)')
        contract = copy.deepcopy(CONTRACT)
        contract['watch_tables'].append('broken')
        with self.assertRaises(EffectError):
            capture(self.db, contract, KEY, now=1000)

    def test_readonly_does_not_mutate_db(self):
        with sqlite3.connect(self.db) as c:
            seq_before = c.execute('PRAGMA schema_version').fetchone()[0]
        self.proof()
        with sqlite3.connect(self.db) as c:
            self.assertEqual(c.execute('PRAGMA schema_version').fetchone()[0], seq_before)


if __name__ == '__main__':
    unittest.main()
