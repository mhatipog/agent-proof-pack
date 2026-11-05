"""Deterministic offline security regressions for witnessed Merkle checkpoints."""
import copy
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentproof.chain_anchor import (
    ZERO, CheckpointError, checkpoint_digest, inclusion_proof, public_key_hex,
    seal_batch, verify_batch, verify_checkpoint_chain, verify_inclusion,
)


class ChainAnchorTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.pubkey = public_key_hex(self.key)
        self.receipts = [
            {"outcome": "denied", "action": "transfer", "policy": "spend-limit"},
            {"outcome": "authorized", "action": "read", "policy": "allow-read"},
            {"outcome": "indeterminate", "action": "write", "policy": "restricted"},
        ]
        self.bundle = seal_batch(self.receipts, self.key, stream_id="test-agent", epoch=1,
                                 first_sequence=1)

    def test_full_batch_and_every_inclusion_proof(self):
        self.assertTrue(verify_batch(self.bundle, self.pubkey, expected_stream_id="test-agent",
                                     expected_previous_checkpoint_hash=ZERO))
        for i, r in enumerate(self.bundle["records"]):
            self.assertTrue(verify_inclusion(r, i,
                                            inclusion_proof(self.bundle["records"], i),
                                            self.bundle["checkpoint"], self.pubkey))

    def test_tamper_receipt_detected(self):
        changed = copy.deepcopy(self.bundle)
        changed["records"][0]["receipt"]["outcome"] = "authorized"
        with self.assertRaises(CheckpointError):
            verify_batch(changed, self.pubkey)

    def test_tamper_sequence_detected(self):
        changed = copy.deepcopy(self.bundle)
        changed["records"][1]["sequence"] = 1
        with self.assertRaises(CheckpointError):
            verify_batch(changed, self.pubkey)

    def test_missing_or_reordered_record_detected(self):
        for records in (self.bundle["records"][:-1], list(reversed(self.bundle["records"]))):
            changed = copy.deepcopy(self.bundle)
            changed["records"] = records
            with self.assertRaises(CheckpointError):
                verify_batch(changed, self.pubkey)

    def test_other_signer_not_trusted(self):
        wrong_key = Ed25519PrivateKey.generate()
        with self.assertRaises(CheckpointError):
            verify_batch(self.bundle, public_key_hex(wrong_key))

    def test_tamper_signed_header_detected(self):
        changed = copy.deepcopy(self.bundle)
        changed["checkpoint"]["epoch"] = 2
        with self.assertRaises(CheckpointError):
            verify_batch(changed, self.pubkey)

    def test_inclusion_splice_and_bad_path_detected(self):
        record = self.bundle["records"][0]
        proof = inclusion_proof(self.bundle["records"], 0)
        with self.assertRaises(CheckpointError):
            verify_inclusion(record, 1, proof, self.bundle["checkpoint"], self.pubkey)
        proof[0]["hash"] = "f" * 64
        with self.assertRaises(CheckpointError):
            verify_inclusion(record, 0, proof, self.bundle["checkpoint"], self.pubkey)

    def test_predecessor_link(self):
        parent = checkpoint_digest(self.bundle["checkpoint"])
        next_batch = seal_batch([{"outcome": "authorized"}], self.key,
                                stream_id="test-agent", epoch=2, first_sequence=4,
                                previous_checkpoint_hash=parent)
        self.assertTrue(verify_batch(next_batch, self.pubkey,
                                     expected_previous_checkpoint_hash=parent))
        self.assertTrue(verify_checkpoint_chain(self.bundle["checkpoint"],
                                                next_batch["checkpoint"], self.pubkey))
        with self.assertRaises(CheckpointError):
            verify_batch(next_batch, self.pubkey,
                         expected_previous_checkpoint_hash="a" * 64)
        with self.assertRaises(CheckpointError):
            seal_batch([{"x": 1}], self.key, stream_id="test-agent", epoch=2,
                       first_sequence=4)

    def test_skipped_sequence_in_signed_batches_rejected(self):
        parent = checkpoint_digest(self.bundle["checkpoint"])
        skipped = seal_batch([{"ok": True}], self.key, stream_id="test-agent",
                             epoch=2, first_sequence=100, previous_checkpoint_hash=parent)
        with self.assertRaises(CheckpointError):
            verify_checkpoint_chain(self.bundle["checkpoint"], skipped["checkpoint"], self.pubkey)

    def test_no_invalid_floats_or_oversize_records(self):
        with self.assertRaises(CheckpointError):
            seal_batch([{"amount": float("nan")}], self.key,
                       stream_id="test-agent", epoch=1, first_sequence=1)
        with self.assertRaises(CheckpointError):
            seal_batch([{"large": "x" * 70000}], self.key,
                       stream_id="test-agent", epoch=1, first_sequence=1)

    def test_odd_width_proof_strict_duplicate(self):
        proof = inclusion_proof(self.bundle["records"], 2)
        self.assertTrue(verify_inclusion(self.bundle["records"][2], 2, proof,
                                         self.bundle["checkpoint"], self.pubkey))
        proof[0]["hash"] = "f" * 64
        with self.assertRaises(CheckpointError):
            verify_inclusion(self.bundle["records"][2], 2, proof,
                             self.bundle["checkpoint"], self.pubkey)

    def test_zero_records_and_duplicate_epoch_zero_disallowed(self):
        with self.assertRaises(CheckpointError):
            seal_batch([], self.key, stream_id="test-agent", epoch=1, first_sequence=1)
        with self.assertRaises(CheckpointError):
            seal_batch([{"ok": True}], self.key, stream_id="test-agent",
                       epoch=1, first_sequence=2)


if __name__ == "__main__":
    unittest.main()
