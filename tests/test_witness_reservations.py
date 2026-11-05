"""Security regressions for the independent, durable pre-execution witness."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import uuid4

from agentproof.witness_http import WitnessClient, make_handler
from agentproof.witness_reservations import (
    AlreadyReserved, DurableWitnessLedger, WitnessDenied, receipt_hash,
    verify_reservation, witness_public_key,
)
from test_mcp_gateway import APP, ACTION, PRINCIPAL, config, GatewayDenied, GuardedActionGateway

NONCE = "a" * 32


class WitnessLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "durable.sqlite3")
        self.key = Ed25519PrivateKey.generate()
        self.pub = witness_public_key(self.key)
        self.ledger = DurableWitnessLedger(self.db, self.key)

    def test_persisted_reservation_survives_restart_and_rejects_replay(self):
        first = self.ledger.reserve(ACTION, PRINCIPAL, NONCE)
        self.assertTrue(verify_reservation(first, public_key_hex=self.pub,
                                           action_id=ACTION, principal_id=PRINCIPAL, nonce=NONCE))
        new = DurableWitnessLedger(self.db, self.key)
        with self.assertRaises(AlreadyReserved):
            new.reserve(ACTION, PRINCIPAL, "b" * 32)
        second_id = str(uuid4())
        second = new.reserve(second_id, PRINCIPAL, "c" * 32)
        self.assertEqual(second["record"]["sequence"], 2)
        self.assertEqual(second["record"]["previous_receipt_sha256"], receipt_hash(first))
        self.assertEqual([r["record"]["sequence"] for r in new.read_all()], [1, 2])
        self.assertNotIn(ACTION, Path(self.db).read_bytes().decode("utf-8", errors="replace"))

    def test_signature_forgery_altered_fields_wrong_challenge_rejected(self):
        receipt = self.ledger.reserve(ACTION, PRINCIPAL, NONCE)
        for args in ({"action_id": str(uuid4())},
                     {"principal_id": str(uuid4())},
                     {"nonce": "b" * 32},
                     {"public_key_hex": witness_public_key(Ed25519PrivateKey.generate())}):
            values = {"public_key_hex": self.pub, "action_id": ACTION,
                      "principal_id": PRINCIPAL, "nonce": NONCE, **args}
            with self.assertRaises(WitnessDenied):
                verify_reservation(receipt, **values)
        altered = deepcopy(receipt)
        altered["record"]["sequence"] = 9
        with self.assertRaises(WitnessDenied):
            verify_reservation(altered, public_key_hex=self.pub,
                               action_id=ACTION, principal_id=PRINCIPAL, nonce=NONCE)
        with self.assertRaises(WitnessDenied):
            verify_reservation({"fake": "receipt"}, public_key_hex=self.pub,
                               action_id=ACTION, principal_id=PRINCIPAL, nonce=NONCE)

    def test_concurrent_same_action_reserves_once(self):
        def attempt(_):
            try:
                return self.ledger.reserve(ACTION, PRINCIPAL, str(uuid4()).replace("-", "")[:32])
            except AlreadyReserved:
                return None
        with ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(pool.map(attempt, range(14)))
        self.assertEqual(sum(v is not None for v in responses), 1)
        self.assertEqual(len(self.ledger.read_all()), 1)

    def test_db_mutation_breaks_auditable_chain(self):
        self.ledger.reserve(ACTION, PRINCIPAL, NONCE)
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE reservations SET receipt_sha256 = ?", ("b" * 64,))
        with self.assertRaises(WitnessDenied):
            self.ledger.read_all()

    def test_http_auth_size_validation_and_duplicate(self):
        token = "g" * 48
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.ledger, token))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_address[1]}/v1/reservations"
        body = json.dumps({"action_id": ACTION, "principal_id": PRINCIPAL, "nonce": NONCE}).encode()

        def request(payload, secret=token):
            req = Request(base, data=payload, method="POST",
                          headers={"Authorization": "Bearer " + secret,
                                   "Content-Type": "application/json"})
            try:
                with urlopen(req, timeout=3) as response:
                    return response.status, json.loads(response.read())
            except HTTPError as exc:
                return exc.code, json.loads(exc.read())

        status, _ = request(body, "wrong-token")
        self.assertEqual(status, 401)
        status, _ = request(b"x" * 700)
        self.assertEqual(status, 400)
        status, output = request(body)
        self.assertEqual(status, 201)
        self.assertTrue(verify_reservation(output["receipt"], public_key_hex=self.pub,
                                           action_id=ACTION, principal_id=PRINCIPAL, nonce=NONCE))
        status, _ = request(body)
        self.assertEqual(status, 409)
        self.assertEqual(len(self.ledger.read_all()), 1)

    def test_https_client_rejects_replayed_or_changed_signed_response(self):
        def good_sender(request):
            return {"receipt": self.ledger.reserve(request["action_id"],
                                                   request["principal_id"], request["nonce"])}
        client = WitnessClient("https://independent-witness.example.invalid/v1/reservations",
                               "a" * 48, self.pub, sender=good_sender)
        evidence_hash = client.reserve(ACTION, PRINCIPAL)
        self.assertEqual(evidence_hash, receipt_hash(self.ledger.read_all()[0]))
        # A second request for the same action obtains a new random challenge,
        # so a replayed old signed response cannot count as a fresh ACK.
        previous = self.ledger.read_all()[0]
        replay = WitnessClient("https://independent-witness.example.invalid/v1/reservations",
                               "a" * 48, self.pub,
                               sender=lambda req: {"receipt": previous})
        with self.assertRaises(WitnessDenied):
            replay.reserve(ACTION, PRINCIPAL)

    def test_witness_duplicate_prevents_retry_after_ambiguous_execution(self):
        class Adapter:
            def reserve(_, action_id, principal_id):
                return receipt_hash(self.ledger.reserve(action_id, principal_id,
                                                        str(uuid4()).replace("-", "")[:32]))
        calls = []
        def uncertain(dsn, action_id):
            calls.append(action_id)
            raise OSError("write may have committed")
        expected = {"tenant_id": config().policy.tenant_id,
                    "application_id": APP, "principal_object_id": PRINCIPAL,
                    "authorized_role": "AgentProof.Apply"}
        gate = GuardedActionGateway(config(),
                                    verifier=lambda t, p: expected,
                                    executor=uncertain, witness=Adapter())
        for _ in range(2):
            with self.assertRaises(GatewayDenied):
                gate.apply("synthetic", ACTION)
        self.assertEqual(calls, [ACTION])
        self.assertEqual(len(self.ledger.read_all()), 1)


if __name__ == "__main__":
    unittest.main()
