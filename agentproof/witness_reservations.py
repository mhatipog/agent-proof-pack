"""Independently administered durable pre-execution reservations.

The witness records a reservation BEFORE the gateway may submit a DB action.
Reservations prove that intent was acknowledged, NOT that the side effect ran,
that an agent has no bypass routes, or that the witness operator is honest.
"""
from __future__ import annotations

import hashlib
from contextlib import closing
import os
import stat
import json
import re
import sqlite3
import time
from pathlib import Path
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SCHEMA = "agent-proof-pack/witness-reservation/v1"
ZERO_HASH = "0" * 64
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX128 = re.compile(r"[0-9a-f]{128}\Z")


class WitnessDenied(Exception):
    """Generic denial; no database details or signing keys are returned."""


class AlreadyReserved(WitnessDenied):
    """An action can only obtain one pre-execution reservation."""


def _json(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise WitnessDenied("invalid witness evidence") from exc


def _id(value: str) -> str:
    try:
        if type(value) is not str or str(UUID(value)) != value:
            raise ValueError("noncanonical UUID")
    except (ValueError, AttributeError, TypeError) as exc:
        raise WitnessDenied("invalid action or principal ID") from exc
    return value


def _digest(prefix: bytes, value: bytes) -> str:
    return hashlib.sha256(prefix + value).hexdigest()


def action_hash(action_id: str) -> str:
    return _digest(b"AgentProof/action/v1\0", _id(action_id).encode("ascii"))


def principal_hash(principal_id: str) -> str:
    return _digest(b"AgentProof/principal/v1\0", _id(principal_id).encode("ascii"))


def receipt_hash(receipt: dict) -> str:
    return _digest(b"AgentProof/witness-receipt/v1\0", _json(receipt))


def witness_public_key(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def verify_reservation(receipt: object, *, public_key_hex: str,
                       action_id: str, principal_id: str, nonce: str) -> bool:
    """Verify signed *fresh* ACK using a pre-pinned independent witness key."""
    if not isinstance(receipt, dict) or set(receipt) != {"record", "signature"}:
        raise WitnessDenied("invalid reservation receipt")
    record = receipt["record"]
    if not isinstance(record, dict) or set(record) != {
            "schema", "sequence", "action_sha256", "principal_sha256",
            "nonce", "previous_receipt_sha256", "created_at_ns"}:
        raise WitnessDenied("invalid reservation fields")
    if (record["schema"] != SCHEMA or
            type(record["sequence"]) is not int or record["sequence"] < 1 or
            type(record["created_at_ns"]) is not int or record["created_at_ns"] < 1 or
            record["action_sha256"] != action_hash(action_id) or
            record["principal_sha256"] != principal_hash(principal_id) or
            record["nonce"] != nonce or
            not isinstance(nonce, str) or _HEX32.fullmatch(nonce) is None or
            not isinstance(record["previous_receipt_sha256"], str) or
            _HEX64.fullmatch(record["previous_receipt_sha256"]) is None or
            (record["sequence"] == 1 and
             record["previous_receipt_sha256"] != ZERO_HASH) or
            not isinstance(public_key_hex, str) or _HEX64.fullmatch(public_key_hex) is None or
            not isinstance(receipt["signature"], str) or
            _HEX128.fullmatch(receipt["signature"]) is None):
        raise WitnessDenied("reservation does not match trusted intent")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(
            bytes.fromhex(receipt["signature"]), _json(record))
    except (InvalidSignature, ValueError) as exc:
        raise WitnessDenied("invalid independent witness signature") from exc
    return True


def verify_witness_export(receipts: object, pinned_public_key_hex: str) -> bool:
    """Independent, public-key-only verification of a complete *supplied* prefix.

    The verifier detects modifications, internal gaps and forks in the
    supplied sequence. It cannot know whether the witness withheld a suffix
    or failed to admit an action that never reached this ledger.
    """
    if (not isinstance(receipts, list) or not receipts or
            not isinstance(pinned_public_key_hex, str) or
            _HEX64.fullmatch(pinned_public_key_hex) is None):
        raise WitnessDenied("invalid independent witness export")
    try:
        verifier = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pinned_public_key_hex))
        previous = ZERO_HASH
        for sequence, receipt in enumerate(receipts, 1):
            if not isinstance(receipt, dict) or set(receipt) != {"record", "signature"}:
                raise WitnessDenied("invalid exported receipt")
            record = receipt["record"]
            signature = receipt["signature"]
            if (not isinstance(record, dict) or set(record) != {
                    "schema", "sequence", "action_sha256", "principal_sha256",
                    "nonce", "previous_receipt_sha256", "created_at_ns"} or
                    record["schema"] != SCHEMA or
                    type(record["sequence"]) is not int or record["sequence"] != sequence or
                    type(record["created_at_ns"]) is not int or record["created_at_ns"] < 1 or
                    not isinstance(record["action_sha256"], str) or
                    _HEX64.fullmatch(record["action_sha256"]) is None or
                    not isinstance(record["principal_sha256"], str) or
                    _HEX64.fullmatch(record["principal_sha256"]) is None or
                    not isinstance(record["nonce"], str) or
                    _HEX32.fullmatch(record["nonce"]) is None or
                    record["previous_receipt_sha256"] != previous or
                    not isinstance(signature, str) or _HEX128.fullmatch(signature) is None):
                raise WitnessDenied("invalid exported receipt or chain discontinuity")
            verifier.verify(bytes.fromhex(signature), _json(record))
            previous = receipt_hash(receipt)
        return True
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise WitnessDenied("witness export failed public-key verification") from exc


class DurableWitnessLedger:
    """SQLite atomic admissions with a separately held Ed25519 signing key.

    The DB and signing key must be owned by a separate service principal,
    not the Codex runtime or the execution gateway. SQLite provides
    crash-durable admission and uniqueness, not operator-proof immutability.
    """

    def __init__(self, path: str, private_key: Ed25519PrivateKey):
        if not isinstance(private_key, Ed25519PrivateKey):
            raise WitnessDenied("witness signing key unavailable")
        if not isinstance(path, str) or not path or path == ":memory:":
            raise WitnessDenied("durable witness database path required")
        self.path = path
        self.private_key = private_key
        p = Path(path)
        if (p.is_symlink() or p.parent.is_symlink() or
                not p.parent.is_dir() or p.parent.stat().st_mode & 0o022):
            raise WitnessDenied("witness directory must not be group/world writable")
        try:
            # Force private DB permissions on creation; do not silently chmod
            # an existing unsafe database. A private, independent host identity
            # and a non-agent-writable directory are still mandatory.
            fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or
                        stat.S_IMODE(info.st_mode) & 0o077 or
                        info.st_uid != os.getuid()):
                    raise WitnessDenied("unsafe witness database ownership or permissions")
            finally:
                os.close(fd)
            with closing(self._connect()) as conn:
                conn.execute("""CREATE TABLE IF NOT EXISTS reservations (
                    sequence INTEGER PRIMARY KEY,
                    action_sha256 TEXT NOT NULL UNIQUE,
                    signed_receipt_json TEXT NOT NULL,
                    receipt_sha256 TEXT NOT NULL UNIQUE
                )""")
        except sqlite3.Error as exc:
            raise WitnessDenied("witness database unavailable") from exc

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=3, isolation_level=None)
        conn.execute("PRAGMA busy_timeout=3000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def reserve(self, action_id: str, principal_id: str, nonce: str) -> dict:
        a_hash, p_hash = action_hash(action_id), principal_hash(principal_id)
        if type(nonce) is not str or _HEX32.fullmatch(nonce) is None:
            raise WitnessDenied("invalid reservation challenge")
        try:
            with closing(self._connect()) as conn:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    if conn.execute("SELECT 1 FROM reservations WHERE action_sha256=?",
                                    (a_hash,)).fetchone():
                        raise AlreadyReserved("action already reserved")
                    last = conn.execute(
                        "SELECT sequence, receipt_sha256 FROM reservations "
                        "ORDER BY sequence DESC LIMIT 1").fetchone()
                    seq = int(last[0]) + 1 if last else 1
                    previous = last[1] if last else ZERO_HASH
                    record = {
                        "schema": SCHEMA,
                        "sequence": seq,
                        "action_sha256": a_hash,
                        "principal_sha256": p_hash,
                        "nonce": nonce,
                        "previous_receipt_sha256": previous,
                        "created_at_ns": time.time_ns(),
                    }
                    receipt = {"record": record,
                               "signature": self.private_key.sign(_json(record)).hex()}
                    conn.execute(
                        "INSERT INTO reservations(sequence,action_sha256,signed_receipt_json,"
                        "receipt_sha256) VALUES (?,?,?,?)",
                        (seq, a_hash, _json(receipt).decode("utf-8"), receipt_hash(receipt)))
                    conn.execute("COMMIT")
                    return receipt
                except BaseException:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK")
                    raise
        except AlreadyReserved:
            raise
        except sqlite3.Error as exc:
            raise WitnessDenied("witness database unavailable") from exc

    def read_all(self) -> list[dict]:
        """Auditor export, through a protected administrative channel only."""
        try:
            with closing(self._connect()) as conn:
                rows = conn.execute(
                    "SELECT sequence, signed_receipt_json, receipt_sha256 FROM "
                    "reservations ORDER BY sequence").fetchall()
        except sqlite3.Error as exc:
            raise WitnessDenied("witness database unavailable") from exc
        records = []
        previous = ZERO_HASH
        for expected_seq, (seq, raw, stored_hash) in enumerate(rows, 1):
            receipt = json.loads(raw)
            record = receipt["record"]
            if (seq != expected_seq or record["sequence"] != expected_seq or
                    record["previous_receipt_sha256"] != previous or
                    receipt_hash(receipt) != stored_hash):
                raise WitnessDenied("witness ledger discontinuity")
            # Caller-specific fresh ACK verification occurs at the gateway;
            # auditors can check chain continuity without seeing raw UUIDs.
            Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(witness_public_key(self.private_key))
            ).verify(bytes.fromhex(receipt["signature"]), _json(record))
            previous = stored_hash
            records.append(receipt)
        return records
