"""Signed, privacy-salted Merkle checkpoints for independently witnessed agent actions.

This module does not execute an agent action, authenticate an actor, or submit a chain
transaction. The witness must run independently of the agent and keep its signing key
private. Blockchain publication is a separate, verifiable deployment step.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from collections.abc import Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA = "agent-proof-pack/chain-checkpoint/v1"
RECORD_SCHEMA = "agent-proof-pack/chain-record/v1"
ZERO = "0" * 64
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_STREAM = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
MAX_RECORDS = 1024
MAX_RECORD_BYTES = 65536


class CheckpointError(ValueError):
    """Malformed, unsigned, tampered or untrusted checkpoint evidence."""


def _canonical(obj: object) -> bytes:
    try:
        result = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CheckpointError("record is not canonical JSON") from exc
    return result


def _hash(tag: bytes, blob: bytes) -> bytes:
    return hashlib.sha256(tag + blob).digest()


def _hex32(value: object) -> bool:
    return isinstance(value, str) and _HEX.fullmatch(value) is not None


def _leaf(record: Mapping) -> bytes:
    if (not isinstance(record, dict) or set(record) != {"schema", "sequence", "salt", "receipt"}
            or record["schema"] != RECORD_SCHEMA or not _hex32(record["salt"])
            or type(record["sequence"]) is not int or record["sequence"] < 1
            or not isinstance(record["receipt"], dict)):
        raise CheckpointError("invalid record")
    raw = _canonical(record)
    if len(raw) > MAX_RECORD_BYTES:
        raise CheckpointError("record exceeds size limit")
    return _hash(b"AgentProof/leaf/v1\x00", raw)


def _node(left: bytes, right: bytes) -> bytes:
    return _hash(b"AgentProof/node/v1\x00", left + right)


def _root(leaves: Sequence[bytes]) -> bytes:
    if not leaves:
        raise CheckpointError("empty batch")
    level = list(leaves)
    while len(level) > 1:
        level = [_node(level[i], level[i + 1] if i + 1 < len(level) else level[i])
                 for i in range(0, len(level), 2)]
    return level[0]


def checkpoint_digest(checkpoint: Mapping) -> str:
    """Digest a complete signed checkpoint; use this as next epoch's parent reference."""
    if not isinstance(checkpoint, dict):
        raise CheckpointError("invalid checkpoint")
    return _hash(b"AgentProof/checkpoint/v1\x00", _canonical(checkpoint)).hex()


def public_key_hex(private_key: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def seal_batch(receipts: Sequence[dict], signer: Ed25519PrivateKey, *, stream_id: str,
               epoch: int, first_sequence: int, previous_checkpoint_hash: str = ZERO) -> dict:
    """Called only in a *separately trusted witness*, never in the agent process."""
    if not isinstance(signer, Ed25519PrivateKey):
        raise CheckpointError("Ed25519 witness key required")
    if not isinstance(stream_id, str) or _STREAM.fullmatch(stream_id) is None:
        raise CheckpointError("invalid stream id")
    if type(epoch) is not int or epoch < 1 or type(first_sequence) is not int or first_sequence < 1:
        raise CheckpointError("invalid epoch or sequence")
    if (not _hex32(previous_checkpoint_hash)
            or (epoch == 1 and (previous_checkpoint_hash != ZERO or first_sequence != 1))
            or (epoch > 1 and previous_checkpoint_hash == ZERO)):
        raise CheckpointError("invalid predecessor")
    if (not isinstance(receipts, (list, tuple)) or not 1 <= len(receipts) <= MAX_RECORDS
            or any(not isinstance(r, dict) for r in receipts)):
        raise CheckpointError("invalid batch")
    records = [{"schema": RECORD_SCHEMA, "sequence": first_sequence + i,
                "salt": secrets.token_hex(32), "receipt": r}
               for i, r in enumerate(receipts)]
    root = _root([_leaf(r) for r in records]).hex()
    body = {"schema": SCHEMA, "stream_id": stream_id, "epoch": epoch,
            "first_sequence": first_sequence, "last_sequence": first_sequence + len(records) - 1,
            "record_count": len(records), "merkle_root": root,
            "previous_checkpoint_hash": previous_checkpoint_hash}
    signature = signer.sign(_canonical(body)).hex()
    return {"checkpoint": {**body, "ed25519_signature": signature}, "records": records}


def _verify_header(checkpoint: dict, trusted_public_key_hex: str) -> dict:
    fields = {"schema", "stream_id", "epoch", "first_sequence", "last_sequence", "record_count",
              "merkle_root", "previous_checkpoint_hash", "ed25519_signature"}
    if not isinstance(checkpoint, dict) or set(checkpoint) != fields:
        raise CheckpointError("invalid checkpoint fields")
    if (checkpoint["schema"] != SCHEMA or not isinstance(checkpoint["stream_id"], str)
            or _STREAM.fullmatch(checkpoint["stream_id"]) is None
            or any(type(checkpoint[k]) is not int for k in
                   ("epoch", "first_sequence", "last_sequence", "record_count"))
            or checkpoint["epoch"] < 1 or checkpoint["first_sequence"] < 1
            or not 1 <= checkpoint["record_count"] <= MAX_RECORDS
            or checkpoint["last_sequence"] != checkpoint["first_sequence"] + checkpoint["record_count"] - 1
            or not _hex32(checkpoint["merkle_root"])
            or not _hex32(checkpoint["previous_checkpoint_hash"])
            or (checkpoint["epoch"] == 1 and
                (checkpoint["first_sequence"] != 1 or checkpoint["previous_checkpoint_hash"] != ZERO))
            or (checkpoint["epoch"] > 1 and checkpoint["previous_checkpoint_hash"] == ZERO)
            or not isinstance(checkpoint["ed25519_signature"], str)
            or re.fullmatch(r"[0-9a-f]{128}", checkpoint["ed25519_signature"]) is None
            or not _hex32(trusted_public_key_hex)):
        raise CheckpointError("malformed checkpoint")
    # Public keys/signatures must not be self-authorized by the evidence they sign.
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_public_key_hex)).verify(
            bytes.fromhex(checkpoint["ed25519_signature"]),
            _canonical({k: v for k, v in checkpoint.items() if k != "ed25519_signature"}))
    except (InvalidSignature, ValueError) as exc:
        raise CheckpointError("invalid witness signature") from exc
    return checkpoint


def verify_batch(bundle: dict, trusted_public_key_hex: str, *,
                 expected_stream_id: str | None = None,
                 expected_previous_checkpoint_hash: str | None = None) -> bool:
    if not isinstance(bundle, dict) or set(bundle) != {"checkpoint", "records"}:
        raise CheckpointError("invalid bundle")
    c = _verify_header(bundle["checkpoint"], trusted_public_key_hex)
    if expected_stream_id is not None and c["stream_id"] != expected_stream_id:
        raise CheckpointError("wrong stream")
    if (expected_previous_checkpoint_hash is not None
            and c["previous_checkpoint_hash"] != expected_previous_checkpoint_hash):
        raise CheckpointError("broken checkpoint chain")
    records = bundle["records"]
    if not isinstance(records, list) or len(records) != c["record_count"]:
        raise CheckpointError("record count mismatch")
    for i, r in enumerate(records):
        if not isinstance(r, dict) or r.get("sequence") != c["first_sequence"] + i:
            raise CheckpointError("missing, duplicated, or reordered record")
    if _root([_leaf(r) for r in records]).hex() != c["merkle_root"]:
        raise CheckpointError("merkle root mismatch")
    return True


def verify_checkpoint_chain(previous: dict, following: dict, trusted_public_key_hex: str) -> bool:
    """Check signature, adjacent epochs, adjacent sequences and parent hash."""
    before = _verify_header(previous, trusted_public_key_hex)
    after = _verify_header(following, trusted_public_key_hex)
    if (after["stream_id"] != before["stream_id"]
            or after["epoch"] != before["epoch"] + 1
            or after["first_sequence"] != before["last_sequence"] + 1
            or after["previous_checkpoint_hash"] != checkpoint_digest(before)):
        raise CheckpointError("checkpoint chain discontinuity")
    return True


def inclusion_proof(records: Sequence[dict], index: int) -> list[dict]:
    if (not isinstance(records, (list, tuple)) or not 1 <= len(records) <= MAX_RECORDS
            or type(index) is not int or not 0 <= index < len(records)):
        raise CheckpointError("invalid proof index or batch")
    level = [_leaf(r) for r in records]
    proof = []
    while len(level) > 1:
        sibling = index ^ 1
        if sibling >= len(level):
            sibling = index  # duplicate last node in odd-width level
        proof.append({"side": "left" if index & 1 else "right", "hash": level[sibling].hex()})
        level = [_node(level[i], level[i + 1] if i + 1 < len(level) else level[i])
                 for i in range(0, len(level), 2)]
        index //= 2
    return proof


def verify_inclusion(record: dict, index: int, proof: Sequence[dict], checkpoint: dict,
                     trusted_public_key_hex: str) -> bool:
    c = _verify_header(checkpoint, trusted_public_key_hex)
    if type(index) is not int or not 0 <= index < c["record_count"]:
        raise CheckpointError("invalid index")
    if record.get("sequence") != c["first_sequence"] + index:
        raise CheckpointError("wrong sequence")
    node = _leaf(record)
    width, position = c["record_count"], index
    if not isinstance(proof, list):
        raise CheckpointError("invalid inclusion proof")
    step = 0
    while width > 1:
        if step >= len(proof) or not isinstance(proof[step], dict):
            raise CheckpointError("truncated inclusion proof")
        entry = proof[step]
        required_side = "left" if position & 1 else "right"
        if set(entry) != {"side", "hash"} or entry["side"] != required_side or not _hex32(entry["hash"]):
            raise CheckpointError("invalid sibling")
        sibling = bytes.fromhex(entry["hash"])
        if position == width - 1 and width & 1 and sibling != node:
            raise CheckpointError("incorrect odd-leaf duplication")
        node = _node(sibling, node) if position & 1 else _node(node, sibling)
        width = (width + 1) // 2
        position //= 2
        step += 1
    if step != len(proof) or node.hex() != c["merkle_root"]:
        raise CheckpointError("invalid inclusion path")
    return True
