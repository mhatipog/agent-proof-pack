"""Public-key-only offline verification of a witness export.

A valid prefix is not proof of log completeness. Pass an independently
obtained expected head digest to detect truncated history relative to it.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

from .witness_reservations import (
    WitnessDenied, receipt_hash, verify_witness_export,
)

_HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_EXPORT_BYTES = 8 * 1024 * 1024


def verify_file(path: str, public_key_hex: str,
                expected_head: str | None = None) -> dict:
    if expected_head is not None and (
            type(expected_head) is not str or _HEX.fullmatch(expected_head) is None):
        raise WitnessDenied("invalid expected head")
    try:
        candidate = Path(path)
        if not candidate.is_file() or candidate.stat().st_size > MAX_EXPORT_BYTES:
            raise WitnessDenied("bounded witness export file required")
        data = candidate.read_bytes()
        if len(data) > MAX_EXPORT_BYTES:
            raise WitnessDenied("witness export too large")
        receipts = json.loads(data)
        verify_witness_export(receipts, public_key_hex)
        head = receipt_hash(receipts[-1])
        if expected_head is not None and head != expected_head:
            raise WitnessDenied("witness export does not match independently pinned head")
        return {"status": "VERIFIED_PREFIX", "records": len(receipts), "head_sha256": head,
                "expected_head_checked": expected_head is not None}
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        raise WitnessDenied("independent witness verification unavailable") from exc


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="agent-proof-witness-verify")
    p.add_argument("--file", required=True, help="witness exported JSON array")
    p.add_argument("--public-key-hex", required=True, help="out-of-band trusted Ed25519 public key")
    p.add_argument("--expected-head", help="out-of-band trusted last receipt digest")
    args = p.parse_args(argv)
    try:
        print(json.dumps(verify_file(args.file, args.public_key_hex, args.expected_head),
                         sort_keys=True))
        return 0
    except WitnessDenied:
        print("witness verification failed", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
