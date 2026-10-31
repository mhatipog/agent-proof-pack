"""Authenticate a saved transaction-effect receipt without database access.

Exit code 0: signature authentic AND signed status is verified.
Exit code 4: bad signature, signed failure, absent secret, or malformed evidence.
This confirms issuer-key possession and artifact integrity, not database truth.
"""
import argparse
import json
import os
import sys

from .effect import EffectError
from .tx_effect import verify_transaction_receipt


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="agent-tx-verify",
                                     description="Verify a saved HMAC-authenticated transaction witness")
    parser.add_argument("--receipt", required=True, help="path to saved witness JSON")
    parser.add_argument("--key-env", required=True, help="env var holding separately protected verifier key")
    args = parser.parse_args(argv)
    try:
        key = os.environ.get(args.key_env)
        if not key:
            raise EffectError("verifier-held secret unavailable")
        with open(args.receipt, encoding="utf8") as source:
            payload = json.load(source)
        if not verify_transaction_receipt(payload, key):
            print("INVALID", file=sys.stderr)
            return 4
        status = payload["statement"]["predicate"]["status"]
        print("VERIFIED" if status == "verified" else "AUTHENTICATED_FAILURE")
        return 0 if status == "verified" else 4
    except (EffectError, ValueError, OSError, TypeError, KeyError) as exc:
        print("INVALID: " + str(exc), file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
