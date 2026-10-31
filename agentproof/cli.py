"""CLI for local proof-pack checks; never runs an agent or changes target state."""
import argparse
import json
import os
import sys
from pathlib import Path

from .engine import PolicyError, evaluate, verify_signature


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv=None):
    parser = argparse.ArgumentParser(prog="agent-proof", description="Deterministic agent action verification")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("verify", help="evaluate policy against independent evidence JSON")
    check.add_argument("--policy", required=True)
    check.add_argument("--evidence", required=True)
    check.add_argument("--output", help="receipt JSON file (default: stdout)")
    check.add_argument("--signing-key-env", help="name of an environment variable containing a verifier-only HMAC key")
    suite = sub.add_parser("suite", help="run public fixture cases with expected verdicts")
    suite.add_argument("--cases", default="examples/cases.json")
    verify = sub.add_parser("check-signature", help="verify HMAC receipt")
    verify.add_argument("--receipt", required=True)
    verify.add_argument("--signing-key-env", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            key = None
            if args.signing_key_env:
                key = os.environ.get(args.signing_key_env)
                if not key:
                    raise PolicyError("signing key environment variable not set")
            receipt = evaluate(read_json(args.policy), read_json(args.evidence), signing_key=key)
            rendered = json.dumps(receipt, indent=2, ensure_ascii=False) + "\n"
            if args.output:
                Path(args.output).write_text(rendered, encoding="utf-8")
            else:
                print(rendered, end="")
            return {"approve": 0, "escalate": 3, "block": 4}[receipt["verdict"]]
        if args.command == "check-signature":
            key = os.environ.get(args.signing_key_env)
            passed = bool(key and verify_signature(read_json(args.receipt), key))
            print("VALID" if passed else "INVALID")
            return 0 if passed else 4
        cases = read_json(args.cases)
        failed = []
        for case in cases:
            try:
                receipt = evaluate(case["policy"], case["evidence"], evaluated_at="2026-01-01T00:00:00Z")
                actual = receipt["verdict"]
            except (PolicyError, KeyError, TypeError) as exc:
                actual = "error: " + str(exc)
            ok = actual == case["expected"]
            print(f"{'PASS' if ok else 'FAIL'} {case['id']}: {actual} (wanted {case['expected']})")
            if not ok:
                failed.append(case["id"])
        print(f"{len(cases) - len(failed)}/{len(cases)} cases matched expected verdicts")
        return 4 if failed else 0
    except (PolicyError, OSError, json.JSONDecodeError) as exc:
        print(f"verification unavailable: {exc}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
