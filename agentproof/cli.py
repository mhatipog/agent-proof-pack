"""CLI for local proof-pack checks; never runs an agent or changes target state."""
import argparse
import json
import os
import sys
from pathlib import Path

from .engine import PolicyError, evaluate, verify_signature
from .terraform_guard import TerraformGateError, apply_saved_plan, review_plan, review_saved_plan


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
    tf = sub.add_parser("terraform", help="review Terraform plans or gate a deliberately opted-in apply")
    inp = tf.add_mutually_exclusive_group(required=True)
    inp.add_argument("--plan", help="saved binary plan, inspected by terraform show -json")
    inp.add_argument("--plan-json", help="JSON fixture mode, NOT bound to executable plan")
    tf.add_argument("--policy", required=True)
    tf.add_argument("--approved-sha256", help="independently approved saved-plan SHA-256")
    tf.add_argument("--execute", action="store_true", help="explicitly apply the saved plan after passing all gates")
    tf.add_argument("--output", help="write JSON decision receipt")
    args = parser.parse_args(argv)
    try:
        if args.command == "terraform":
            if args.execute and (not args.plan or not args.approved_sha256):
                raise TerraformGateError("--execute requires --plan and --approved-sha256")
            policy = read_json(args.policy)
            if args.execute:
                report = apply_saved_plan(Path(args.plan), policy, approved_sha256=args.approved_sha256)
                exit_code = 0 if report["state"] == "apply_completed_unverified" else 4
            elif args.plan:
                report = review_saved_plan(Path(args.plan), policy, expected_sha256=args.approved_sha256)
                exit_code = 0 if report["verdict"] == "approve" else 4
            else:
                if args.approved_sha256:
                    raise TerraformGateError("--approved-sha256 requires binary --plan")
                report = review_plan(read_json(args.plan_json), policy)
                exit_code = 0 if report["verdict"] == "approve" else 4
            rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
            if args.output:
                Path(args.output).write_text(rendered, encoding="utf-8")
                try:
                    os.chmod(args.output, 0o600)
                except OSError:
                    pass
            else:
                print(rendered, end="")
            return exit_code
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
        if isinstance(cases, dict) and isinstance(cases.get("cases"), list):
            cases = cases["cases"]
        if not isinstance(cases, list) or not cases:
            raise PolicyError("scenario library must contain a nonempty case list")
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
    except (PolicyError, TerraformGateError, OSError, json.JSONDecodeError) as exc:
        print(f"verification unavailable: {exc}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
