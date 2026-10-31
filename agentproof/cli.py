"""CLI for local proof-pack checks; never runs an agent or changes target state."""
import argparse
import json
import os
import sys
from pathlib import Path

from .engine import PolicyError, evaluate, verify_signature
from .approval import ApprovalError, issue as issue_approval, verify_outcome
from .attest import ObservationError, observe_files
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
    issuer = sub.add_parser("issue-terraform-approval", help="sign exact plan, policy and outcome in a PROTECTED approver runtime")
    for flag in ("plan", "policy", "expectations", "environment", "approver", "key-env", "output"):
        issuer.add_argument("--" + flag, required=True)
    issuer.add_argument("--ttl-seconds", type=int, default=900)
    observer = sub.add_parser("observe-files", help="independently hash expected filesystem results")
    observer.add_argument("--root", required=True)
    observer.add_argument("--expectations", required=True)
    tf.add_argument("--approval", help="short-lived signed approval JSON for execution")
    tf.add_argument("--approval-key-env", help="approver HMAC key environment variable (trusted executor only)")
    tf.add_argument("--environment", help="exact approved target environment")
    tf.add_argument("--expectations", help="trusted expected-result JSON")
    tf.add_argument("--observe-root", help="trusted filesystem root for postflight proof")
    outcome = sub.add_parser("check-outcome", help="authenticate a stored Terraform outcome receipt")
    outcome.add_argument("--receipt", required=True)
    outcome.add_argument("--key-env", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "issue-terraform-approval":
            secret = os.environ.get(args.key_env)
            if not secret:
                raise ApprovalError("protected approver key missing")
            from .terraform_guard import saved_plan_sha256
            approval = issue_approval(
                plan_sha256=saved_plan_sha256(Path(args.plan)), policy=read_json(args.policy),
                expectations=read_json(args.expectations), environment=args.environment,
                approver=args.approver, key=secret, ttl_seconds=args.ttl_seconds)
            # Refuse overwriting an existing approval; independent reviewers
            # should sign into a protected artifact directory.
            with open(args.output, "x", encoding="utf-8") as handle:
                json.dump(approval, handle, indent=2)
                handle.write("\n")
            os.chmod(args.output, 0o600)
            print("Signed approval written to protected output path")
            return 0
        if args.command == "check-outcome":
            ok = verify_outcome(read_json(args.receipt), os.environ.get(args.key_env))
            print("VALID" if ok else "INVALID")
            return 0 if ok else 4
        if args.command == "observe-files":
            report = observe_files(Path(args.root), read_json(args.expectations))
            print(json.dumps(report, indent=2))
            return 0 if report["state"] == "verified" else 4
        if args.command == "terraform":
            policy = read_json(args.policy)
            if args.execute:
                if (not args.plan or args.approved_sha256 or
                    not all((args.approval, args.approval_key_env, args.environment,
                             args.expectations, args.observe_root))):
                    raise TerraformGateError(
                        "--execute requires binary --plan, signed --approval, --approval-key-env, "
                        "--environment, --expectations and --observe-root; raw hashes cannot authorize apply")
                secret = os.environ.get(args.approval_key_env)
                if not secret:
                    raise ApprovalError("independent approval key missing")
                report = apply_saved_plan(
                    Path(args.plan), policy, approval=read_json(args.approval),
                    approval_key=secret, environment=args.environment,
                    expectations=read_json(args.expectations),
                    observe_root=Path(args.observe_root))
                exit_code = 0 if report["state"] == "verified" else 4
            elif args.plan:
                report = review_saved_plan(Path(args.plan), policy,
                                           expected_sha256=args.approved_sha256)
                exit_code = 0 if report["verdict"] == "approve" else 4
            else:
                if args.approved_sha256:
                    raise TerraformGateError("--approved-sha256 requires binary --plan")
                report = review_plan(read_json(args.plan_json), policy)
                exit_code = 0 if report["verdict"] == "approve" else 4
            rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
            if args.output:
                Path(args.output).write_text(rendered, encoding="utf-8")
                os.chmod(args.output, 0o600)
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
    except (PolicyError, TerraformGateError, ApprovalError, ObservationError, OSError, json.JSONDecodeError) as exc:
        print(f"verification unavailable: {exc}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
