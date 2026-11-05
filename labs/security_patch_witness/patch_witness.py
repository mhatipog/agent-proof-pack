"""A narrow, dependency-free differential witness for *trusted* Python fixtures.

Experimental research tool. Not a sandbox or proof of general exploitability.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import sys
from types import ModuleType
from typing import Any


@dataclass(frozen=True)
class Case:
    name: str
    args: tuple[Any, ...]
    before: bool
    after: bool
    kwargs: dict[str, Any] | None = None


@dataclass(frozen=True)
class Observation:
    result: bool | None
    target_called: bool
    error: str | None


@dataclass(frozen=True)
class CaseResult:
    name: str
    before: Observation
    after: Observation
    passed: bool
    reason: str


def _load_trusted_fixture(path: Path) -> tuple[ModuleType, str]:
    """Executing a Python fixture is unsafe for untrusted sources. Use a sandbox."""
    data = path.read_bytes()
    source_hash = hashlib.sha256(data).hexdigest()
    module = ModuleType(f"patch_witness_{source_hash[:12]}")
    module.__file__ = str(path)
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module, source_hash


def _observe(module: ModuleType, entrypoint: str, target: str, case: Case) -> Observation:
    entry = getattr(module, entrypoint, None)
    watched = getattr(module, target, None)
    if not callable(entry) or not callable(watched) or not hasattr(watched, "__code__"):
        return Observation(None, False, "missing entrypoint or target function")

    called = False
    code = watched.__code__

    def profile(frame: Any, event: str, arg: Any) -> None:
        nonlocal called
        if event == "call" and frame.f_code is code:
            called = True

    previous = sys.getprofile()
    try:
        sys.setprofile(profile)
        result = entry(*case.args, **(case.kwargs or {}))
        if type(result) is not bool:
            return Observation(None, called, "entrypoint did not return bool")
        return Observation(result, called, None)
    except Exception as exc:
        return Observation(None, called, f"{type(exc).__name__}: {exc}")
    finally:
        sys.setprofile(previous)


def verify(before: Path, after: Path, entrypoint: str, target: str, cases: list[Case]) -> dict[str, Any]:
    """Fail closed unless both versions exercise the target and satisfy all cases.

    Only applies to locally trusted synthetic fixtures. Import-time code executes.
    The path trace proves a Python function was called, not that it caused the result.
    """
    if not cases or len({c.name for c in cases}) != len(cases):
        raise ValueError("provide unique, nonempty case names")
    if not all(c.name and type(c.before) is bool and type(c.after) is bool for c in cases):
        raise ValueError("each case requires a name and boolean expectations")
    before_module, before_sha = _load_trusted_fixture(before)
    after_module, after_sha = _load_trusted_fixture(after)
    results: list[CaseResult] = []
    for case in cases:
        b = _observe(before_module, entrypoint, target, case)
        a = _observe(after_module, entrypoint, target, case)
        if b.error or a.error:
            reason = "execution_error"
        elif not b.target_called or not a.target_called:
            reason = "wrong_execution_path"
        elif b.result != case.before:
            reason = "baseline_not_reproduced"
        elif a.result != case.after:
            reason = "patch_not_validated"
        else:
            reason = "differential_case_passed"
        results.append(CaseResult(case.name, b, a, reason == "differential_case_passed", reason))
    has_transition = any(c.before != c.after for c in cases)
    overall = before_sha != after_sha and has_transition and all(r.passed for r in results)
    return {
        "schema": "agent-proof-pack/patch-witness-experiment/v1",
        "status": "differential_probes_passed" if overall else "inconclusive",
        "before_sha256": before_sha,
        "after_sha256": after_sha,
        "entrypoint": entrypoint,
        "target": target,
        "has_security_transition_case": has_transition,
        "cases": [asdict(r) for r in results],
        "limitations": [
            "Only trusted fixture code; no execution sandbox.",
            "Tracing establishes function invocation, not causal root cause.",
            "Passing tests does not establish complete remediation or exploitability.",
        ],
    }


def format_result(result: dict[str, Any]) -> str:
    return json.dumps(result, sort_keys=True, indent=2)
