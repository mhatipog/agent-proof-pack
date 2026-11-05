"""Deterministic counterfactual patch witness for *trusted, synthetic* Python fixtures.

No models, network clients or third-party dependencies. This is NOT a sandbox.
"""
from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import sys
from types import CodeType, ModuleType
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


@dataclass(frozen=True)
class Fixture:
    content: str
    digest: str
    code: CodeType
    target_source: str
    target_ast_sha256: str


def _target_function(tree: ast.Module, target: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    matches = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == target]
    if len(matches) != 1 or matches[0].decorator_list:
        raise ValueError('target must be a single undecorated top-level function')
    if isinstance(matches[0], ast.AsyncFunctionDef):
        raise ValueError('async targets are unsupported')
    return matches[0]


def _fingerprint(node: ast.AST) -> str:
    # Ignore whitespace/comment-only edits; no claim of full semantic equivalence.
    return hashlib.sha256(ast.dump(node, include_attributes=False).encode('utf-8')).hexdigest()


def _load_fixture(path: Path, target: str) -> Fixture:
    data = path.read_bytes()
    content = data.decode('utf-8')
    tree = ast.parse(content, filename=str(path))
    node = _target_function(tree, target)
    target_source = ast.get_source_segment(content, node)
    if not target_source:
        raise ValueError('unable to locate target function')
    return Fixture(content, hashlib.sha256(data).hexdigest(), compile(tree, str(path), 'exec'),
                   target_source, _fingerprint(node))


def _reverted_fixture(patched: Fixture, baseline: Fixture, target: str) -> Fixture:
    """Replace ONLY the patched top-level target function with baseline's target.

    Replaying the changed target body inside otherwise patched code is a stronger
    dependency test than tracing alone, but is not a formal proof of root cause.
    """
    tree = ast.parse(patched.content)
    node = _target_function(tree, target)
    lines = patched.content.splitlines(keepends=True)
    replacement = baseline.target_source.rstrip('\n') + '\n'
    lines[node.lineno - 1:node.end_lineno] = [replacement]
    altered = ''.join(lines)
    new_tree = ast.parse(altered, filename='<counterfactual>')
    _target_function(new_tree, target)
    return Fixture(altered, hashlib.sha256(altered.encode('utf-8')).hexdigest(),
                   compile(new_tree, '<counterfactual>', 'exec'), baseline.target_source,
                   baseline.target_ast_sha256)


def _observe(fixture: Fixture, entrypoint: str, target: str, case: Case) -> Observation:
    """Fresh namespace for each probe; cannot safely execute untrusted code."""
    module = ModuleType(f'patch_witness_{fixture.digest[:12]}')
    called = False
    try:
        # Even module import may have arbitrary side effects: TRUSTED FIXTURES ONLY.
        exec(fixture.code, module.__dict__)
        entry = getattr(module, entrypoint, None)
        watched = getattr(module, target, None)
        if not callable(entry) or not callable(watched) or not hasattr(watched, '__code__'):
            return Observation(None, False, 'missing entrypoint or target function')
        code = watched.__code__
        def trace(frame: Any, event: str, arg: Any) -> None:
            nonlocal called
            if event == 'call' and frame.f_code is code:
                called = True
        previous = sys.getprofile()
        try:
            sys.setprofile(trace)
            value = entry(*case.args, **(case.kwargs or {}))
        finally:
            sys.setprofile(previous)
        if type(value) is not bool:
            return Observation(None, called, 'entrypoint did not return bool')
        return Observation(value, called, None)
    except Exception as exc:
        return Observation(None, called, type(exc).__name__)  # avoid leaking fixture secrets


def _matched(observed: Observation, expected: bool) -> bool:
    return observed.error is None and observed.target_called and observed.result is expected


def _validate(cases: list[Case], entrypoint: str, target: str, budget: int) -> None:
    if not entrypoint.isidentifier() or not target.isidentifier():
        raise ValueError('entrypoint and target must be identifiers')
    if not cases or len({c.name for c in cases}) != len(cases):
        raise ValueError('case names must be unique and nonempty')
    if not all(c.name and type(c.before) is bool and type(c.after) is bool
               and isinstance(c.args, tuple) and (c.kwargs is None or isinstance(c.kwargs, dict))
               for c in cases):
        raise ValueError('invalid case, args or boolean expectations')
    if budget <= 0:
        raise ValueError('budget must be positive')


def verify(before: Path, after: Path, entrypoint: str, target: str, cases: list[Case],
           *, max_executions: int = 100, fail_fast: bool = True) -> dict[str, Any]:
    """Budgeted, negative-first, counterfactual verification.

    Positive verdict means only the declared *trusted fixture probes* pass.
    max_executions is a deterministic local budget, not a security sandbox.
    """
    _validate(cases, entrypoint, target, max_executions)
    baseline = _load_fixture(Path(before), target)
    patched = _load_fixture(Path(after), target)
    transitions = [c for c in cases if c.before != c.after]
    controls = [c for c in cases if c.before == c.after]
    changed = baseline.target_ast_sha256 != patched.target_ast_sha256
    report: dict[str, Any] = {
        'schema': 'agent-proof-pack/patch-witness-experiment/v2',
        'status': 'inconclusive',
        'reason': '',
        'before_sha256': baseline.digest,
        'after_sha256': patched.digest,
        'target_before_ast_sha256': baseline.target_ast_sha256,
        'target_after_ast_sha256': patched.target_ast_sha256,
        'entrypoint': entrypoint,
        'target': target,
        'has_security_transition_case': bool(transitions),
        'target_changed': changed,
        'executions': 0,
        'execution_budget': max_executions,
        'cases': [],
        'counterfactual': [],
        'skipped_cases': [],
        'limitations': [
            'Trusted, synthetic fixtures only; not isolated from filesystem/network.',
            'Target reversion supports causal evidence but cannot prove root cause.',
            'Passing declared probes does not establish complete remediation.',
        ],
    }
    if baseline.digest == patched.digest:
        report['reason'] = 'identical_artifacts'
        return report
    if not transitions:
        report['reason'] = 'no_security_transition'
        return report
    if not changed:
        report['reason'] = 'target_function_not_changed'
        return report

    ordered = transitions + controls  # cheap security failures first
    count = 0
    def run(fixture: Fixture, case: Case) -> Observation:
        nonlocal count
        if count >= max_executions:
            raise RuntimeError('execution_budget_exhausted')
        count += 1
        return _observe(fixture, entrypoint, target, case)

    for i, case in enumerate(ordered):
        try:
            b = run(baseline, case)
            a = run(patched, case)
        except RuntimeError as exc:
            report['reason'] = str(exc)
            report['skipped_cases'] = [c.name for c in ordered[i:]]
            break
        if b.error or a.error:
            reason = 'execution_error'
        elif not b.target_called or not a.target_called:
            reason = 'wrong_execution_path'
        elif b.result is not case.before:
            reason = 'baseline_not_reproduced'
        elif a.result is not case.after:
            reason = 'patch_not_validated'
        else:
            reason = 'differential_case_passed'
        report['cases'].append(asdict(CaseResult(case.name, b, a, reason == 'differential_case_passed', reason)))
        if reason != 'differential_case_passed' and fail_fast:
            report['reason'] = reason
            report['skipped_cases'] = [c.name for c in ordered[i + 1:]]
            break
    report['executions'] = count
    if report['reason'] or len(report['cases']) != len(ordered):
        if not report['reason']:
            report['reason'] = 'differential_probe_failed'
        return report
    if not all(c['passed'] for c in report['cases']):
        report['reason'] = 'differential_probe_failed'
        return report

    try:
        mutant = _reverted_fixture(patched, baseline, target)
    except (SyntaxError, ValueError):
        report['reason'] = 'cannot_construct_counterfactual'
        return report
    for case in ordered:
        try:
            m = run(mutant, case)
        except RuntimeError as exc:
            report['reason'] = str(exc)
            break
        expected = case.before
        ok = _matched(m, expected)
        report['counterfactual'].append({'name': case.name, 'observation': asdict(m),
                                         'expected': expected, 'passed': ok})
        if not ok and fail_fast:
            report['reason'] = 'counterfactual_failed'
            break
    report['executions'] = count
    report['counterfactual_sha256'] = mutant.digest
    if report['reason']:
        return report
    if len(report['counterfactual']) != len(ordered) or not all(c['passed'] for c in report['counterfactual']):
        report['reason'] = 'counterfactual_failed'
    else:
        report['status'] = 'differential_and_counterfactual_probes_passed'
        report['reason'] = 'all_declared_probes_passed'
    return report


def format_result(result: dict[str, Any]) -> str:
    return json.dumps(result, sort_keys=True, indent=2, allow_nan=False)
