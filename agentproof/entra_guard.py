"""Entra-guarded entry point for the PostgreSQL transaction gate.

This is the *only* entry point to expose to an Entra-authenticated agent.
Run it in a protected executor; the agent cannot edit its policy variables,
PostgreSQL connection secret or operator-issued action grant.
"""
from __future__ import annotations
import argparse
import json
import os
import sys
from .entra import EntraPolicy, AuthorizationDenied, verify_access_token
from .generic_cli import apply_approved, EffectError


def authorized_apply(action_id: str, *, environ=None, verifier=verify_access_token) -> dict:
    env = os.environ if environ is None else environ
    policy = EntraPolicy(
        tenant_id=env.get("AGENTPROOF_ENTRA_TENANT_ID", ""),
        audience=env.get("AGENTPROOF_ENTRA_AUDIENCE", ""),
        application_id=env.get("AGENTPROOF_ENTRA_CLIENT_ID", ""),
        principal_object_id=env.get("AGENTPROOF_ENTRA_PRINCIPAL_OID", ""),
        required_role=env.get("AGENTPROOF_ENTRA_REQUIRED_ROLE", "AgentProof.Apply"),
    )
    identity = verifier(env.get("AGENTPROOF_ENTRA_ACCESS_TOKEN", ""), policy)
    # Authentication is only the outer boundary. The database still requires a
    # pre-existing, one-use, role-bound approval and forbids direct table writes.
    outcome = apply_approved(env.get("AGENTPROOF_ACTOR_DSN", ""), action_id)
    return {"action_id": outcome["action_id"], "state": outcome["state"],
            "auth": "entra-app-role", "principal": identity["principal_object_id"],
            "database_effect_verified": False}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="agent-guarded-entra")
    parser.add_argument("--action-id", required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(authorized_apply(args.action_id), sort_keys=True))
        return 0
    except (AuthorizationDenied, EffectError, ValueError, OSError):
        # Authentication and database errors intentionally have one public shape.
        print("guarded action denied or unavailable", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
