"""HTTP-only, Entra-authenticated MCP gateway for one-use PostgreSQL actions.

Deploy this in a service that agents cannot edit or reach except through its
authenticated HTTPS endpoint. It offers no grant-writing or arbitrary SQL tools.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
import re
from urllib.parse import urlsplit
from uuid import UUID

from .entra import AuthorizationDenied, EntraPolicy, verify_access_token
from .generic_cli import apply_approved
from .witness_http import WitnessClient, WitnessDenied

_ACTION_ID = re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\Z")


class GatewayDenied(Exception):
    """Generic refusal: do not reveal tokens, connection strings or DB errors."""


@dataclass(frozen=True)
class GatewayConfig:
    policy: EntraPolicy
    actor_dsn: str
    resource_url: str
    witness_url: str = ""
    witness_bearer: str = ""
    witness_public_key_hex: str = ""

    def validate(self) -> None:
        self.policy.validate()
        try:
            url = urlsplit(self.resource_url)
            valid = (url.scheme == "https" and url.hostname is not None and
                     url.hostname.lower() not in ("localhost", "127.0.0.1", "::1") and
                     url.path == "/mcp" and not url.query and not url.fragment and
                     not url.username and not url.password and
                     len(self.resource_url) <= 2048)
        except (TypeError, ValueError, AttributeError):
            valid = False
        if not valid:
            raise GatewayDenied("gateway requires a public HTTPS /mcp URL")
        if not isinstance(self.actor_dsn, str) or not self.actor_dsn.strip():
            raise GatewayDenied("missing protected DB executor")
        try:
            WitnessClient(self.witness_url, self.witness_bearer,
                          self.witness_public_key_hex)
        except WitnessDenied as exc:
            raise GatewayDenied("independent reservation witness is required") from exc

    @classmethod
    def from_env(cls, environ=None) -> "GatewayConfig":
        env = os.environ if environ is None else environ
        config = cls(
            policy=EntraPolicy(
                tenant_id=env.get("AGENTPROOF_ENTRA_TENANT_ID", ""),
                audience=env.get("AGENTPROOF_ENTRA_AUDIENCE", ""),
                application_id=env.get("AGENTPROOF_ENTRA_CLIENT_ID", ""),
                principal_object_id=env.get("AGENTPROOF_ENTRA_PRINCIPAL_OID", ""),
                required_role="AgentProof.Apply",
            ),
            actor_dsn=env.get("AGENTPROOF_ACTOR_DSN", ""),
            resource_url=env.get("AGENTPROOF_MCP_RESOURCE_URL", ""),
            witness_url=env.get("AGENTPROOF_WITNESS_URL", ""),
            witness_bearer=env.get("AGENTPROOF_WITNESS_OUTBOUND_TOKEN", ""),
            witness_public_key_hex=env.get("AGENTPROOF_WITNESS_PUBLIC_KEY", ""),
        )
        config.validate()
        return config


class GuardedActionGateway:
    """Server-owned policy and restricted DB credentials, never agent-controlled.

    Dependency injection is used only for synthetic unit tests. Production uses
    the signed Entra token verifier and PostgreSQL one-use grant function.
    """

    def __init__(self, config: GatewayConfig, *, verifier=verify_access_token,
                 executor=apply_approved, witness=None):
        config.validate()
        self.config = config
        self._verifier = verifier
        self._executor = executor
        self._witness = witness if witness is not None else WitnessClient(
            config.witness_url, config.witness_bearer, config.witness_public_key_hex)

    def verify_caller(self, token: str) -> dict:
        try:
            identity = self._verifier(token, self.config.policy)
            expected = {
                "tenant_id": self.config.policy.tenant_id.lower(),
                "application_id": self.config.policy.application_id.lower(),
                "principal_object_id": self.config.policy.principal_object_id.lower(),
                "authorized_role": self.config.policy.required_role,
            }
            if not isinstance(identity, dict) or any(identity.get(k) != v for k, v in expected.items()):
                raise AuthorizationDenied("access denied")
            return identity
        except Exception as exc:
            raise GatewayDenied("action denied or unavailable") from exc

    def apply(self, token: str, action_id: str) -> dict:
        if not isinstance(action_id, str) or not _ACTION_ID.fullmatch(action_id):
            raise GatewayDenied("action denied or unavailable")
        try:
            if str(UUID(action_id)) != action_id:
                raise ValueError("non-canonical action id")
        except ValueError as exc:
            raise GatewayDenied("action denied or unavailable") from exc

        identity = self.verify_caller(token)
        # Durable, independently signed ACK is MANDATORY before DB execution.
        # A second admission of this UUID is refused even if the prior call
        # timed out. The operator must reconcile before issuing a new grant.
        try:
            reservation_sha256 = self._witness.reserve(
                action_id, identity["principal_object_id"])
        except WitnessDenied as exc:
            raise GatewayDenied("action denied or unavailable") from exc
        try:
            result = self._executor(self.config.actor_dsn, action_id)
            if (not isinstance(result, dict) or result.get("action_id") != action_id
                    or result.get("state") != "submitted_unverified"):
                raise GatewayDenied("action denied or unavailable")
        except Exception as exc:
            # A timeout may follow a committed DB transaction. Never report rollback.
            raise GatewayDenied("action denied or unavailable") from exc
        return {"action_id": action_id, "state": "submitted_unverified",
                "independent_effect_verified": False,
                "witness_reservation_sha256": reservation_sha256}


def build_mcp_server(config: GatewayConfig, *, gateway: GuardedActionGateway | None = None):
    """An OAuth resource server, not a stdio tool or an authentication provider."""
    from pydantic import AnyHttpUrl
    from mcp.server import MCPServer
    from mcp.server.auth.middleware.auth_context import get_access_token
    from mcp.server.auth.provider import AccessToken, TokenVerifier
    from mcp.server.auth.settings import AuthSettings

    config.validate()
    guard = gateway if gateway is not None else GuardedActionGateway(config)

    class EntraTokenVerifier(TokenVerifier):
        async def verify_token(self, token: str) -> AccessToken | None:
            try:
                identity = guard.verify_caller(token)
            except GatewayDenied:
                return None
            return AccessToken(token=token, client_id=identity["application_id"],
                               subject=identity["principal_object_id"],
                               scopes=["agentproof:apply"], resource=config.policy.audience)

    server = MCPServer(
        "Agent Proof Guarded Actions",
        token_verifier=EntraTokenVerifier(),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl("https://login.microsoftonline.com/"
                                  + config.policy.tenant_id + "/v2.0"),
            resource_server_url=AnyHttpUrl(config.resource_url),
            required_scopes=["agentproof:apply"],
            # Entra aud is api://resource, checked strictly by verify_access_token,
            # rather than the HTTPS MCP URL.
            validate_token_resource=False,
        ),
    )

    @server.tool()
    def apply_preapproved_postgres_change(action_id: str) -> dict:
        """Consume a trusted operator's one-use DB grant; returns unverified submission."""
        identity = get_access_token()
        # Direct in-memory and stdio invocation skips HTTP auth; refuse it.
        if identity is None or not isinstance(identity.token, str):
            raise GatewayDenied("action denied or unavailable")
        # Reverify independently: an SDK-side approval or injected token context
        # must not become the only enforcement boundary.
        return guard.apply(identity.token, action_id)

    return server


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="agent-proof-mcp-gateway")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    if args.host not in ("127.0.0.1", "::1", "localhost") or not (1 <= args.port <= 65535):
        parser.error("gateway must bind loopback behind an independent HTTPS proxy")
    try:
        config = GatewayConfig.from_env()
        server = build_mcp_server(config)
    except (GatewayDenied, AuthorizationDenied) as exc:
        parser.error(str(exc))
    # No .run('stdio') entry point. A shell/stdio MCP server has no OAuth boundary.
    server.run(transport="streamable-http", host=args.host, port=args.port,
               stateless_http=True, json_response=True, max_request_body_size=65536)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
