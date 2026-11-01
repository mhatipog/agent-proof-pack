"""Verify Microsoft Entra *API access tokens* before a protected database action.

This is a resource-server authorization component. It must never accept a token
issued for Microsoft Graph, Fabric, Azure Management, or another API as a grant
to this service. The expected tenant, resource audience, principal and role
come from operator-controlled configuration, never from the agent's request.

Optional dependency: pip install 'agent-proof-pack[entra]'.
"""
from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


class AuthorizationDenied(Exception):
    """No token diagnostics or token contents are exposed to callers."""


def _guid(value: str) -> str:
    try:
        parsed = UUID(value)
        if parsed.version is None or str(parsed) != value.lower():
            raise ValueError()
        return str(parsed)
    except (AttributeError, TypeError, ValueError) as exc:
        raise AuthorizationDenied("invalid protected identity policy") from exc


@dataclass(frozen=True)
class EntraPolicy:
    tenant_id: str
    audience: str
    application_id: str
    principal_object_id: str
    required_role: str

    def validate(self) -> None:
        _guid(self.tenant_id)
        _guid(self.application_id)
        _guid(self.principal_object_id)
        if (not isinstance(self.audience, str) or not self.audience
                or not (self.audience.startswith("api://")
                        or self.audience == self.application_id)):
            # A first-party Microsoft API token must not authorize this guard.
            raise AuthorizationDenied("expected audience must be the guard's own API")
        if (not isinstance(self.required_role, str)
                or not self.required_role.startswith("AgentProof.")
                or len(self.required_role) > 100
                or any(c.isspace() for c in self.required_role)):
            raise AuthorizationDenied("invalid protected role policy")


def verify_access_token(token: str, policy: EntraPolicy, *, jwk_client=None) -> dict:
    """Validate a signed Entra app-only token and the exact assigned API role.

    Only server-owned policy is safe to use here. The caller must independently
    enforce one-use action approval; authentication alone never approves SQL.
    Pass a fixed jwk_client only in tests; the production URL is constructed
    solely from the configured tenant (no JWT-controlled URLs).
    """
    policy.validate()
    if not isinstance(token, str) or not (100 <= len(token) <= 20000):
        raise AuthorizationDenied("access denied")
    try:
        import jwt
        from jwt import PyJWKClient
        header = jwt.get_unverified_header(token)
        # Untrusted version only selects one of two fixed, tenant-scoped keysets.
        preliminary = jwt.decode(token, options={"verify_signature": False,
            "verify_exp": False, "verify_aud": False, "verify_iss": False})
        version = preliminary.get("ver")
        if header.get("alg") != "RS256" or version not in ("1.0", "2.0"):
            raise AuthorizationDenied("access denied")
        tenant = _guid(policy.tenant_id)
        base = "https://login.microsoftonline.com/" + tenant
        if version == "1.0":
            uri = base + "/discovery/keys"
            issuer = "https://sts.windows.net/" + tenant + "/"
        else:
            uri = base + "/discovery/v2.0/keys"
            issuer = base + "/v2.0"
        client = jwk_client if jwk_client is not None else PyJWKClient(uri, timeout=8)
        signing_key = client.get_signing_key_from_jwt(token)
        claims = jwt.decode(token, signing_key.key, algorithms=["RS256"],
                            audience=policy.audience, issuer=issuer,
                            leeway=30, options={"require": ["exp", "iat", "nbf", "iss", "aud"]})
        if (claims.get("ver") != version
                or not isinstance(claims.get("aud"), str)
                or claims["aud"] != policy.audience
                or _guid(claims.get("tid")) != tenant
                or claims.get("scp") not in (None, "", "/")
                or claims.get("idtyp") not in (None, "app")):
            raise AuthorizationDenied("access denied")
        app = claims.get("appid") if version == "1.0" else claims.get("azp")
        if (_guid(app) != _guid(policy.application_id)
                or _guid(claims.get("oid")) != _guid(policy.principal_object_id)):
            raise AuthorizationDenied("access denied")
        roles = claims.get("roles")
        if (not isinstance(roles, list)
                or not all(isinstance(r, str) for r in roles)
                or policy.required_role not in roles):
            raise AuthorizationDenied("access denied")
        return {"tenant_id": tenant, "application_id": _guid(app),
                "principal_object_id": _guid(claims["oid"]),
                "authorized_role": policy.required_role, "token_version": version}
    except AuthorizationDenied:
        raise
    except Exception as exc:
        # Do not expose JWT, OIDC/JWKS response payloads or sensitive claims.
        raise AuthorizationDenied("access denied") from exc
