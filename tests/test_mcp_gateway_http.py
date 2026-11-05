"""Black-box HTTP admission checks for the optional MCP v2 transport.

No real database, Entra app or bearer credential is used. This verifies that
HTTP authorization refuses unauthenticated and invalid-token requests before
they reach a tool. Core authorization tests live in test_mcp_gateway.py.
"""
import unittest

try:
    import httpx
    import mcp
    from agentproof.mcp_gateway import build_mcp_server
    _HAS_SDK = True
except ImportError:
    _HAS_SDK = False

from agentproof.entra import AuthorizationDenied
from agentproof.mcp_gateway import GatewayConfig, GuardedActionGateway
from test_mcp_gateway import POLICY, config, SyntheticWitness


@unittest.skipUnless(_HAS_SDK, "optional mcp/httpx gateway dependencies not installed")
class TransportAdmissionTests(unittest.IsolatedAsyncioTestCase):
    async def test_no_token_and_invalid_token_are_http_401(self):
        operations = []
        def verify(token, policy):
            raise AuthorizationDenied("invalid JWT")
        def apply(dsn, action_id):
            operations.append(action_id)
            raise AssertionError("transport admitted unauthenticated tool")
        config = config(actor_dsn="postgresql://synthetic-only")
        gateway = GuardedActionGateway(config, verifier=verify, executor=apply,
                                       witness=SyntheticWitness())
        server = build_mcp_server(config, gateway=gateway)
        app = server.streamable_http_app(host="127.0.0.1",
                                         stateless_http=True, json_response=True)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport,
                                     base_url="http://127.0.0.1:8000") as client:
            payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
            headers = {"accept": "application/json, text/event-stream"}
            for token in (None, "forged"):
                case_headers = dict(headers)
                if token is not None:
                    case_headers["authorization"] = "Bearer " + token
                response = await client.post("/mcp", json=payload, headers=case_headers)
                self.assertEqual(response.status_code, 401, response.text[:500])
                self.assertIn("WWW-Authenticate", response.headers)
        self.assertEqual(operations, [])


    async def test_authenticated_remote_tool_uses_only_protected_executor(self):
        from test_mcp_gateway import TENANT, APP, PRINCIPAL, ACTION
        actions = []

        def verify(token, policy):
            if token != "synthetic-valid":
                raise AuthorizationDenied("no")
            return {"tenant_id": TENANT, "application_id": APP,
                    "principal_object_id": PRINCIPAL,
                    "authorized_role": "AgentProof.Apply"}

        def execute(dsn, action):
            actions.append((dsn, action))
            return {"action_id": action, "state": "submitted_unverified"}

        config = config(actor_dsn="postgresql://mock-execute-only")
        server = build_mcp_server(config, gateway=GuardedActionGateway(
            config, verifier=verify, executor=execute,
            witness=SyntheticWitness()))
        app = server.streamable_http_app(host="127.0.0.1",
                                         stateless_http=True, json_response=True)
        req = {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {
                "name": "apply_preapproved_postgres_change",
                "arguments": {"action_id": ACTION},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "synthetic-ci", "version": "1.0"
                    },
                },
            },
        }
        headers = {"authorization": "Bearer synthetic-valid",
                   "accept": "application/json, text/event-stream",
                   "MCP-Protocol-Version": "2026-07-28",
                   "Mcp-Method": "tools/call",
                   "Mcp-Name": "apply_preapproved_postgres_change"}
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://127.0.0.1:8000"
            ) as client:
                response = await client.post("/mcp", json=req, headers=headers)
        self.assertEqual(response.status_code, 200, response.text[:600])
        self.assertIn("submitted_unverified", response.text)
        self.assertEqual(actions, [("postgresql://mock-execute-only", ACTION)])


    async def test_real_rsa_jwt_is_checked_on_http_before_executor(self):
        import time
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        from agentproof.entra import verify_access_token
        from test_mcp_gateway import TENANT, APP, PRINCIPAL, ACTION

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        class TestJwkClient:
            def get_signing_key_from_jwt(self, token):
                return type("Key", (), {"key": key.public_key()})()

        def verify(token, policy):
            return verify_access_token(token, policy, jwk_client=TestJwkClient())

        now = int(time.time())
        claims = {
            "ver": "2.0", "iss": "https://login.microsoftonline.com/" + TENANT + "/v2.0",
            "aud": POLICY.audience, "tid": TENANT, "azp": APP, "oid": PRINCIPAL,
            "roles": ["AgentProof.Apply"], "idtyp": "app",
            "iat": now, "nbf": now - 1, "exp": now + 180,
        }

        def sign(changes=None, *, private_key=key):
            return jwt.encode({**claims, **(changes or {})}, private_key,
                              algorithm="RS256", headers={"kid": "synthetic"})

        executions = []
        def execute(dsn, action):
            executions.append(action)
            return {"action_id": action, "state": "submitted_unverified"}

        config = config(actor_dsn="postgresql://synthetic-only")
        server = build_mcp_server(config, gateway=GuardedActionGateway(
            config, verifier=verify, executor=execute,
            witness=SyntheticWitness()))
        app = server.streamable_http_app(host="127.0.0.1",
                                         stateless_http=True, json_response=True)
        req = {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "apply_preapproved_postgres_change",
                "arguments": {"action_id": ACTION},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "rsa-ci-client", "version": "1.0"
                    },
                },
            },
        }
        headers = {"accept": "application/json, text/event-stream",
                   "MCP-Protocol-Version": "2026-07-28",
                   "Mcp-Method": "tools/call",
                   "Mcp-Name": "apply_preapproved_postgres_change"}
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://127.0.0.1:8000"
            ) as client:
                for bad_token in (
                    sign({"aud": "https://graph.microsoft.com"}),
                    sign({"roles": ["AgentProof.Read"]}),
                    sign({"oid": TENANT}),
                    sign(private_key=wrong_key),
                ):
                    response = await client.post(
                        "/mcp", json=req,
                        headers={**headers, "authorization": "Bearer " + bad_token})
                    self.assertEqual(response.status_code, 401, response.text[:400])
                self.assertEqual(executions, [])
                response = await client.post(
                    "/mcp", json=req,
                    headers={**headers, "authorization": "Bearer " + sign()})
        self.assertEqual(response.status_code, 200, response.text[:600])
        self.assertIn("submitted_unverified", response.text)
        self.assertEqual(executions, [ACTION])


if __name__ == "__main__":
    unittest.main()
