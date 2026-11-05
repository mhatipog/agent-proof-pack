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
from test_mcp_gateway import POLICY


@unittest.skipUnless(_HAS_SDK, "optional mcp/httpx gateway dependencies not installed")
class TransportAdmissionTests(unittest.IsolatedAsyncioTestCase):
    async def test_no_token_and_invalid_token_are_http_401(self):
        operations = []
        def verify(token, policy):
            raise AuthorizationDenied("invalid JWT")
        def apply(dsn, action_id):
            operations.append(action_id)
            raise AssertionError("transport admitted unauthenticated tool")
        config = GatewayConfig(POLICY, "postgresql://synthetic-only",
                               "https://agent-proof.example.invalid/mcp")
        gateway = GuardedActionGateway(config, verifier=verify, executor=apply)
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


if __name__ == "__main__":
    unittest.main()
