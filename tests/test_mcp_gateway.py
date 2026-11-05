"""Offline attacker cases for the narrow server-side execution boundary."""
import unittest
from agentproof.entra import AuthorizationDenied, EntraPolicy
from agentproof.mcp_gateway import GatewayConfig, GatewayDenied, GuardedActionGateway

TENANT = "11111111-1111-4111-8111-111111111111"
APP = "22222222-2222-4222-8222-222222222222"
PRINCIPAL = "33333333-3333-4333-8333-333333333333"
ACTION = "44444444-4444-4444-8444-444444444444"
POLICY = EntraPolicy(
    tenant_id=TENANT, audience="api://agent-proof-guard",
    application_id=APP, principal_object_id=PRINCIPAL,
    required_role="AgentProof.Apply",
)


class MCPGatewayTests(unittest.TestCase):
    def setUp(self):
        self.executed = []
        self.authenticated = []
        self.config = GatewayConfig(POLICY, "postgresql://protected-role",
                                    "https://agent-proof.example.invalid/mcp")

        def verify(token, policy):
            self.authenticated.append(token)
            if token != "valid":
                raise AuthorizationDenied("bad token")
            return {"tenant_id": TENANT, "application_id": APP,
                    "principal_object_id": PRINCIPAL,
                    "authorized_role": "AgentProof.Apply"}

        def execute(dsn, action_id):
            self.executed.append((dsn, action_id))
            return {"action_id": action_id, "state": "submitted_unverified"}

        self.gateway = GuardedActionGateway(self.config, verifier=verify, executor=execute)

    def test_authorized_grant_submission_is_not_verified_effect(self):
        self.assertEqual(self.gateway.apply("valid", ACTION),
                         {"action_id": ACTION, "state": "submitted_unverified",
                          "independent_effect_verified": False})
        self.assertEqual(self.executed, [("postgresql://protected-role", ACTION)])

    def test_absent_invalid_token_rejected_before_sql(self):
        for token in ("", "bad", None):
            with self.assertRaises(GatewayDenied):
                self.gateway.apply(token, ACTION)
        self.assertEqual(self.executed, [])

    def test_arbitrary_sql_path_traversal_and_malformed_uuid_rejected(self):
        for action in ("DROP TABLE users", "../secrets", "", None, "4444",
                       ACTION + " ", {"action_id": ACTION},
                       ("a" + ACTION[1:]).upper()):
            with self.assertRaises(GatewayDenied):
                self.gateway.apply("valid", action)
        self.assertEqual(self.executed, [])
        self.assertEqual(self.authenticated, [])

    def test_wrong_tenant_principal_application_role_rejected(self):
        expected = {"tenant_id": TENANT, "application_id": APP,
                    "principal_object_id": PRINCIPAL,
                    "authorized_role": "AgentProof.Apply"}
        for key, value in (("tenant_id", APP), ("application_id", PRINCIPAL),
                           ("principal_object_id", APP),
                           ("authorized_role", "Administrator")):
            identity = {**expected, key: value}
            gate = GuardedActionGateway(self.config,
                                        verifier=lambda t, p: identity,
                                        executor=lambda d, a: self.fail("unauthorized execution"))
            with self.assertRaises(GatewayDenied):
                gate.apply("valid", ACTION)

    def test_failed_or_ambiguous_db_result_is_not_success(self):
        expected = {"tenant_id": TENANT, "application_id": APP,
                    "principal_object_id": PRINCIPAL,
                    "authorized_role": "AgentProof.Apply"}
        for outcome in (None, {}, {"action_id": ACTION, "state": "verified"},
                        {"action_id": TENANT, "state": "submitted_unverified"}):
            gate = GuardedActionGateway(self.config, verifier=lambda t, p: expected,
                                        executor=lambda d, a: outcome)
            with self.assertRaises(GatewayDenied):
                gate.apply("valid", ACTION)

        def uncertain(*args):
            raise OSError("could have committed; secret connection string")
        gate = GuardedActionGateway(self.config, verifier=lambda t, p: expected,
                                    executor=uncertain)
        with self.assertRaisesRegex(GatewayDenied, "^action denied or unavailable$"):
            gate.apply("valid", ACTION)

    def test_gateway_config_refuses_http_loopback_and_url_credentials(self):
        for url in ("http://agent-proof.example.invalid/mcp",
                    "http://127.0.0.1:8000/mcp",
                    "https://localhost/mcp",
                    "https://user:password@agent-proof.example.invalid/mcp",
                    "https://agent-proof.example.invalid/mcp?q=secret",
                    "https://agent-proof.example.invalid/wrong"):
            with self.assertRaises(GatewayDenied):
                GatewayConfig(POLICY, "postgresql://protected-role", url).validate()
        with self.assertRaises(GatewayDenied):
            GatewayConfig(POLICY, "", "https://agent-proof.example.invalid/mcp").validate()

    def test_client_cannot_configure_role_through_env(self):
        env = {
            "AGENTPROOF_ENTRA_TENANT_ID": TENANT,
            "AGENTPROOF_ENTRA_AUDIENCE": POLICY.audience,
            "AGENTPROOF_ENTRA_CLIENT_ID": APP,
            "AGENTPROOF_ENTRA_PRINCIPAL_OID": PRINCIPAL,
            "AGENTPROOF_ENTRA_REQUIRED_ROLE": "Administrator",
            "AGENTPROOF_ACTOR_DSN": "postgresql://protected-role",
            "AGENTPROOF_MCP_RESOURCE_URL": "https://agent-proof.example.invalid/mcp",
        }
        self.assertEqual(GatewayConfig.from_env(env).policy.required_role, "AgentProof.Apply")


if __name__ == "__main__":
    unittest.main()
