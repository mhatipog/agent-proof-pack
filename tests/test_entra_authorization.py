"""Identity-bound guard regression tests; every case uses real RSA signatures."""
import time
import unittest
from unittest.mock import patch
try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    jwt = None
    rsa = None
from agentproof.entra import EntraPolicy, AuthorizationDenied, verify_access_token
from agentproof.entra_guard import authorized_apply

TENANT = "11111111-2222-4333-8444-555555555555"
CLIENT = "22222222-3333-4444-8555-666666666666"
PRINCIPAL = "33333333-4444-4555-8666-777777777777"
AUDIENCE = "api://44444444-5555-4666-8777-888888888888"


class KeyClient:
    def __init__(self, key):
        self.key = key
    def get_signing_key_from_jwt(self, token):
        return type("SigningKey", (), {"key": self.key})()


@unittest.skipUnless(jwt is not None and rsa is not None, "install optional entra dependencies")
class AuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.policy = EntraPolicy(TENANT, AUDIENCE, CLIENT, PRINCIPAL, "AgentProof.Apply")
        cls.client = KeyClient(cls.key.public_key())

    def claims(self, **changes):
        now = int(time.time())
        result = {"ver": "2.0", "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
                  "aud": AUDIENCE, "tid": TENANT, "azp": CLIENT, "oid": PRINCIPAL,
                  "roles": ["AgentProof.Apply"], "idtyp": "app",
                  "iat": now, "nbf": now - 10, "exp": now + 180}
        result.update(changes)
        return result

    def token(self, key=None, **changes):
        return jwt.encode(self.claims(**changes), key or self.key, algorithm="RS256", headers={"kid": "testkey"})

    def verify(self, token, policy=None):
        return verify_access_token(token, policy or self.policy, jwk_client=self.client)

    def test_accept_signed_tenant_bound_role(self):
        self.assertEqual(self.verify(self.token())["authorized_role"], "AgentProof.Apply")

    def test_v1_signed_token(self):
        token = self.token(ver="1.0", iss=f"https://sts.windows.net/{TENANT}/",
                           appid=CLIENT, azp=None)
        self.assertEqual(self.verify(token)["token_version"], "1.0")

    def test_unauthorized_tokens(self):
        variants = [
            {"aud": "https://api.fabric.microsoft.com"},
            {"aud": "https://graph.microsoft.com"},
            {"iss": f"https://sts.windows.net/{TENANT}/"},
            {"tid": "99999999-9999-4999-8999-999999999999"},
            {"oid": "99999999-9999-4999-8999-999999999999"},
            {"azp": "99999999-9999-4999-8999-999999999999"},
            {"roles": []}, {"roles": ["AgentProof.Read"]},
            {"scp": "user_impersonation"}, {"idtyp": "user"},
            {"exp": int(time.time()) - 500},
            {"nbf": int(time.time()) + 500},
            {"aud": [AUDIENCE, "https://graph.microsoft.com"]},
        ]
        for claims in variants:
            with self.subTest(claims=claims), self.assertRaises(AuthorizationDenied):
                self.verify(self.token(**claims))

    def test_bad_signature(self):
        with self.assertRaises(AuthorizationDenied):
            self.verify(self.token(key=self.other))

    def test_missing_role_configuration(self):
        with self.assertRaises(AuthorizationDenied):
            self.verify(self.token(), EntraPolicy(TENANT, AUDIENCE, CLIENT, PRINCIPAL, ""))

    def test_no_cross_resource_grants(self):
        bad_policy = EntraPolicy(TENANT, "https://api.fabric.microsoft.com",
                                 CLIENT, PRINCIPAL, "AgentProof.Apply")
        with self.assertRaises(AuthorizationDenied):
            self.verify(self.token(), bad_policy)

    def test_transaction_never_called_before_accepted_identity(self):
        env = {
            "AGENTPROOF_ENTRA_TENANT_ID": TENANT,
            "AGENTPROOF_ENTRA_AUDIENCE": AUDIENCE,
            "AGENTPROOF_ENTRA_CLIENT_ID": CLIENT,
            "AGENTPROOF_ENTRA_PRINCIPAL_OID": PRINCIPAL,
            "AGENTPROOF_ENTRA_REQUIRED_ROLE": "AgentProof.Apply",
            "AGENTPROOF_ENTRA_ACCESS_TOKEN": "bad-token",
            "AGENTPROOF_ACTOR_DSN": "postgresql://not-connected",
        }
        with patch("agentproof.entra_guard.apply_approved") as operation:
            with self.assertRaises(AuthorizationDenied):
                authorized_apply("00000000-0000-4000-8000-000000000001",
                                 environ=env, verifier=lambda token, policy: self.verify(token))
            operation.assert_not_called()
            env["AGENTPROOF_ENTRA_ACCESS_TOKEN"] = self.token()
            operation.return_value = {"action_id": "00000000-0000-4000-8000-000000000001",
                                      "state": "submitted_unverified"}
            outcome = authorized_apply("00000000-0000-4000-8000-000000000001",
                                       environ=env, verifier=lambda token, policy: self.verify(token))
            self.assertEqual(outcome["state"], "submitted_unverified")
            self.assertFalse(outcome["database_effect_verified"])
            operation.assert_called_once()


if __name__ == "__main__":
    unittest.main()
