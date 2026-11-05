"""Independent reservation service and HTTPS client for the protected MCP gateway.

Run this service OUTSIDE the agent and the gateway, under an independent OS
identity with private durable storage. The server binds loopback only; a
separately administered HTTPS/mTLS reverse proxy is required for remote use.
"""
from __future__ import annotations

import argparse
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import secrets
import ssl
from urllib.parse import urlsplit
from urllib.request import (
    Request, build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler,
)
from urllib.error import HTTPError, URLError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .witness_reservations import (
    AlreadyReserved, DurableWitnessLedger, WitnessDenied, receipt_hash,
    verify_reservation,
)

MAX_REQUEST = 512
MAX_RESPONSE = 8192
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def validate_witness_url(url: str) -> str:
    try:
        parts = urlsplit(url)
        okay = (type(url) is str and 1 <= len(url) <= 2048 and
                parts.scheme == "https" and bool(parts.hostname) and
                parts.hostname.lower() not in {"localhost", "127.0.0.1", "::1"} and
                parts.path == "/v1/reservations" and not parts.query and
                not parts.fragment and not parts.username and not parts.password)
    except (TypeError, ValueError):
        okay = False
    if not okay:
        raise WitnessDenied("independent HTTPS witness required")
    return url


class WitnessClient:
    """Fails closed if independent durable reservation or signature is missing."""

    def __init__(self, url: str, bearer: str, pinned_public_key_hex: str,
                 *, sender=None):
        self.url = validate_witness_url(url)
        if (type(bearer) is not str or not 32 <= len(bearer) <= 2048 or
                not isinstance(pinned_public_key_hex, str) or
                _HEX64.fullmatch(pinned_public_key_hex) is None):
            raise WitnessDenied("invalid protected witness client configuration")
        self._bearer = bearer
        self.public_key = pinned_public_key_hex
        self._sender = sender or self._post

    def _post(self, payload: dict) -> dict:
        req = Request(
            self.url, data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers={
                "Authorization": "Bearer " + self._bearer,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        # No automatic proxy from untrusted environment and no redirect of
        # the service credential to another origin. HTTPS validates host+CA.
        opener = build_opener(
            ProxyHandler({}), _NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
        with opener.open(req, timeout=4) as response:
            if (response.status != 201 or
                    response.headers.get_content_type() != "application/json"):
                raise WitnessDenied("witness did not acknowledge reservation")
            raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise WitnessDenied("oversized witness response")
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise WitnessDenied("malformed witness response")
            return result

    def reserve(self, action_id: str, principal_id: str) -> str:
        nonce = secrets.token_hex(16)
        try:
            response = self._sender({
                "action_id": action_id,
                "principal_id": principal_id,
                "nonce": nonce,
            })
            if not isinstance(response, dict) or set(response) != {"receipt"}:
                raise WitnessDenied("untrusted reservation response")
            receipt = response["receipt"]
            verify_reservation(
                receipt, public_key_hex=self.public_key,
                action_id=action_id, principal_id=principal_id, nonce=nonce)
            return receipt_hash(receipt)
        except (WitnessDenied, HTTPError, URLError, OSError, ValueError, TypeError) as exc:
            raise WitnessDenied("independent reservation unavailable") from exc


def make_handler(ledger: DurableWitnessLedger, bearer: str):
    if type(bearer) is not str or not 32 <= len(bearer) <= 2048:
        raise WitnessDenied("invalid reservation service access secret")

    class Handler(BaseHTTPRequestHandler):
        server_version = "AgentProofWitness"
        sys_version = ""

        def log_message(self, fmt, *args):
            # Do not log raw HTTP request content or Authorization headers.
            pass

        def _respond(self, status: int, data: dict):
            payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self):
            if self.path != "/v1/reservations":
                return self._respond(404, {"error": "not_found"})
            incoming = self.headers.get("Authorization", "")
            expected = "Bearer " + bearer
            if not hmac.compare_digest(incoming, expected):
                return self._respond(401, {"error": "unauthorized"})
            if (self.headers.get("Transfer-Encoding") or
                    self.headers.get("Content-Type", "").split(";")[0].strip() !=
                    "application/json"):
                return self._respond(400, {"error": "invalid_request"})
            try:
                n = int(self.headers.get("Content-Length", "0"))
                if n < 1 or n > MAX_REQUEST:
                    raise ValueError()
                body = self.rfile.read(n)
                def reject_duplicates(pairs):
                    obj = {}
                    for k, v in pairs:
                        if k in obj:
                            raise ValueError("duplicate JSON key")
                        obj[k] = v
                    return obj
                payload = json.loads(body, object_pairs_hook=reject_duplicates)
                if not isinstance(payload, dict) or set(payload) != {
                        "action_id", "principal_id", "nonce"}:
                    raise ValueError("invalid reservation shape")
            except (ValueError, UnicodeError, TypeError, json.JSONDecodeError):
                return self._respond(400, {"error": "invalid_request"})
            try:
                receipt = ledger.reserve(payload["action_id"],
                                         payload["principal_id"], payload["nonce"])
                return self._respond(201, {"receipt": receipt})
            except AlreadyReserved:
                return self._respond(409, {"error": "already_reserved"})
            except WitnessDenied:
                return self._respond(503, {"error": "unavailable"})

    return Handler


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="agent-proof-witness")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8030)
    parser.add_argument("--db", required=True, help="protected durable SQLite file")
    args = parser.parse_args(argv)
    if args.host not in ("127.0.0.1", "::1", "localhost") or not 1 <= args.port <= 65535:
        parser.error("witness must bind loopback behind its independent HTTPS proxy")
    seed = os.environ.get("AGENTPROOF_WITNESS_SEED_HEX", "")
    bearer = os.environ.get("AGENTPROOF_WITNESS_INBOUND_TOKEN", "")
    if not isinstance(seed, str) or _HEX64.fullmatch(seed) is None:
        parser.error("independent 32-byte Ed25519 signing seed required")
    # Never make the signing key available to the gateway or an agent process.
    os.umask(0o077)
    try:
        ledger = DurableWitnessLedger(args.db, Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(seed)))
        handler = make_handler(ledger, bearer)
    except (WitnessDenied, ValueError) as exc:
        parser.error(str(exc))
    server = ThreadingHTTPServer((args.host, args.port), handler)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
