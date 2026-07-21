from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse


HOST = "127.0.0.1"
DEFAULT_PORT = 8899

# Fixture-only credentials and markers. They are intentionally public so a judge
# can reproduce the authorization differential without using a real account.
TOKEN_A = "bug-bunny-fixture-account-a"
TOKEN_B = "bug-bunny-fixture-account-b"
MARKER_A = "BUG_BUNNY_FIXTURE_OBJECT_A_7F3A"
MARKER_B = "BUG_BUNNY_FIXTURE_OBJECT_B_91C2"

OBJECTS = {
    "A": {
        "id": "A",
        "owner": "account-a",
        "marker": MARKER_A,
        "note": "Benign fixture data owned by account A.",
    },
    "B": {
        "id": "B",
        "owner": "account-b",
        "marker": MARKER_B,
        "note": "Benign fixture data owned by account B.",
    },
}

TOKEN_OWNERS = {
    TOKEN_A: "A",
    TOKEN_B: "B",
}


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def make_handler(mode: str) -> type[BaseHTTPRequestHandler]:
    class AuthenticatedReplayHandler(BaseHTTPRequestHandler):
        server_version = "BugBunnyAuthenticatedReplayFixture/1.0"

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler method name
            parsed = urlparse(self.path)
            if parsed.path == "/health":
                self._json(200, {"ok": True, "fixture": "authenticated-replay", "mode": mode})
                return

            prefix = "/api/objects/"
            if not parsed.path.startswith(prefix):
                self._json(404, {"error": "not found"})
                return

            object_id = parsed.path[len(prefix) :]
            requested_object = OBJECTS.get(object_id)
            if requested_object is None:
                self._json(404, {"error": "object not found"})
                return

            authorization = self.headers.get("authorization", "")
            token_prefix = "Bearer "
            if not authorization.startswith(token_prefix):
                self._json(401, {"error": "missing bearer token"})
                return

            token = authorization[len(token_prefix) :]
            owned_object_id = TOKEN_OWNERS.get(token)
            if owned_object_id is None:
                self._json(401, {"error": "invalid fixture token"})
                return

            is_owner = owned_object_id == object_id
            if mode == "secure" and not is_owner:
                self._json(403, {"error": "forbidden"})
                return

            # Vulnerable mode intentionally authenticates the caller without
            # authorizing the requested object. This is local fixture behavior.
            self._json(200, requested_object)

        def log_message(self, _format: str, *_args: Any) -> None:
            return

        def _json(self, status: int, payload: dict[str, Any]) -> None:
            body = _canonical_json(payload)
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return AuthenticatedReplayHandler


def print_instructions(mode: str, port: int) -> None:
    target = f"http://{HOST}:{port}"
    account_a_command = (
        f"curl --fail-with-body --silent --show-error "
        f"-H 'Authorization: Bearer {TOKEN_A}' '{target}/api/objects/A'"
    )
    account_b_command = (
        f"curl --fail-with-body --silent --show-error "
        f"-H 'Authorization: Bearer {TOKEN_B}' '{target}/api/objects/B'"
    )

    print("Bug Bunny authenticated capture-and-replay fixture", flush=True)
    print(f"MODE={mode}", flush=True)
    print(f"TARGET={target}", flush=True)
    print(f"MARKER_A={MARKER_A}", flush=True)
    print(f"MARKER_B={MARKER_B}", flush=True)
    print("Copy-as-cURL (account A owner capture):", flush=True)
    print(account_a_command, flush=True)
    print("Copy-as-cURL (account B owner capture):", flush=True)
    print(account_b_command, flush=True)
    print(
        "Bug Bunny derives the B-token -> A-object replay from these equivalent owner captures.",
        flush=True,
    )
    print("Fixture is bound to localhost only. Press Ctrl-C to stop.", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Serve Bug Bunny's localhost-only authenticated replay demo fixture."
    )
    parser.add_argument(
        "--mode",
        choices=("vulnerable", "secure"),
        required=True,
        help="Whether account B can read account A's object.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Local TCP port (default: {DEFAULT_PORT}).",
    )
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    server = ThreadingHTTPServer((HOST, args.port), make_handler(args.mode))
    print_instructions(args.mode, server.server_port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nFixture stopped.", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
