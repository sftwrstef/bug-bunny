from __future__ import annotations

import copy
import json
import stat
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.parse import urlparse

import backend.replay_engine as replay_engine
from backend.replay_engine import (
    ReplayHostBusyError,
    ReplayValidationError,
    build_capture_plan,
    build_sanitized_artifact,
    execute_capture_plan,
    parse_curl_capture,
    validate_sanitized_artifact,
)
import backend.main as app_backend


OWNER_COOKIE = "session=OWNER_SESSION_CANARY_7c46"
PEER_COOKIE = "session=PEER_SESSION_CANARY_b193"
OWNER_MARKER = "OWNER_MARKER_CANARY_236a"
PEER_MARKER = "PEER_MARKER_CANARY_91de"
TRACE_SECRET = "TRACE_HEADER_CANARY_f407"
BODY_SECRET = "BODY_SECRET_CANARY_0a83"
EMAIL_SECRET = "capture-secret@example.test"


class AuthenticatedReplayFixture(BaseHTTPRequestHandler):
    server_version = "ControlXReplayFixture/1.0"

    @property
    def fixture_server(self) -> Any:
        return self.server

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        parsed = urlparse(self.path)
        cookie = self.headers.get("cookie", "")
        self.fixture_server.hits.append(
            {"path": parsed.path, "query": parsed.query, "cookie": cookie}
        )

        if parsed.query == "redirected=1":
            self.fixture_server.redirect_follow_hits += 1

        if parsed.path not in {"/objects/A", "/objects/B"}:
            self._json(404, {"error": "not found"})
            return

        actor = "A" if cookie == OWNER_COOKIE else "B" if cookie == PEER_COOKIE else None
        object_id = parsed.path.rsplit("/", 1)[-1]
        if actor is None:
            self._json(401, {"error": "unauthenticated"})
            return

        mode = self.fixture_server.fixture_mode
        if mode == "redirect" and actor == "A" and object_id == "A":
            self.send_response(302)
            self.send_header("location", "/objects/A?redirected=1")
            self.send_header("content-length", "0")
            self.end_headers()
            return

        if mode == "control_failure" and actor == "A" and object_id == "A":
            self._json(200, {"id": "A", "note": "owner marker intentionally absent"})
            return

        if mode == "negative_marker_collision" and actor == "B" and object_id == "B":
            self._json(
                200,
                {"id": "B", "marker": PEER_MARKER, "unexpected": OWNER_MARKER},
            )
            return

        if mode == "secure" and actor != object_id:
            self._json(403, {"error": "forbidden"})
            return

        marker = OWNER_MARKER if object_id == "A" else PEER_MARKER
        self._json(
            200,
            {
                "id": object_id,
                "marker": marker,
                "private": BODY_SECRET,
                "email": EMAIL_SECRET,
            },
        )

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class AuthenticatedReplayTest(unittest.TestCase):
    def setUp(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), AuthenticatedReplayFixture)
        self.server.fixture_mode = "vulnerable"
        self.server.hits = []
        self.server.redirect_follow_hits = 0
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def capture(self, object_id: str, cookie: str, *, extra: str = "") -> str:
        return (
            f"curl '{self.origin}/objects/{object_id}' "
            f"-H 'Cookie: {cookie}' "
            f"-H 'X-Trace: {TRACE_SECRET}' {extra}"
        ).strip()

    def plan(self, *, owner_cookie: str = OWNER_COOKIE, peer_cookie: str = PEER_COOKIE):
        return build_capture_plan(
            self.capture("A", owner_cookie),
            self.capture("B", peer_cookie),
            target_url=f"{self.origin}/",
            allowed_hosts=None,
            external=False,
        )

    def execute(self, mode: str) -> tuple[Any, dict[str, Any], dict[str, Any]]:
        self.server.fixture_mode = mode
        plan, preview = self.plan()
        execution = execute_capture_plan(
            plan,
            owner_marker=OWNER_MARKER,
            peer_marker=PEER_MARKER,
            requests_per_second=2,
        )
        return plan, preview, execution

    def artifact(self, plan: Any, execution: dict[str, Any]) -> dict[str, Any]:
        return build_sanitized_artifact(
            run_id="run-authenticated-replay-test",
            plan=plan,
            execution=execution,
            recorded_at="2026-07-21T16:00:00+00:00",
            object_kind="controlled fixture object",
        )

    def test_vulnerable_fixture_is_verified_and_stops_after_first_replay(self) -> None:
        plan, _preview, execution = self.execute("vulnerable")

        self.assertEqual(execution["verdict"], "VERIFIED")
        self.assertEqual(execution["classification"], "CROSS_ACCOUNT_OBJECT_EXPOSURE")
        self.assertEqual(execution["requestBudgetUsed"], 3)
        self.assertEqual(
            [attempt["branch"] for attempt in execution["attempts"]],
            ["peer_control", "owner_control", "cross_account_replay"],
        )
        replay = execution["attempts"][2]
        self.assertEqual(replay["status"], 200)
        self.assertTrue(replay["markerObserved"])
        self.assertEqual(len(self.server.hits), 3)

        artifact = self.artifact(plan, execution)
        self.assertTrue(
            validate_sanitized_artifact(
                artifact,
                run_id="run-authenticated-replay-test",
                allowed_hosts=["127.0.0.1"],
            )
        )
        self.assertFalse(artifact["result"]["submissionReady"])

    def test_secure_fixture_is_invalid_only_after_two_stable_replays(self) -> None:
        plan, _preview, execution = self.execute("secure")

        self.assertEqual(execution["verdict"], "INVALID")
        self.assertEqual(execution["classification"], "NO_CROSS_ACCOUNT_EXPOSURE")
        self.assertEqual(execution["requestBudgetUsed"], 4)
        self.assertEqual(
            [attempt["branch"] for attempt in execution["attempts"]],
            [
                "peer_control",
                "owner_control",
                "cross_account_replay",
                "cross_account_replay_repeat",
            ],
        )
        self.assertEqual([attempt["status"] for attempt in execution["attempts"][2:]], [403, 403])
        self.assertTrue(all(not attempt["markerObserved"] for attempt in execution["attempts"][2:]))
        self.assertEqual(len(self.server.hits), 4)

        artifact = self.artifact(plan, execution)
        self.assertTrue(
            validate_sanitized_artifact(
                artifact,
                run_id="run-authenticated-replay-test",
                allowed_hosts=["127.0.0.1"],
            )
        )

    def test_failed_same_account_control_is_inconclusive_and_never_replays(self) -> None:
        _plan, _preview, execution = self.execute("control_failure")

        self.assertEqual(execution["verdict"], "INCONCLUSIVE")
        self.assertEqual(execution["classification"], "CONTROL_FAILED")
        self.assertEqual(execution["requestBudgetUsed"], 2)
        self.assertEqual(
            [attempt["branch"] for attempt in execution["attempts"]],
            ["peer_control", "owner_control"],
        )
        self.assertEqual(len(self.server.hits), 2)

    def test_same_session_material_is_rejected_before_network_traffic(self) -> None:
        with self.assertRaisesRegex(ReplayValidationError, "distinct primary authentication credentials"):
            self.plan(peer_cookie=OWNER_COOKIE)
        self.assertEqual(self.server.hits, [])

    def test_rotated_csrf_does_not_make_one_primary_session_distinct(self) -> None:
        owner = self.capture(
            "A",
            OWNER_COOKIE,
            extra="-H 'X-CSRF-Token: OWNER_CSRF_CANARY_2c3e'",
        )
        peer = self.capture(
            "B",
            OWNER_COOKIE,
            extra="-H 'X-CSRF-Token: PEER_CSRF_CANARY_7a91'",
        )

        with self.assertRaisesRegex(ReplayValidationError, "distinct primary authentication credentials"):
            build_capture_plan(
                owner,
                peer,
                target_url=f"{self.origin}/",
                allowed_hosts=None,
                external=False,
            )
        self.assertEqual(self.server.hits, [])

    def test_ambiguous_account_binding_header_is_rejected_before_traffic(self) -> None:
        with self.assertRaisesRegex(ReplayValidationError, "ambiguous account-binding"):
            build_capture_plan(
                self.capture("A", OWNER_COOKIE, extra="-H 'X-User-Id: account-a'"),
                self.capture("B", PEER_COOKIE, extra="-H 'X-User-Id: account-b'"),
                target_url=f"{self.origin}/",
                allowed_hosts=None,
                external=False,
            )
        self.assertEqual(self.server.hits, [])

    def test_parser_rejects_unsafe_curl_flags_and_non_get_methods(self) -> None:
        unsafe_captures = [
            self.capture("A", OWNER_COOKIE, extra="-L"),
            self.capture("A", OWNER_COOKIE, extra="--data 'write=true'"),
            self.capture("A", OWNER_COOKIE, extra="--resolve 'example.test:443:127.0.0.1'"),
            self.capture("A", OWNER_COOKIE, extra="-X DELETE"),
        ]
        for raw_capture in unsafe_captures:
            with self.subTest(raw_capture=raw_capture.rsplit(" ", 1)[-1]):
                with self.assertRaises(ReplayValidationError):
                    parse_curl_capture(raw_capture)
        self.assertEqual(self.server.hits, [])

    def test_redirect_is_recorded_but_never_followed(self) -> None:
        _plan, _preview, execution = self.execute("redirect")

        self.assertEqual(execution["verdict"], "INCONCLUSIVE")
        self.assertEqual(execution["classification"], "CONTROL_FAILED")
        owner_control = execution["attempts"][1]
        self.assertEqual(owner_control["status"], 302)
        self.assertEqual(owner_control["outcome"], "redirect_blocked")
        self.assertEqual(self.server.redirect_follow_hits, 0)
        self.assertEqual(len(self.server.hits), 2)

    def test_low_entropy_or_overlapping_markers_are_rejected_before_traffic(self) -> None:
        plan, _preview = self.plan()
        invalid_pairs = [
            ("short7", PEER_MARKER),
            ("OWNER_MARKER_CANARY_236a", "prefix_OWNER_MARKER_CANARY_236a_suffix9"),
            ("AAAAAAAAAAAAAAAA1", PEER_MARKER),
        ]
        for owner_marker, peer_marker in invalid_pairs:
            with self.subTest(owner_marker=owner_marker):
                with self.assertRaises(ReplayValidationError):
                    execute_capture_plan(
                        plan,
                        owner_marker=owner_marker,
                        peer_marker=peer_marker,
                        requests_per_second=2,
                    )
        self.assertEqual(self.server.hits, [])

    def test_other_actor_marker_in_control_is_inconclusive_and_never_replays(self) -> None:
        _plan, _preview, execution = self.execute("negative_marker_collision")

        self.assertEqual(execution["verdict"], "INCONCLUSIVE")
        self.assertEqual(execution["classification"], "CONTROL_FAILED")
        self.assertEqual(execution["requestBudgetUsed"], 2)
        self.assertTrue(execution["attempts"][0]["unexpectedMarkerObserved"])
        self.assertEqual(len(self.server.hits), 2)

    def test_process_wide_origin_lock_rejects_concurrent_replay(self) -> None:
        plan, _preview = self.plan()
        entered = threading.Event()
        release = threading.Event()
        completed: list[dict[str, Any]] = []
        failures: list[BaseException] = []
        original_request_once = replay_engine._request_once

        def blocking_request_once(*args: Any, **kwargs: Any) -> dict[str, Any]:
            if not entered.is_set():
                entered.set()
                if not release.wait(timeout=3):
                    raise AssertionError("test did not release the first replay")
            return original_request_once(*args, **kwargs)

        def first_replay() -> None:
            try:
                completed.append(
                    execute_capture_plan(
                        plan,
                        owner_marker=OWNER_MARKER,
                        peer_marker=PEER_MARKER,
                        requests_per_second=2,
                    )
                )
            except BaseException as error:  # pragma: no cover - asserted below
                failures.append(error)

        with patch.object(replay_engine, "_request_once", side_effect=blocking_request_once):
            worker = threading.Thread(target=first_replay, daemon=True)
            worker.start()
            self.assertTrue(entered.wait(timeout=2))
            with self.assertRaises(ReplayHostBusyError):
                execute_capture_plan(
                    plan,
                    owner_marker=OWNER_MARKER,
                    peer_marker=PEER_MARKER,
                    requests_per_second=2,
                )
            release.set()
            worker.join(timeout=5)

        self.assertFalse(worker.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(completed[0]["verdict"], "VERIFIED")

    def test_process_wide_scheduler_paces_sequential_runs_for_same_origin(self) -> None:
        plan, _preview = self.plan()
        starts: list[float] = []

        def successful_request_once(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            starts.append(time.monotonic())
            return {
                "status": 200,
                "outcome": "response",
                "bytes": 32,
                "elapsedMs": 1,
                "responseSha256": "a" * 64,
                "markerObserved": True,
                "unexpectedMarkerObserved": False,
            }

        with patch.object(replay_engine, "_request_once", side_effect=successful_request_once):
            for _index in range(2):
                execution = execute_capture_plan(
                    plan,
                    owner_marker=OWNER_MARKER,
                    peer_marker=PEER_MARKER,
                    requests_per_second=2,
                )
                self.assertEqual(execution["verdict"], "VERIFIED")

        self.assertEqual(len(starts), 6)
        self.assertGreaterEqual(starts[3] - starts[2], 0.45)

    def test_preview_and_persisted_artifact_contain_no_capture_or_response_secrets(self) -> None:
        plan, preview, execution = self.execute("vulnerable")
        artifact = self.artifact(plan, execution)
        serialized_preview = json.dumps(preview, sort_keys=True)
        serialized_artifact = json.dumps(artifact, sort_keys=True)
        owner_url = f"{self.origin}/objects/A"
        peer_url = f"{self.origin}/objects/B"
        secrets = [
            OWNER_COOKIE,
            PEER_COOKIE,
            OWNER_MARKER,
            PEER_MARKER,
            TRACE_SECRET,
            BODY_SECRET,
            EMAIL_SECRET,
            owner_url,
            peer_url,
        ]

        for secret in secrets:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, serialized_preview)
                self.assertNotIn(secret, serialized_artifact)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authenticated-replay.json"
            path.write_text(serialized_artifact, encoding="utf-8")
            persisted = path.read_text(encoding="utf-8")
            for secret in secrets:
                self.assertNotIn(secret, persisted)

        self.assertTrue(all(artifact["result"]["redaction"].values()))
        self.assertTrue(
            validate_sanitized_artifact(
                artifact,
                run_id="run-authenticated-replay-test",
                allowed_hosts=["127.0.0.1"],
            )
        )

    def test_artifact_integrity_rejects_tampering_or_wrong_scope(self) -> None:
        plan, _preview, execution = self.execute("secure")
        artifact = self.artifact(plan, execution)
        tampered = copy.deepcopy(artifact)
        tampered["result"]["attempts"][2]["status"] = 200

        self.assertFalse(
            validate_sanitized_artifact(
                tampered,
                run_id="run-authenticated-replay-test",
                allowed_hosts=["127.0.0.1"],
            )
        )
        self.assertFalse(
            validate_sanitized_artifact(
                artifact,
                run_id="different-run",
                allowed_hosts=["127.0.0.1"],
            )
        )
        self.assertFalse(
            validate_sanitized_artifact(
                artifact,
                run_id="run-authenticated-replay-test",
                allowed_hosts=["example.test"],
            )
        )

    def test_api_lifecycle_persists_only_a_private_secret_free_receipt(self) -> None:
        previous_db = app_backend.DB_PATH
        previous_runs = app_backend.RUNS_DIR
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                app_backend.DB_PATH = root / "audit-console.sqlite3"
                app_backend.RUNS_DIR = root / "runs"
                app_backend.init_db()
                created = app_backend.create_audit(
                    app_backend.AuditCreateRequest(
                        target=f"{self.origin}/",
                        scope_notes="Two controlled localhost fixture accounts only.",
                        authorized=True,
                        mode="local_lab",
                    )
                )
                run_id = created["audit"]["run_id"]
                owner_curl = self.capture("A", OWNER_COOKIE)
                peer_curl = self.capture("B", PEER_COOKIE)
                preview = app_backend.preview_authenticated_replay(
                    run_id,
                    app_backend.AuthenticatedReplayPreviewRequest(
                        owner_curl=owner_curl,
                        peer_curl=peer_curl,
                    ),
                    x_controlx_intent=app_backend.AUTHENTICATED_REPLAY_INTENT,
                )["preview"]
                response = app_backend.run_authenticated_replay(
                    run_id,
                    app_backend.AuthenticatedReplayExecuteRequest(
                        owner_curl=owner_curl,
                        peer_curl=peer_curl,
                        object_kind="controlled fixture object",
                        owner_marker=OWNER_MARKER,
                        peer_marker=PEER_MARKER,
                        preview_sha256=preview["captureSha256"],
                        sessions_isolated=True,
                        controlled_objects_acknowledged=True,
                        third_party_data_expected=False,
                    ),
                    x_controlx_intent=app_backend.AUTHENTICATED_REPLAY_INTENT,
                )

                self.assertEqual(response["authenticated_replay_result"]["verdict"], "VERIFIED")
                artifact_path = (
                    root
                    / "runs"
                    / run_id
                    / "raw"
                    / app_backend.AUTHENTICATED_REPLAY_ARTIFACT_NAME
                )
                self.assertTrue(artifact_path.exists())
                self.assertEqual(stat.S_IMODE(artifact_path.stat().st_mode) & 0o077, 0)

                persisted = b"\n".join(
                    path.read_bytes()
                    for path in root.rglob("*")
                    if path.is_file()
                ).decode("utf-8", errors="ignore")
                for secret in (
                    OWNER_COOKIE,
                    PEER_COOKIE,
                    OWNER_MARKER,
                    PEER_MARKER,
                    TRACE_SECRET,
                    BODY_SECRET,
                    EMAIL_SECRET,
                    f"{self.origin}/objects/A",
                    f"{self.origin}/objects/B",
                ):
                    self.assertNotIn(secret, persisted)
        finally:
            app_backend.DB_PATH = previous_db
            app_backend.RUNS_DIR = previous_runs


if __name__ == "__main__":
    unittest.main()
