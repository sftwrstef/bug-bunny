from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException
from pydantic import ValidationError

from backend.main import (
    CONTROLLED_PROOF_ARTIFACT_NAME,
    AuditRunModel,
    ControlledProofResultRequest,
    apply_analysis_server_gate,
    build_ai_input,
    build_controlled_proof_artifact,
    ensure_mock_scan_allowed,
    load_controlled_proof_artifact,
    load_engine_audit,
    write_json_once,
)


class ControlledProofTest(unittest.TestCase):
    def make_run(self, root: Path, **policy_overrides: object) -> AuditRunModel:
        policy: dict[str, object] = {
            "profileId": "intigriti-pwn-proof",
            "allowedHosts": ["app.pwn.intigriti.rocks", "login.pwn.intigriti.rocks"],
            "proofHypothesis": "Account B can access Account A's known draft identifier.",
            "allowedReplayMethods": ["GET"],
        }
        policy.update(policy_overrides)
        raw_dir = root / "raw"
        raw_dir.mkdir(parents=True)
        reports_dir = root / "reports"
        reports_dir.mkdir()
        return AuditRunModel(
            run_id="run-controlled-proof",
            target="https://app.pwn.intigriti.rocks/",
            target_type="url",
            scope_notes="Two controlled accounts; one known draft; stop after two denied replays.",
            authorized=True,
            mode="external_program",
            policy_receipt=policy,
            status="proof_scope_recorded",
            run_dir=str(root),
            raw_dir=str(raw_dir),
            reports_dir=str(reports_dir),
            created_at="2026-07-21T00:00:00+00:00",
            updated_at="2026-07-21T00:00:00+00:00",
        )

    def payload(self, **overrides: object) -> ControlledProofResultRequest:
        values: dict[str, object] = {
            "owner_actor": "bugbunny",
            "peer_actor": "bugbunny_b",
            "object_kind": "submission_draft",
            "target_host": "app.pwn.intigriti.rocks",
            "object_locator_sha256": "a" * 64,
            "owner_marker_observed": True,
            "peer_outcomes": ["forbidden", "forbidden"],
            "peer_marker_observed": False,
            "sessions_isolated": True,
            "third_party_data_observed": False,
        }
        values.update(overrides)
        return ControlledProofResultRequest(**values)

    def test_two_denials_close_only_the_tested_draft_hypothesis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = build_controlled_proof_artifact(self.make_run(Path(directory)), self.payload())

        result = artifact["result"]
        self.assertEqual(result["verdict"], "INVALID")
        self.assertEqual(result["classification"], "NO_IDOR")
        self.assertEqual(result["testedScope"], "tested_draft_only")
        self.assertFalse(result["submissionReady"])
        self.assertTrue(result["truthfulControl"]["markerObserved"])
        self.assertEqual(result["authorizationBranch"]["attempts"], 2)
        self.assertEqual(result["authorizationBranch"]["outcomes"], ["forbidden", "forbidden"])
        self.assertFalse(result["authorizationBranch"]["markerObserved"])

        serialized = json.dumps(artifact)
        self.assertNotIn("BUGBUNNY-", serialized)
        self.assertNotIn("Forbidden —", serialized)
        self.assertNotIn("session_cookie_value", serialized.lower())
        self.assertNotIn("researcher@example.com", serialized.lower())

    def test_import_schema_rejects_extra_or_non_closing_claims(self) -> None:
        with self.assertRaises(ValidationError):
            self.payload(object_marker="BUGBUNNY-SECRET")
        with self.assertRaises(ValidationError):
            self.payload(peer_outcomes=["forbidden"])
        with self.assertRaises(ValidationError):
            self.payload(owner_marker_observed=False)
        with self.assertRaises(ValidationError):
            self.payload(peer_marker_observed=True)
        with self.assertRaises(ValidationError):
            self.payload(sessions_isolated=False)
        with self.assertRaises(ValidationError):
            self.payload(third_party_data_observed=True)

    def test_builder_rejects_wrong_profile_actor_or_host(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(HTTPException):
                build_controlled_proof_artifact(
                    self.make_run(root, profileId="intigriti-pwn"),
                    self.payload(),
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(HTTPException):
                build_controlled_proof_artifact(
                    self.make_run(root),
                    self.payload(peer_actor="bugbunny"),
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(HTTPException):
                build_controlled_proof_artifact(
                    self.make_run(root),
                    self.payload(target_host="other.pwn.intigriti.rocks"),
                )

    def test_receipt_is_immutable_private_and_separate_from_web_audit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run = self.make_run(Path(directory))
            artifact = build_controlled_proof_artifact(run, self.payload())
            path = Path(run.raw_dir) / CONTROLLED_PROOF_ARTIFACT_NAME
            write_json_once(path, artifact)

            self.assertIsNone(load_engine_audit(run))
            self.assertEqual(load_controlled_proof_artifact(run), artifact)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0)
            ai_input = build_ai_input(run, [])
            self.assertTrue(ai_input["controlled_proof_supplied"])
            self.assertFalse(ai_input["deterministic_proof_supplied"])
            with self.assertRaises(HTTPException) as duplicate:
                write_json_once(path, artifact)
            self.assertEqual(duplicate.exception.status_code, 409)

    def test_closed_proof_rejects_mock_findings_and_controls_ai_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run = self.make_run(Path(directory))
            artifact = build_controlled_proof_artifact(run, self.payload())
            with self.assertRaises(HTTPException) as blocked:
                ensure_mock_scan_allowed(run)
            self.assertIn("Mock findings", str(blocked.exception.detail))

            model_output = {
                "verdict": "OBSERVATION",
                "submission_ready": True,
                "summary": "Model tried a broader advisory label.",
            }
            gated, original = apply_analysis_server_gate(
                run,
                {"deterministic_proof_supplied": False},
                model_output,
                artifact,
            )
            self.assertEqual(original["verdict"], "OBSERVATION")
            self.assertEqual(gated["verdict"], "INVALID")
            self.assertFalse(gated["submission_ready"])


if __name__ == "__main__":
    unittest.main()
