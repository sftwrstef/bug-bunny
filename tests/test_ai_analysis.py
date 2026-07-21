from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from backend.main import AuditRunModel, build_ai_input, parse_analysis_json, redact_text, redact_url


class AIAnalysisTest(unittest.TestCase):
    def test_redaction_removes_query_secrets_and_sensitive_values(self) -> None:
        self.assertEqual(redact_url("https://example.com/path?token=secret#part"), "https://example.com/path")
        redacted = redact_text("Authorization: Bearer abc.def Cookie=session-value password=hunter2")
        self.assertNotIn("abc.def", redacted)
        self.assertNotIn("session-value", redacted)
        self.assertNotIn("hunter2", redacted)

    def test_ai_input_never_includes_cookie_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            raw_dir = Path(directory)
            engine = {
                "evidence": {
                    "http": {
                        "status": 200,
                        "finalUrl": "https://example.com/?session=private",
                        "title": "Fixture",
                        "forms": 1,
                        "links": ["https://example.com/account"],
                        "headers": {
                            "content-security-policy": "default-src 'self'",
                            "set-cookie": "SessionId=never-send-me; Secure; HttpOnly; SameSite=Lax",
                        },
                    },
                    "requestLog": [{"method": "GET", "url": "https://example.com/?session=private", "status": 200}],
                }
            }
            (raw_dir / "web_audit.json").write_text(json.dumps(engine), encoding="utf-8")
            run = AuditRunModel(
                run_id="run-test",
                target="https://example.com/?session=private",
                target_type="url",
                scope_notes="Authorization: Bearer do-not-send",
                authorized=True,
                mode="external_program",
                policy_receipt={"platform": "HackerOne", "programName": "Fixture", "exactScopeUrl": "https://example.com/"},
                status="web_audit_complete",
                run_dir=directory,
                raw_dir=directory,
                reports_dir=directory,
                created_at="2026-01-01T00:00:00+00:00",
                updated_at="2026-01-01T00:00:00+00:00",
            )

            payload = build_ai_input(run, [])
            serialized = json.dumps(payload)
            self.assertNotIn("never-send-me", serialized)
            self.assertNotIn("do-not-send", serialized)
            self.assertNotIn("session=private", serialized)
            self.assertTrue(payload["response"]["cookie_attributes"]["secure"])
            self.assertTrue(payload["response"]["cookie_attributes"]["http_only"])

    def test_structured_analysis_validation(self) -> None:
        analysis = parse_analysis_json(
            json.dumps(
                {
                    "verdict": "OBSERVATION",
                    "summary": "No victim-centered impact is demonstrated.",
                    "observed_facts": ["One GET returned HTTP 200."],
                    "unsupported_claims": ["A vulnerability exists."],
                    "likely_dismissal": "Informational only.",
                    "attacker": "None identified.",
                    "victim": "None identified.",
                    "asset_or_authority_at_risk": "None demonstrated.",
                    "safest_next_manual_step": "Review the policy without making traffic.",
                    "proof_requirements": ["Demonstrate concrete impact."],
                    "submission_ready": False,
                }
            )
        )
        self.assertEqual(analysis["verdict"], "OBSERVATION")
        self.assertFalse(analysis["submission_ready"])

    def test_schema_normalizes_safe_empty_identity_fields(self) -> None:
        analysis = parse_analysis_json(
            json.dumps(
                {
                    "verdict": "OBSERVATION",
                    "summary": "No impact is demonstrated.",
                    "observed_facts": [],
                    "unsupported_claims": [],
                    "likely_dismissal": True,
                    "attacker": None,
                    "victim": None,
                    "asset_or_authority_at_risk": None,
                    "safest_next_manual_step": "Stop.",
                    "proof_requirements": [],
                    "submission_ready": False,
                }
            )
        )
        self.assertIn("Likely dismissal", analysis["likely_dismissal"])
        self.assertEqual(analysis["attacker"], "None identified.")
        self.assertEqual(analysis["victim"], "None identified.")


if __name__ == "__main__":
    unittest.main()
