from __future__ import annotations

import unittest

from fastapi import HTTPException

from backend.main import AuditCreateRequest, build_external_policy_receipt


class ProgramProfileTest(unittest.TestCase):
    def payload(self, **overrides: object) -> AuditCreateRequest:
        profile: dict[str, object] = {
            "profile_id": "intigriti-pwn",
            "platform": "Intigriti",
            "program_name": "Intigriti",
            "policy_url": "https://app.intigriti.com/programs/intigriti/intigriti/detail",
            "researcher_username": "researcher_test",
            "automation_acknowledged": True,
            "human_review_acknowledged": True,
        }
        profile.update(overrides)
        return AuditCreateRequest(
            target="https://app.pwn.intigriti.rocks/",
            scope_notes="Exact Intigriti PWN host only.",
            authorized=True,
            mode="external_program",
            program_profile=profile,
        )

    def proof_payload(self, **overrides: object) -> AuditCreateRequest:
        profile: dict[str, object] = {
            "profile_id": "intigriti-pwn-proof",
            "platform": "Intigriti",
            "program_name": "Intigriti",
            "policy_url": "https://app.intigriti.com/programs/intigriti/intigriti/detail",
            "researcher_username": "researcher_test",
            "allowed_hosts": ["app.pwn.intigriti.rocks", "login.pwn.intigriti.rocks"],
            "proof_hypothesis": "Account B can read Account A's known object identifier.",
            "controlled_accounts_acknowledged": True,
            "minimum_proof_acknowledged": True,
            "automation_acknowledged": True,
            "human_review_acknowledged": True,
        }
        profile.update(overrides)
        return AuditCreateRequest(
            target="https://app.pwn.intigriti.rocks/",
            scope_notes="Two self-controlled accounts; known-ID replay only.",
            authorized=True,
            mode="external_program",
            program_profile=profile,
        )

    def test_intigriti_pwn_receipt_is_pinned_and_attributed(self) -> None:
        payload = self.payload()
        receipt = build_external_policy_receipt(payload, payload.target)
        self.assertEqual(receipt["profileId"], "intigriti-pwn")
        self.assertEqual(receipt["requestRatePerSecond"], 2)
        self.assertEqual(receipt["publishedRequestRatePerSecond"], 10)
        self.assertEqual(receipt["requestBudget"], 24)
        self.assertEqual(receipt["allowedMethods"], ["GET", "HEAD"])
        self.assertEqual(receipt["researcherUsername"], "researcher_test")
        self.assertIn("X-Intigriti-Username", receipt["attributionHeaders"])

    def test_intigriti_pwn_receipt_rejects_wrong_host(self) -> None:
        payload = self.payload()
        with self.assertRaises(HTTPException) as raised:
            build_external_policy_receipt(payload, "https://example.com/")
        self.assertIn("pwn.intigriti.rocks", str(raised.exception.detail))

    def test_intigriti_pwn_receipt_rejects_placeholder_identity(self) -> None:
        payload = self.payload(researcher_username="<username>")
        with self.assertRaises(HTTPException) as raised:
            build_external_policy_receipt(payload, payload.target)
        self.assertIn("real Intigriti username", str(raised.exception.detail))

    def test_controlled_proof_receipt_enables_bounded_ephemeral_replay(self) -> None:
        payload = self.proof_payload()
        receipt = build_external_policy_receipt(payload, payload.target)
        self.assertEqual(receipt["profileId"], "intigriti-pwn-proof")
        self.assertEqual(receipt["executionMode"], "authenticated-capture-replay")
        self.assertTrue(receipt["authenticatedReplayEnabled"])
        self.assertEqual(receipt["automatedCollection"], "user-initiated ephemeral credentials only")
        self.assertEqual(receipt["requestRatePerSecond"], 2)
        self.assertEqual(receipt["requestBudget"], 4)
        self.assertEqual(receipt["allowedReplayMethods"], ["GET"])
        self.assertEqual(receipt["redirectPolicy"], "do-not-follow")
        self.assertEqual(
            receipt["allowedHosts"],
            ["app.pwn.intigriti.rocks", "login.pwn.intigriti.rocks"],
        )
        self.assertIn("Account B", receipt["proofHypothesis"])
        self.assertIn("third-party accounts or data", receipt["prohibitedActions"])
        self.assertTrue(any("marker-present booleans" in item for item in receipt["requiredEvidence"]))
        self.assertTrue(any("capture, template, and response hashes only" in item for item in receipt["requiredEvidence"]))
        self.assertFalse(any("body fragment" in item for item in receipt["requiredEvidence"]))
        self.assertTrue(any("raw cURL" in item for item in receipt["prohibitedActions"]))

    def test_controlled_proof_receipt_rejects_wildcards_and_implicit_hosts(self) -> None:
        wildcard_payload = self.proof_payload(allowed_hosts=["*.pwn.intigriti.rocks"])
        with self.assertRaises(HTTPException) as wildcard_error:
            build_external_policy_receipt(wildcard_payload, wildcard_payload.target)
        self.assertIn("wildcards", str(wildcard_error.exception.detail))

        missing_target_payload = self.proof_payload(allowed_hosts=["login.pwn.intigriti.rocks"])
        with self.assertRaises(HTTPException) as missing_target_error:
            build_external_policy_receipt(missing_target_payload, missing_target_payload.target)
        self.assertIn("target hostname", str(missing_target_error.exception.detail))

        port_payload = self.proof_payload()
        with self.assertRaises(HTTPException) as port_error:
            build_external_policy_receipt(port_payload, "https://app.pwn.intigriti.rocks:8443/")
        self.assertIn("port 443", str(port_error.exception.detail))

    def test_controlled_proof_receipt_requires_two_controlled_accounts_and_stop_condition(self) -> None:
        accounts_payload = self.proof_payload(controlled_accounts_acknowledged=False)
        with self.assertRaises(HTTPException) as accounts_error:
            build_external_policy_receipt(accounts_payload, accounts_payload.target)
        self.assertIn("both attacker and victim accounts", str(accounts_error.exception.detail))

        stop_payload = self.proof_payload(minimum_proof_acknowledged=False)
        with self.assertRaises(HTTPException) as stop_error:
            build_external_policy_receipt(stop_payload, stop_payload.target)
        self.assertIn("minimum-proof stop condition", str(stop_error.exception.detail))

    def test_generic_authenticated_replay_profile_supports_all_program_platforms(self) -> None:
        for platform in ("HackerOne", "Bugcrowd", "Intigriti"):
            with self.subTest(platform=platform):
                payload = AuditCreateRequest(
                    target="https://api.example.test/",
                    scope_notes="Two controlled accounts and two harmless marked objects only.",
                    authorized=True,
                    mode="external_program",
                    program_profile={
                        "profile_id": "authenticated-replay",
                        "platform": platform,
                        "program_name": "Controlled fixture program",
                        "policy_url": "https://example.test/security-policy",
                        "allowed_hosts": ["api.example.test"],
                        "proof_hypothesis": "Account B can read Account A's known object.",
                        "controlled_accounts_acknowledged": True,
                        "minimum_proof_acknowledged": True,
                        "automation_acknowledged": True,
                        "human_review_acknowledged": True,
                    },
                )
                receipt = build_external_policy_receipt(payload, payload.target)
                self.assertTrue(receipt["authenticatedReplayEnabled"])
                self.assertEqual(receipt["requestBudget"], 4)
                self.assertEqual(receipt["allowedReplayMethods"], ["GET"])
                self.assertEqual(receipt["redirectPolicy"], "do-not-follow")
                self.assertEqual(receipt["allowedHosts"], ["api.example.test"])


if __name__ == "__main__":
    unittest.main()
