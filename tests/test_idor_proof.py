from __future__ import annotations

import unittest

from proofs.idor_proof import run_idor_proof


class IdorProofTest(unittest.TestCase):
    def test_same_state_control_proves_victim_data_exposure(self) -> None:
        proof = run_idor_proof()

        self.assertEqual(proof["verdict"], "confirmed")
        self.assertEqual(proof["negative_control"]["response"]["status"], 401)
        self.assertEqual(proof["control"]["response"]["status"], 200)
        self.assertEqual(proof["control"]["response"]["body"]["id"], "attacker")
        self.assertEqual(proof["exploit"]["response"]["status"], 200)
        self.assertEqual(proof["exploit"]["response"]["body"]["id"], "victim")
        self.assertTrue(proof["assertions"]["victim_private_data_exposed"])
        self.assertNotIn("controlx-attacker-token", str(proof))


if __name__ == "__main__":
    unittest.main()
