import unittest
from scripts.sync_answered_questions import BOUNTY_ANSWERS, fnv1a_hex, parse_kind_and_problem

class TestSyncAnsweredQuestionsBounty(unittest.TestCase):
    def test_bounty_answers_presence(self):
        self.assertIn(3653, BOUNTY_ANSWERS)
        self.assertIn(3654, BOUNTY_ANSWERS)
        self.assertTrue(len(BOUNTY_ANSWERS[3653]["answer"]) > 20)
        self.assertTrue(len(BOUNTY_ANSWERS[3654]["answer"]) > 20)

    def test_fnv1a_hex_consistency(self):
        h = fnv1a_hex("test-bounty-string")
        self.assertEqual(len(h), 8)

    def test_parse_kind_and_problem(self):
        body = "**Kind:** question\n## Problem\nmacOS display mode coregraphics test\n## Error\nnone"
        kind, prob, err = parse_kind_and_problem(body)
        self.assertEqual(kind, "question")
        self.assertIn("macOS display mode", prob)

if __name__ == "__main__":
    unittest.main()
