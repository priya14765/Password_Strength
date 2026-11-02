"""Unit tests for the standalone local password checker."""

import contextlib
import io
import json
import unittest
from unittest.mock import patch

import password_checker


class AnalyzePasswordTests(unittest.TestCase):
    def test_empty_password_has_zero_entropy_and_is_weak(self):
        assessment = password_checker.analyze_password("")

        self.assertEqual(assessment.length, 0)
        self.assertEqual(assessment.shannon_entropy_bits_per_character, 0.0)
        self.assertEqual(assessment.empirical_shannon_entropy_bits, 0.0)
        self.assertEqual(assessment.strength, "Weak")
        self.assertTrue(assessment.recommendations)

    def test_shannon_entropy_uses_observed_character_frequencies(self):
        assessment = password_checker.analyze_password("aab")

        self.assertAlmostEqual(
            assessment.shannon_entropy_bits_per_character, 0.9182958340544896
        )
        self.assertAlmostEqual(
            assessment.empirical_shannon_entropy_bits, 2.7548875021634687
        )

    def test_common_password_is_detected_and_capped(self):
        assessment = password_checker.analyze_password("password123")

        self.assertIn("common_password", assessment.findings)
        self.assertNotIn("repeated_characters_or_chunks", assessment.findings)
        self.assertLessEqual(assessment.estimated_search_space_bits, 10.0)
        self.assertEqual(assessment.strength, "Weak")
        self.assertTrue(
            any("Replace the common word/password" in item
                for item in assessment.recommendations)
        )

    def test_leetspeak_common_password_and_admin_are_detected(self):
        for password in ("P@ssw0rd!", "adm!n"):
            with self.subTest(password=password):
                assessment = password_checker.analyze_password(password)
                self.assertIn(
                    "leetspeak_weak_substitution", assessment.findings
                )
                self.assertIn("common_dictionary_word", assessment.findings)
                self.assertTrue(
                    any("substitutions" in item
                        for item in assessment.recommendations)
                )

    def test_ascending_keyboard_and_normalized_sequences_are_detected(self):
        for password in ("abcDEF", "123456", "QWERTY", "p@ssword123"):
            with self.subTest(password=password):
                assessment = password_checker.analyze_password(password)
                self.assertIn("predictable_sequence", assessment.findings)

    def test_descending_sequence_is_detected(self):
        assessment = password_checker.analyze_password("zyx987")
        self.assertIn("predictable_sequence", assessment.findings)

    def test_repeated_characters_and_chunks_are_detected(self):
        for password in ("aaaa", "abcabcabc", "QabcabcZ9!"):
            with self.subTest(password=password):
                assessment = password_checker.analyze_password(password)
                self.assertIn(
                    "repeated_characters_or_chunks", assessment.findings
                )

    def test_moderate_password_gets_contextual_length_feedback(self):
        assessment = password_checker.analyze_password("Lion7")

        self.assertEqual(assessment.strength, "Moderate")
        self.assertTrue(
            any("Increase the length from 5" in item
                for item in assessment.recommendations)
        )
        self.assertTrue(
            any("symbols" in item
                for item in assessment.recommendations)
        )

    def test_long_varied_password_is_strong_without_findings(self):
        assessment = password_checker.analyze_password(
            "N7@qL2#vR9!xC4$zB8^mP3&"
        )

        self.assertEqual(assessment.strength, "Strong")
        self.assertGreaterEqual(assessment.estimated_search_space_bits, 60.0)
        self.assertEqual(assessment.findings, ())

    def test_assessment_never_contains_the_password(self):
        password = "PrivateValue9!Random"
        assessment = password_checker.analyze_password(password)

        self.assertNotIn(password, repr(assessment))
        self.assertNotIn(password, json.dumps(assessment.__dict__))

    def test_non_string_input_is_rejected(self):
        with self.assertRaises(TypeError):
            password_checker.analyze_password(None)


class CliTests(unittest.TestCase):
    def test_json_cli_does_not_echo_or_serialize_the_password(self):
        password = "DoNotPrintThis9!Value"
        stdout = io.StringIO()
        with patch.object(password_checker.getpass, "getpass", return_value=password):
            with contextlib.redirect_stdout(stdout):
                status = password_checker.main(["--json"])

        self.assertEqual(status, 0)
        self.assertNotIn(password, stdout.getvalue())
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["length"], len(password))
        self.assertIn("shannon_entropy_bits_per_character", payload)

    def test_cancelled_prompt_returns_nonzero_without_traceback(self):
        stderr = io.StringIO()
        with patch.object(
            password_checker.getpass, "getpass", side_effect=KeyboardInterrupt
        ):
            with contextlib.redirect_stderr(stderr):
                status = password_checker.main([])

        self.assertEqual(status, 130)
        self.assertIn("Input cancelled.", stderr.getvalue())

    def test_insecure_getpass_fallback_is_rejected(self):
        stderr = io.StringIO()
        with patch.object(
            password_checker.getpass,
            "getpass",
            side_effect=password_checker.getpass.GetPassWarning,
        ):
            with contextlib.redirect_stderr(stderr):
                status = password_checker.main([])

        self.assertEqual(status, 2)
        self.assertIn("Secure hidden input is unavailable", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
