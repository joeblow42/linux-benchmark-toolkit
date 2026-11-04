"""Owner-approved 2026-11-04 D1 PARTIAL/EXIT_NONZERO status mapping.

Contract provenance: governance/cp03_d1_nonzero_status_owner_decision_2026-11-04.json.
No new status vocabulary, user-supplied argv, or source execution.
"""
import unittest

from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import _status_for


class D1NonzeroOwnerDecisionOracles(unittest.TestCase):
    def receipt(self, **changes):
        p = {
            "outcome":"PARTIAL", "reason":"EXIT_NONZERO",
            "authorization_class":"D1", "exit_code":2,
            "timed_out":False, "capture_limited":False,
        }
        p.update(changes)
        return p

    def test_real_nonzero_d1_with_original_is_incomplete_not_parser_failed(self):
        for parser_state in ("OK", "FAILED", "NOT_RUN"):
            with self.subTest(parser_state=parser_state):
                self.assertEqual(
                    _status_for(self.receipt(), [object()],
                                parser_state=parser_state),
                    ("PARTIAL", "SOURCE_INCOMPLETE"))

    def test_return_code_positive_and_negative_are_both_nonzero(self):
        for code in (1, 2, 255, -1, -15, 65535, -65535):
            with self.subTest(code=code):
                self.assertEqual(
                    _status_for(self.receipt(exit_code=code),
                                [object()], parser_state="OK"),
                    ("PARTIAL", "SOURCE_INCOMPLETE"))

    def test_no_original_or_invalid_return_code_cannot_prove_partial(self):
        for code in (None, 0, True, False, "2", 1.5, 65536, -65536):
            with self.subTest(code=code), self.assertRaises(CanonicalContractError):
                _status_for(self.receipt(exit_code=code), [object()],
                            parser_state="OK")
        with self.assertRaises(CanonicalContractError):
            _status_for(self.receipt(), [], parser_state="NOT_RUN")

    def test_non_d1_or_timeout_or_capture_limit_not_silently_reclassified(self):
        for attrs in (
            {"authorization_class":"D0"},
            {"authorization_class":"O1"},
            {"authorization_class":None},
            {"timed_out":True},
        ):
            with self.subTest(attrs=attrs), self.assertRaises(CanonicalContractError):
                _status_for(self.receipt(**attrs), [object()], parser_state="OK")

    def test_prior_capture_limit_takes_precedence_over_exit_interpretation(self):
        self.assertEqual(
            _status_for(self.receipt(capture_limited=True),
                        [object()], parser_state="OK"),
            ("PARTIAL", "CAPTURE_LIMIT"))

    def test_other_unknown_or_conflicting_outcomes_remain_fail_closed(self):
        for attrs in (
            {"reason":"UNKNOWN_NONZERO"},
            {"outcome":"CAPTURED", "reason":"EXIT_NONZERO"},
            {"outcome":"FAILED", "reason":"EXIT_NONZERO"},
        ):
            with self.subTest(attrs=attrs), self.assertRaises(CanonicalContractError):
                _status_for(self.receipt(**attrs), [object()], parser_state="OK")

    def test_prior_source_partial_reason_preserved(self):
        self.assertEqual(
            _status_for(self.receipt(reason="SOURCE_INCOMPLETE"),
                        [object()], parser_state="OK"),
            ("PARTIAL", "SOURCE_INCOMPLETE"))
        self.assertEqual(
            _status_for(self.receipt(reason="CAPTURE_LIMIT", capture_limited=True),
                        [object()], parser_state="OK"),
            ("PARTIAL", "CAPTURE_LIMIT"))


if __name__ == "__main__":
    unittest.main()
