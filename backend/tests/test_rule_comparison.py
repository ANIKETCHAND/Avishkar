"""
Unit Tests for Strict Rule Comparison Evaluator
===============================================
Verifies Phase 6 requirements for exact expected-rule matching:
1. Exact empty match: Expected [] Actual [] => exact_match=True, TN
2. Exact single rule: Expected [CD-001] Actual [CD-001] => exact_match=True, TP
3. Extra rule: Expected [CD-002] Actual [CD-002, CD-004] => exact_match=False, unexpected=[CD-004], FP
4. Missing rule: Expected [CD-001] Actual [] => exact_match=False, missing=[CD-001], FN
5. Mixed mismatch: Expected [CD-001, CD-003] Actual [CD-001, CD-004] => exact_match=False, missing=[CD-003], unexpected=[CD-004], MIXED
6. Ordering independence: Expected [CD-003, CD-001] Actual [CD-001, CD-003] => exact_match=True, TP
"""

import pytest
from tests.helpers import compare_expected_actual_rules, RuleComparisonResult


class TestRuleComparisonEvaluator:
    """Verifies mathematical correctness and edge cases of the evaluator comparison logic."""

    def test_exact_empty_match(self):
        """1. Exact empty match: Expected [] Actual [] => exact_match=True, TN."""
        res = compare_expected_actual_rules([], [])
        assert res.exact_match is True
        assert res.missing_rules == []
        assert res.unexpected_rules == []
        assert res.classification == "TN"
        assert res.status_label == "TN (PASS)"

    def test_exact_single_rule(self):
        """2. Exact single rule: Expected [CD-001] Actual [CD-001] => exact_match=True, TP."""
        res = compare_expected_actual_rules(["CD-001"], ["CD-001"])
        assert res.exact_match is True
        assert res.missing_rules == []
        assert res.unexpected_rules == []
        assert res.classification == "TP"
        assert res.status_label == "TP (PASS)"

    def test_extra_rule_mismatch(self):
        """3. Extra rule: Expected [CD-002] Actual [CD-002, CD-004] => exact_match=False, unexpected=[CD-004], FP."""
        res = compare_expected_actual_rules(["CD-002"], ["CD-002", "CD-004"])
        assert res.exact_match is False
        assert res.missing_rules == []
        assert res.unexpected_rules == ["CD-004"]
        assert res.classification == "FP"
        assert res.status_label == "RULE-MISMATCH / FALSE-POSITIVE"

    def test_missing_rule_mismatch(self):
        """4. Missing rule: Expected [CD-001] Actual [] => exact_match=False, missing=[CD-001], FN."""
        res = compare_expected_actual_rules(["CD-001"], [])
        assert res.exact_match is False
        assert res.missing_rules == ["CD-001"]
        assert res.unexpected_rules == []
        assert res.classification == "FN"
        assert res.status_label == "FALSE-NEGATIVE"

    def test_mixed_mismatch(self):
        """5. Mixed mismatch: Expected [CD-001, CD-003] Actual [CD-001, CD-004] => missing=[CD-003], unexpected=[CD-004], MIXED."""
        res = compare_expected_actual_rules(["CD-001", "CD-003"], ["CD-001", "CD-004"])
        assert res.exact_match is False
        assert res.missing_rules == ["CD-003"]
        assert res.unexpected_rules == ["CD-004"]
        assert res.classification == "MIXED"
        assert res.status_label == "MIXED-ERROR"

    def test_ordering_independence(self):
        """6. Ordering independence: Expected [CD-003, CD-001] Actual [CD-001, CD-003] => exact_match=True, TP."""
        res = compare_expected_actual_rules(["CD-003", "CD-001"], ["CD-001", "CD-003"])
        assert res.exact_match is True
        assert res.missing_rules == []
        assert res.unexpected_rules == []
        assert res.classification == "TP"
        assert res.expected_rules == ["CD-001", "CD-003"]
        assert res.actual_rules == ["CD-001", "CD-003"]

    def test_format_details_output(self):
        """Test human-readable detailed failure reporting format."""
        res = compare_expected_actual_rules(["CD-002"], ["CD-002", "CD-004"])
        formatted = res.format_details("cd002_case")
        assert "Case: cd002_case" in formatted
        assert "Expected: ['CD-002']" in formatted
        assert "Actual: ['CD-002', 'CD-004']" in formatted
        assert "Missing: []" in formatted
        assert "Unexpected: ['CD-004']" in formatted
        assert "Status: RULE-MISMATCH / FALSE-POSITIVE" in formatted
