"""Tests for the E2E experiment runner."""

from __future__ import annotations

from agent_sandbox.experiments.e2e_runner import run_e2e


class TestE2ERunner:
    """Test the E2E experiment runner."""

    def test_run_e2e_without_classifier(self):
        report = run_e2e(with_classifier=False)

        # Environment scan should find sensitive files
        assert report.sensitive_files > 0
        assert report.sensitive_values > 0

        # Almost all attacks should be blocked (1 known gap: per-line dilution)
        assert report.attacks_total > 0
        assert report.attacks_blocked >= report.attacks_total - 1

        # Adversary experiments should produce results
        assert len(report.adversary_results) == 5

        # Benign experiments should have 0 false positives
        benign_clean = report.adversary_results[0]
        assert benign_clean.name == "Benign developer (clean)"
        assert all("FALSE POSITIVE" not in d for d in benign_clean.details)

        benign_tainted = report.adversary_results[4]
        assert benign_tainted.name == "Benign developer (tainted)"
        assert all("FALSE POSITIVE" not in d for d in benign_tainted.details)

        # Summarizer should have recorded turns (7 turns exercise all detectors)
        assert report.total_turns == 7

        # TraceAnalyzer should have fired alerts
        assert report.trace_alerts > 0
        # At least some suspicious turns detected by behavioral analysis
        assert report.suspicious_turns > 0

        # No classifier
        assert report.classifier_assessments == 0

        # Should complete in reasonable time
        assert report.duration_ms < 30000  # 30 seconds

    def test_report_has_timing(self):
        report = run_e2e(with_classifier=False)
        assert report.duration_ms > 0
