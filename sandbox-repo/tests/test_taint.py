"""Tests for taint tracking: labels, propagation, monotonicity, inheritance."""

from __future__ import annotations

from agent_sandbox.core.taint import TaintLabel, TaintTracker


class TestTaintLabels:
    """Test taint label operations."""

    def test_none_is_not_tainted(self):
        assert TaintLabel.NONE == TaintLabel(0)

    def test_single_label(self):
        label = TaintLabel.CREDENTIAL
        assert label != TaintLabel.NONE

    def test_combine_labels(self):
        label = TaintLabel.CREDENTIAL | TaintLabel.PII
        assert TaintLabel.CREDENTIAL in label
        assert TaintLabel.PII in label
        assert TaintLabel.MEDICAL not in label

    def test_monotonic_addition(self):
        """Taint only increases, never decreases."""
        label = TaintLabel.CREDENTIAL
        label |= TaintLabel.PII
        assert TaintLabel.CREDENTIAL in label
        assert TaintLabel.PII in label
        # Cannot remove taint
        label &= ~TaintLabel.CREDENTIAL  # This is the operation, but we don't do it in practice
        # The taint tracker enforces monotonicity via add_taint


class TestTaintTracker:
    """Test taint tracking across processes and files."""

    def test_register_clean_process(self):
        tracker = TaintTracker()
        proc = tracker.register_process(100)
        assert not proc.is_tainted
        assert proc.label == TaintLabel.NONE

    def test_taint_process(self):
        tracker = TaintTracker()
        tracker.register_process(100)
        tracker.taint_process(100, TaintLabel.CREDENTIAL, ".env")
        assert tracker.is_process_tainted(100)
        proc = tracker.get_process(100)
        assert TaintLabel.CREDENTIAL in proc.label
        assert ".env" in proc.sources

    def test_child_inherits_parent_taint(self):
        """Children inherit parent taint on fork."""
        tracker = TaintTracker()
        tracker.register_process(100)
        tracker.taint_process(100, TaintLabel.CREDENTIAL, ".env")

        child = tracker.on_fork(100, 200)
        assert child.is_tainted
        assert TaintLabel.CREDENTIAL in child.label

    def test_file_taint_propagates_to_process(self):
        """Reading a tainted file taints the process."""
        tracker = TaintTracker()
        tracker.register_process(100)
        tracker.taint_file("/project/.env", TaintLabel.CREDENTIAL)

        tracker.on_open(100, 3, "/project/.env")
        assert tracker.is_process_tainted(100)

    def test_process_taint_propagates_to_file(self):
        """Writing from a tainted process taints the file."""
        tracker = TaintTracker()
        tracker.register_process(100)
        tracker.taint_process(100, TaintLabel.CREDENTIAL, ".env")

        tracker.on_open(100, 4, "/project/output.txt")
        tracker.on_write(100, 4)

        ft = tracker.get_file("/project/output.txt")
        assert ft is not None
        assert ft.is_tainted
        assert TaintLabel.CREDENTIAL in ft.label

    def test_taint_is_monotonic(self):
        """Process taint only increases."""
        tracker = TaintTracker()
        tracker.register_process(100)
        tracker.taint_process(100, TaintLabel.CREDENTIAL, ".env")
        tracker.taint_process(100, TaintLabel.PII, "users.csv")

        proc = tracker.get_process(100)
        assert TaintLabel.CREDENTIAL in proc.label
        assert TaintLabel.PII in proc.label

    def test_transitive_taint(self):
        """Taint propagates through file chains."""
        tracker = TaintTracker()
        # Process A reads .env (tainted)
        tracker.register_process(100)
        tracker.taint_file("/project/.env", TaintLabel.CREDENTIAL)
        tracker.on_open(100, 3, "/project/.env")
        tracker.on_read(100, 3)

        # Process A writes to output.txt
        tracker.on_open(100, 4, "/project/output.txt")
        tracker.on_write(100, 4)

        # Process B reads output.txt → should be tainted
        tracker.register_process(200)
        tracker.on_open(200, 3, "/project/output.txt")
        tracker.on_read(200, 3)

        assert tracker.is_process_tainted(200)

    def test_clean_process_reads_clean_file(self):
        """Clean process reading clean file stays clean."""
        tracker = TaintTracker()
        tracker.register_process(100)
        tracker.on_open(100, 3, "/project/README.md")
        tracker.on_read(100, 3)

        assert not tracker.is_process_tainted(100)
