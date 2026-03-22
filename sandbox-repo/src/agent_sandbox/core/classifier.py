"""Data classification by path and content.

Classifies data into taint labels based on file paths and content patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .taint import TaintLabel


@dataclass(frozen=True)
class Classification:
    """Result of classifying data."""

    label: TaintLabel
    reason: str
    confidence: float  # 0.0 to 1.0


# Path-based classification rules
_PATH_RULES: list[tuple[re.Pattern[str], TaintLabel, str]] = [
    (re.compile(r"\.env(?:\..+)?$"), TaintLabel.CREDENTIAL, "environment file"),
    (re.compile(r"credentials?\.(?:json|yaml|yml|xml)$", re.IGNORECASE), TaintLabel.CREDENTIAL, "credentials file"),
    (re.compile(r"service[_-]?account\.json$", re.IGNORECASE), TaintLabel.CREDENTIAL, "service account"),
    (re.compile(r"\.pem$|\.key$|\.p12$|\.pfx$"), TaintLabel.CREDENTIAL, "key file"),
    (re.compile(r"\.pgpass$|\.my\.cnf$|\.netrc$"), TaintLabel.CREDENTIAL, "auth config"),
    (re.compile(r"id_(?:rsa|ed25519|ecdsa|dsa)$"), TaintLabel.CREDENTIAL, "SSH private key"),
    (re.compile(r"medical|health|patient|clinic", re.IGNORECASE), TaintLabel.MEDICAL, "medical directory"),
    (re.compile(r"financial|tax|bank|accounting", re.IGNORECASE), TaintLabel.FINANCIAL, "financial directory"),
    (re.compile(r"hr|personnel|employee", re.IGNORECASE), TaintLabel.PII, "HR directory"),
]

# Content-based classification rules
_CONTENT_RULES: list[tuple[re.Pattern[str], TaintLabel, str]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), TaintLabel.CREDENTIAL, "AWS access key"),
    (re.compile(r"sk-ant-api\d{2}-"), TaintLabel.CREDENTIAL, "Anthropic API key"),
    (re.compile(r"sk-[A-Za-z0-9]{48}"), TaintLabel.CREDENTIAL, "OpenAI API key"),
    (re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), TaintLabel.CREDENTIAL, "private key"),
    (re.compile(r"(?:postgres|mysql|mongodb)://\S+"), TaintLabel.CREDENTIAL, "database URL"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), TaintLabel.CREDENTIAL, "GitHub token"),
    (re.compile(r"hvs\.[A-Za-z0-9_-]{24,}"), TaintLabel.CREDENTIAL, "Vault token"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), TaintLabel.PII, "SSN"),
    (re.compile(r"\bdiagnosis\b|\bprescription\b|\bmedical record\b", re.IGNORECASE), TaintLabel.MEDICAL, "medical content"),
    (re.compile(r"\bForm 1040\b|\bW-2\b|\btax return\b", re.IGNORECASE), TaintLabel.FINANCIAL, "financial content"),
]


def classify_by_path(path: str) -> Classification | None:
    """Classify data sensitivity based on file path."""
    for pattern, label, reason in _PATH_RULES:
        if pattern.search(path):
            return Classification(label=label, reason=reason, confidence=0.8)
    return None


def classify_by_content(content: str) -> list[Classification]:
    """Classify data sensitivity based on content patterns."""
    results: list[Classification] = []
    seen_labels: set[TaintLabel] = set()
    for pattern, label, reason in _CONTENT_RULES:
        if label not in seen_labels and pattern.search(content):
            results.append(Classification(label=label, reason=reason, confidence=0.9))
            seen_labels.add(label)
    return results


def classify(path: str, content: str) -> TaintLabel:
    """Classify data and return the combined taint label."""
    label = TaintLabel.NONE

    path_class = classify_by_path(path)
    if path_class:
        label |= path_class.label

    for content_class in classify_by_content(content):
        label |= content_class.label

    return label
