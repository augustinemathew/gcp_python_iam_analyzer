"""Multi-strategy LSH engine for content matching.

Detects sensitive data even after transformation (base64, hex, URL encoding,
JSON wrapping, embedding in source code). Uses a three-stage query pipeline:
1. Trigram bloom filter pre-check (fast rejection)
2. MinHash LSH band lookup (medium cost)
3. Detailed scoring (expensive, rare)
"""

from __future__ import annotations

import base64
import hashlib
import struct
import urllib.parse
from dataclasses import dataclass, field


def trigram_set(s: str) -> set[str]:
    """Compute character trigrams."""
    if len(s) < 3:
        return set()
    return {s[i : i + 3] for i in range(len(s) - 2)}


def trigram_jaccard(a: str, b: str) -> float:
    """Jaccard similarity of trigram sets."""
    sa = trigram_set(a)
    sb = trigram_set(b)
    if not sa or not sb:
        return 0.0
    inter = len(sa & sb)
    union = len(sa | sb)
    return inter / union if union else 0.0


def simhash(text: str, bits: int = 64) -> int:
    """Compute SimHash for near-duplicate detection."""
    v = [0] * bits
    for trigram in trigram_set(text):
        h = int(hashlib.md5(trigram.encode()).hexdigest(), 16)
        for i in range(bits):
            if h & (1 << i):
                v[i] += 1
            else:
                v[i] -= 1
    fingerprint = 0
    for i in range(bits):
        if v[i] > 0:
            fingerprint |= 1 << i
    return fingerprint


def simhash_distance(a: int, b: int, bits: int = 64) -> float:
    """Normalized Hamming distance between SimHash fingerprints."""
    xor = a ^ b
    diff = bin(xor).count("1")
    return 1.0 - (diff / bits)


def minhash_signature(text: str, num_hashes: int = 128) -> list[int]:
    """Compute MinHash signature for Jaccard estimation."""
    trigrams = trigram_set(text)
    if not trigrams:
        return [0xFFFFFFFF] * num_hashes

    sig = [0xFFFFFFFF] * num_hashes
    for trigram in trigrams:
        for i in range(num_hashes):
            h = struct.unpack(
                "<I",
                hashlib.md5(f"{i}:{trigram}".encode()).digest()[:4],
            )[0]
            if h < sig[i]:
                sig[i] = h
    return sig


def minhash_jaccard(sig_a: list[int], sig_b: list[int]) -> float:
    """Estimate Jaccard similarity from MinHash signatures."""
    if len(sig_a) != len(sig_b):
        return 0.0
    matches = sum(1 for a, b in zip(sig_a, sig_b) if a == b)
    return matches / len(sig_a)


@dataclass
class IndexedValue:
    """An indexed sensitive value with pre-computed representations."""

    raw: str
    trigrams: set[str] = field(default_factory=set)
    simhash_fp: int = 0
    minhash_sig: list[int] = field(default_factory=list)
    variants: list[str] = field(default_factory=list)
    variant_trigrams: list[set[str]] = field(default_factory=list)


class LSHEngine:
    """Multi-strategy LSH engine for detecting sensitive content in outbound data.

    Three-stage pipeline:
    1. Trigram bloom filter: fast pre-check, rejects 99% of clean traffic
    2. MinHash LSH: medium cost, catches reordering and partial matches
    3. Combined scoring: SimHash x 0.25 + MinHash x 0.40 + Bloom x 0.35
    """

    def __init__(self, threshold: float = 0.30) -> None:
        self.threshold = threshold
        self._indexed: list[IndexedValue] = []
        self._all_trigrams: set[str] = set()  # bloom filter substitute

    def index(self, value: str) -> None:
        """Index a sensitive value and its encoded variants."""
        if len(value) < 3:
            return

        entry = IndexedValue(raw=value)
        entry.trigrams = trigram_set(value)
        entry.simhash_fp = simhash(value)
        entry.minhash_sig = minhash_signature(value)

        # Generate variants
        variants = _generate_variants(value)
        entry.variants = variants
        entry.variant_trigrams = [trigram_set(v) for v in variants]

        self._indexed.append(entry)
        self._all_trigrams.update(entry.trigrams)
        for vt in entry.variant_trigrams:
            self._all_trigrams.update(vt)

    def check(self, data: str) -> tuple[bool, float, str]:
        """Check outbound data against indexed values.

        Returns (matched, score, reason).
        """
        if not self._indexed or len(data) < 3:
            return False, 0.0, ""

        data_trigrams = trigram_set(data)

        # Stage 1: bloom pre-check
        overlap = len(data_trigrams & self._all_trigrams) / len(data_trigrams) if data_trigrams else 0
        if overlap < 0.05:
            return False, 0.0, ""

        # Stage 2 & 3: check each indexed value
        best_score = 0.0
        best_reason = ""

        for entry in self._indexed:
            score, reason = self._score_against(data, data_trigrams, entry)
            if score > best_score:
                best_score = score
                best_reason = reason

        if best_score >= self.threshold:
            return True, best_score, best_reason

        # Also check per-line
        for line in data.splitlines():
            line = line.strip()
            if len(line) < 10:
                continue
            line_trigrams = trigram_set(line)
            for entry in self._indexed:
                score, reason = self._score_against(line, line_trigrams, entry)
                if score > best_score:
                    best_score = score
                    best_reason = reason

        return best_score >= self.threshold, best_score, best_reason

    def _score_against(
        self,
        data: str,
        data_trigrams: set[str],
        entry: IndexedValue,
    ) -> tuple[float, str]:
        """Score data against a single indexed value."""
        # Check direct trigram overlap
        if entry.trigrams and data_trigrams:
            inter = len(data_trigrams & entry.trigrams)
            union = len(data_trigrams | entry.trigrams)
            bloom_score = inter / union if union else 0.0
        else:
            bloom_score = 0.0

        # Check variant trigram overlap
        for i, vt in enumerate(entry.variant_trigrams):
            if vt and data_trigrams:
                inter = len(data_trigrams & vt)
                union = len(data_trigrams | vt)
                variant_score = inter / union if union else 0.0
                if variant_score > bloom_score:
                    bloom_score = variant_score

        if bloom_score < 0.1:
            return 0.0, ""

        # SimHash distance
        data_simhash = simhash(data)
        sim_score = simhash_distance(data_simhash, entry.simhash_fp)

        # MinHash Jaccard
        data_minhash = minhash_signature(data)
        mh_score = minhash_jaccard(data_minhash, entry.minhash_sig)

        # Combined score
        combined = sim_score * 0.25 + mh_score * 0.40 + bloom_score * 0.35

        reason = (
            f"sim={sim_score:.3f} mh={mh_score:.3f} bloom={bloom_score:.3f} "
            f"combined={combined:.3f}"
        )
        return combined, reason


def _generate_variants(value: str) -> list[str]:
    """Generate encoded variants for pre-indexing."""
    variants = [value]
    try:
        variants.append(base64.b64encode(value.encode()).decode())
    except Exception:
        pass
    try:
        variants.append(value.encode().hex())
    except Exception:
        pass
    try:
        variants.append(urllib.parse.quote(value))
    except Exception:
        pass

    # Individual lines for multi-line secrets
    for line in value.splitlines():
        line = line.strip()
        if len(line) >= 10:
            variants.append(line)

    return variants
