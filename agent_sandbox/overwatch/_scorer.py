"""L1 deviation scoring — six signals combined into a composite score."""

from __future__ import annotations

from agent_sandbox.overwatch._baseline import Baseline
from agent_sandbox.overwatch._types import ContentAlert, DeviationSignal, OperationFeatures, TaintContext


# Signal weights for composite score.
_WEIGHTS = {
    "novelty": 0.20,
    "rate": 0.10,
    "sequence": 0.10,
    "burst": 0.05,
    "breadth": 0.10,
    "pattern_match": 0.10,
    "taint_flow": 0.20,
    "content_alert": 0.15,
}


def score_operation(
    features: OperationFeatures,
    baseline: Baseline,
    blocked_patterns: list[OperationFeatures] | None = None,
    taint_context: TaintContext | None = None,
) -> list[DeviationSignal]:
    """Score an operation against the baseline. Returns deviation signals."""
    signals = [
        _score_novelty(features, baseline),
        _score_rate(features, baseline),
        _score_sequence(features, baseline),
        _score_burst(baseline),
        _score_breadth(baseline),
        _score_pattern_match(features, blocked_patterns or []),
        _score_taint_flow(features, taint_context),
        _score_content_alert(taint_context),
    ]
    return signals


def composite_score(signals: list[DeviationSignal]) -> float:
    """Compute weighted composite score from signals."""
    total = 0.0
    for s in signals:
        weight = _WEIGHTS.get(s.name, 0.0)
        total += s.score * weight
    return min(total, 1.0)


def _score_novelty(features: OperationFeatures, baseline: Baseline) -> DeviationSignal:
    """Is this feature value unseen or rare in the baseline?"""
    counters = baseline.query(features)
    unseen_count = 0
    checked = 0

    for key, counter in counters.items():
        if counter is None and key != "op_type":
            # Skip None counters for fields that don't apply to this op type.
            val = getattr(features, _counter_to_feature(key), None)
            if val is not None:
                unseen_count += 1
                checked += 1
        elif counter is not None:
            checked += 1
            if counter.count <= 1:
                unseen_count += 0.5  # Seen once = half novel.

    if checked == 0:
        return DeviationSignal("novelty", 0.0, "no applicable features")

    score = unseen_count / checked
    if not baseline.is_warm:
        score *= 0.5  # Halve during warmup.

    return DeviationSignal(
        "novelty",
        min(score, 1.0),
        f"{unseen_count}/{checked} features unseen",
    )


def _score_rate(features: OperationFeatures, baseline: Baseline) -> DeviationSignal:
    """Is the per-feature rate abnormally high compared to EMA?"""
    counters = baseline.query(features)
    max_ratio = 0.0
    detail = "normal rate"

    for key, counter in counters.items():
        if counter is None or counter.ema_rate <= 0:
            continue
        if counter.count < 3:
            continue  # Not enough data.
        # Compare last interval against EMA.
        ratio = counter.ema_rate / max(counter.ema_rate, 0.001)
        if counter.count > 5 and counter.ema_rate > 0:
            # Simple check: if this feature fires more than 3x its average.
            recent_rate = counter.count / max(baseline.total_ops, 1)
            expected_rate = counter.ema_rate
            if expected_rate > 0:
                ratio = recent_rate / expected_rate
                if ratio > max_ratio:
                    max_ratio = ratio
                    detail = f"{key} rate {ratio:.1f}x above EMA"

    score = min(1.0, max(0.0, (max_ratio - 3.0) / 7.0)) if max_ratio > 3.0 else 0.0
    return DeviationSignal("rate", score, detail)


def _score_sequence(features: OperationFeatures, baseline: Baseline) -> DeviationSignal:
    """Is the op-type bigram unseen or rare?"""
    if baseline._last_op_type is None:
        return DeviationSignal("sequence", 0.0, "first operation")

    key = (baseline._last_op_type, features.op_type)
    count = baseline.bigrams.get(key, 0)
    total_bigrams = sum(baseline.bigrams.values()) if baseline.bigrams else 1

    if count == 0:
        score = 0.5 if baseline.is_warm else 0.25
        detail = f"unseen bigram: {key[0].name}->{key[1].name}"
    else:
        frequency = count / total_bigrams
        score = max(0.0, 0.3 - frequency)  # Rare bigrams score higher.
        detail = f"bigram {key[0].name}->{key[1].name} freq={frequency:.3f}"

    return DeviationSignal("sequence", score, detail)


def _score_burst(baseline: Baseline) -> DeviationSignal:
    """Are many ops happening in a short window?"""
    burst = baseline.get_burst_count(window_ms=100.0)
    if burst >= 5:
        score = min(1.0, (burst - 4) / 10.0)
        return DeviationSignal("burst", score, f"{burst} ops in 100ms")
    return DeviationSignal("burst", 0.0, "no burst")


def _score_breadth(baseline: Baseline) -> DeviationSignal:
    """Is the agent accessing many distinct resources?"""
    breadth = baseline.get_breadth()
    if breadth >= 10:
        score = min(1.0, (breadth - 9) / 20.0)
        return DeviationSignal("breadth", score, f"{breadth} unique resources in 60s")
    return DeviationSignal("breadth", 0.0, f"{breadth} unique resources")


def _score_pattern_match(
    features: OperationFeatures,
    blocked_patterns: list[OperationFeatures],
) -> DeviationSignal:
    """Does this operation match a previously blocked pattern?"""
    for pattern in blocked_patterns:
        if _features_match(features, pattern):
            return DeviationSignal("pattern_match", 1.0, "matches blocked pattern")
    return DeviationSignal("pattern_match", 0.0, "no pattern match")


def _features_match(a: OperationFeatures, b: OperationFeatures) -> bool:
    """Check if two feature sets match on their non-None fields."""
    if a.op_type != b.op_type:
        return False
    matches = 0
    checks = 0
    for attr in ("host_domain", "file_extension", "directory_prefix", "mcp_tool"):
        va = getattr(a, attr)
        vb = getattr(b, attr)
        if va is not None and vb is not None:
            checks += 1
            if va == vb:
                matches += 1
    return checks > 0 and matches == checks


def _score_taint_flow(
    features: OperationFeatures, taint_context: TaintContext | None
) -> DeviationSignal:
    """Is a tainted process making network or MCP calls?"""
    if taint_context is None or not taint_context.pid_tainted:
        return DeviationSignal("taint_flow", 0.0, "not tainted")

    # Tainted process doing network/HTTP/MCP = high score.
    from agent_sandbox.overwatch._types import OpType

    if features.op_type in (OpType.NETWORK, OpType.HTTP, OpType.MCP):
        sources = ", ".join(taint_context.taint_sources[:3])
        return DeviationSignal(
            "taint_flow",
            0.8,
            f"tainted PID sending to {features.host_domain or features.mcp_tool} "
            f"(sources: {sources})",
        )
    return DeviationSignal("taint_flow", 0.0, "tainted but not network/mcp")


def _score_content_alert(taint_context: TaintContext | None) -> DeviationSignal:
    """Does the request body match a known secret via LSH?"""
    if taint_context is None or taint_context.content_alert is None:
        return DeviationSignal("content_alert", 0.0, "no content alert")

    alert = taint_context.content_alert
    score = min(1.0, alert.lsh_score * 2.0) if alert.lsh_score > 0 else 0.7
    return DeviationSignal(
        "content_alert",
        score,
        f"body matches secret: {alert.matched_pattern[:80]}",
    )


def _counter_to_feature(key: str) -> str:
    """Map counter dict key to OperationFeatures attribute name."""
    return {
        "host": "host_domain",
        "file_ext": "file_extension",
        "dir_prefix": "directory_prefix",
        "mcp_tool": "mcp_tool",
        "http_method": "http_method",
        "op_type": "op_type",
    }.get(key, key)
