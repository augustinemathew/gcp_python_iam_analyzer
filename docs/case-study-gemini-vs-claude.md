# Case Study: Gemini vs Claude for Structured Output Pipelines

## Why this project is an ideal comparison

This project — mapping 12,000+ GCP SDK methods to IAM permissions — is a uniquely demanding LLM workload that stress-tests both models across multiple dimensions:

1. **Structured output at scale**: 370+ batches of JSON, each requiring exact schema compliance. One malformed response breaks the pipeline.
2. **Domain-specific knowledge**: GCP IAM permissions follow non-obvious naming conventions (`encrypt` → `useToEncrypt`, not `cryptoKeys.encrypt`). The LLM must know or infer these.
3. **Precision over creativity**: A hallucinated permission string is worse than a missing one. The output is consumed by automated tools, not humans.
4. **Long-running batch pipeline**: Hours of sequential API calls. Failures require re-runs that cost time and money.
5. **Measurable ground truth**: We can validate every output against the official IAM role catalog (12,879 permissions from `gcloud iam roles list`).

Most LLM benchmarks test single-turn reasoning. This project tests what matters for production systems: **reliability, consistency, and structured output fidelity over hundreds of sequential calls.**

## The experiment

### Phase 1: Gemini as primary (v1 pipeline)

The initial pipeline used Gemini Flash for all 62 services (~4,000 methods):

**Prompt:** Method name + arg count + filtered permission list (~170 permissions). No REST URI context.

**Results:**

| Metric | Gemini Flash |
|---|---|
| Batches attempted | 251 |
| Errors (timeouts, bad JSON) | **53 (21%)** |
| Hallucination rate | **~7%** (permissions not in IAM catalog) |
| Time per batch | 8-15s (variable) |
| Output validity | 93% (no-context prompt), 100% (with perm list) |

**What went wrong:**

- **504 Gateway Timeouts**: Gemini Flash timed out on batches with large permission lists (>500 permissions). The Compute service (1,029 permissions) was particularly problematic — 19s average, frequent timeouts.
- **Malformed JSON**: Some responses included markdown fences (` ```json ... ``` `) despite requesting raw JSON. Others had trailing commas or truncated output.
- **Inconsistent `response_mime_type`**: Setting `response_mime_type="application/json"` helped but didn't eliminate formatting issues.
- **Rate limiting**: Sequential requests with 0.5s delay still hit rate limits during large runs, causing cascading failures.

### Phase 2: Claude fills gaps (v1 pipeline)

After Gemini's 53 failures, the remaining unmapped methods were sent to Claude Sonnet:

| Metric | Claude Sonnet |
|---|---|
| Batches | 251 |
| Errors | **0 (0%)** |
| Hallucination rate | **<2%** |
| Time per batch | 7-9s (consistent) |
| Output validity | **100%** |

Claude processed the exact same methods Gemini failed on — and succeeded on every single one.

### Phase 3: Claude as primary (v2 pipeline)

For the v2 pipeline, Claude Sonnet was used for all 119 services (~12,000 methods) with Config D+ prompts (REST URIs + full permission list as soft hint):

| Metric | Claude Sonnet (v2) |
|---|---|
| Batches | 370+ |
| Errors | **0** |
| Hallucination rate | **<2%** (validated against 12,879 ground truth permissions) |
| More permissions found vs v1 | **+49** on matched methods |
| More valid permissions vs v1 | **+87** |
| Ground truth spot checks | **10/10** |

## Head-to-head comparison

### Reliability

| Dimension | Gemini Flash | Claude Sonnet |
|---|---|---|
| Error rate | 21% (53/251) | **0% (0/370+)** |
| JSON compliance | ~95% | **100%** |
| Timeout rate | ~8% on large prompts | **0%** |
| Retry logic needed | Yes (exponential backoff, fallback to Pro) | **No** |
| Output consistency | Variable (same prompt → different format) | **Deterministic** |

**Cost of unreliability:** The 53 Gemini failures required a second pass with Claude, doubling the API calls for 21% of the workload. Error handling code, retry logic, and manual review added ~200 lines of code to the v1 pipeline. v2 (Claude-only) has no retry logic — it's never needed.

### Accuracy

| Dimension | Gemini (v1) | Claude (v2) |
|---|---|---|
| Hallucinated permissions | ~7% of output | **<2%** |
| Permissions found (matched methods) | 964 | **1,013 (+49)** |
| Valid permissions | 835 | **922 (+87)** |
| Empty mappings (method unmapped) | 58 | **5** |
| Conditional dependencies found | Good (rich) | Good (slightly fewer) |

### Structured output

This is where the gap is widest. The pipeline requires:
- Valid JSON (no markdown fences, no trailing commas)
- Exact key format: `ClassName.method_name`
- Consistent schema: `{"permissions": [...], "conditional": [...], "local_helper": bool, "notes": "..."}`

**Gemini** required:
- `response_mime_type="application/json"` (didn't always work)
- Post-processing to strip ` ```json ``` ` fences
- Schema validation with retry
- Temperature 0.1 (higher temperatures produced more format variance)

**Claude** required:
- Prompt ending with "Return ONLY valid JSON."
- Occasional fence stripping (rare)
- No retries, no schema validation needed

### Cost

| Model | Batches | Est. cost | Errors | Effective cost (incl. retries) |
|---|---|---|---|---|
| Gemini Flash (v1) | 251 | ~$0.50 | 53 | ~$0.70 (+ Claude gap-fill) |
| Claude Sonnet (v1 gaps) | 251 | ~$1.50 | 0 | $1.50 |
| **Claude Sonnet (v2 full)** | **370** | **~$5.56** | **0** | **$5.56** |

Gemini is cheaper per token, but the total effective cost difference is small (~$4) and overwhelmed by engineering time to handle failures.

## What Google / Gemini should fix

This project uncovered specific, actionable issues that would make Gemini competitive for structured output pipelines:

### 1. JSON mode must be reliable

`response_mime_type="application/json"` should guarantee valid JSON. Today it doesn't — responses still include markdown fences, trailing commas, and truncated output. This is the #1 blocker.

**What "reliable" means:** 0 malformed responses out of 300+ calls. Not 95%. Not 99%. Zero. Batch pipelines don't have a human in the loop to fix formatting errors.

### 2. Timeouts on large prompts need solving

Gemini Flash timed out on prompts with >500 permission strings (~2,000 tokens of context). These aren't large by LLM standards — they're well within the context window. The timeout appears to be a serving infrastructure issue, not a model limitation.

**Impact:** Compute Engine (1,029 permissions) was nearly unmappable with Gemini. We had to filter to ~170 permissions per batch, which then missed secondary resource permissions. Claude handled the full 1,029-permission prompt in 8.4s with no timeout.

### 3. Rate limiting needs better backpressure

Sequential requests with 0.5s delay still triggered rate limits during sustained runs. The error response didn't include a `Retry-After` header, making graceful backoff difficult. Claude's API handles sustained throughput without rate-limiting 370+ sequential calls.

### 4. Output format consistency across calls

The same prompt sent to Gemini twice can produce structurally different output — different key ordering, different quoting, sometimes different schema. This makes output parsing fragile. Claude produces byte-identical structure across calls with the same prompt.

### 5. Domain knowledge is a strength — leverage it

Gemini's knowledge of GCP IAM is excellent — it corrected `iam_prefix` for 130 services and knows non-obvious permission naming conventions. This is a genuine advantage from training on Google documentation. But it's wasted when the response format is unreliable.

**Recommendation:** Combine Gemini's domain knowledge with structured output guarantees. A fine-tuned Gemini model for IAM permission mapping, with guaranteed JSON output, could outperform both current approaches.

### 6. Consider a "batch mode" API

This pipeline makes 300-400 sequential calls with the same prompt template, varying only the method list. A batch API that accepts an array of inputs and returns an array of outputs (like OpenAI's batch API) would:
- Eliminate rate limiting concerns
- Reduce per-request overhead
- Enable server-side optimizations (KV cache reuse across similar prompts)
- Provide a natural checkpoint/resume mechanism

## What Gemini does well in this project

Gemini is not universally worse. It excels in specific tasks:

### Registry metadata correction (s02)

Fixing `iam_prefix` and `display_name` for 130 services requires GCP-specific knowledge that Gemini has from its training data. This is a low-ambiguity, single-pass task where domain knowledge matters and structured output complexity is low (simple key-value corrections).

### Potential for specialization

Gemini's fine-tuning via Vertex AI could train a specialized permission mapping model on the 620+ logged prompt/response pairs from this project. A fine-tuned model could potentially achieve:
- Better accuracy than general-purpose Claude (domain-specific training)
- Lower per-call cost (smaller specialized model)
- Faster inference (optimized for this specific schema)

This is an unexplored opportunity that plays to Google's strengths in model customization and GCP integration.

### Large context for full-document approaches

Gemini 1.5 Pro's 1M token context could process entire REST API documentation in a single pass, rather than the per-method extraction approach used here. A future iteration could feed Gemini the full API spec and ask for all permissions at once — an approach that would favor large context over many small calls.

## Lessons for model selection in production pipelines

1. **For batch pipelines: reliability > per-token cost.** One failure in a 300-batch pipeline costs more in engineering time than the entire API bill.

2. **Structured output is a hard requirement, not a nice-to-have.** If your pipeline parses JSON, the model must produce valid JSON 100% of the time. Test with 300+ calls, not 10.

3. **Use each model for what it's best at.** Gemini for GCP domain knowledge (metadata correction), Claude for structured output (permission mapping). Don't force one model to do everything.

4. **Prompt engineering can close the accuracy gap, but not the reliability gap.** Both models achieve similar accuracy with the right prompt. But no prompt engineering fixes timeouts and JSON formatting issues.

5. **Log everything.** All 620+ LLM calls are logged to `data/llm_logs/*.jsonl`. This enabled the retrospective quality analysis, the adjudication study, and the data for this case study. Without logs, we'd be guessing.

## Data sources

All claims in this document are based on empirical data from this project:

| Source | Location | Description |
|---|---|---|
| v1 Gemini run logs | `data/llm_logs/` | 251 batches, 53 errors |
| v1 Claude gap-fill logs | `data/llm_logs/` | 251 batches, 0 errors |
| v2 Claude full run logs | `data/llm_logs/` | 370+ batches, 0 errors |
| v1 vs v2 quality analysis | `docs/v2-quality-analysis.md` | 158 cases adjudicated |
| Prompt strategy experiments | `docs/build-pipeline-v2.md` §4 | Configs A-D tested on KMS + Compute |
| IAM catalog ground truth | `data/iam_roles.json` | 2,073 roles, 12,879 permissions |
