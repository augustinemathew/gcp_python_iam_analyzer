# GCP SDK IAM Permission Detector — Executive Summary

## What it does

Statically analyzes Python source code to detect GCP SDK method calls and resolves each call to the IAM permissions it requires at runtime. Developers see exactly which permissions their code needs before deployment.

## Scale

| What we analyze | Count |
|---|---|
| GCP SDK packages installed | 130 |
| SDK Python source files scanned | 10,066 |
| SDK lines of code analyzed | 8.8 million |
| REST API endpoints extracted | 52,841 |
| SDK methods mapped to permissions | ~13,500 |
| IAM roles in catalog | 2,073 |
| Valid IAM permissions tracked | 12,879 |
| GCP services covered | 122 |

## How the build pipeline works

```
SDK Source Code (8.8M LOC)
  ↓ tree-sitter + regex parsing
REST URIs + Docstrings (method_context.json)
  ↓ Claude Sonnet (Config D+ prompts)
IAM Permission Mappings (iam_permissions.json)
  ↓ validation against IAM role catalog
Production output: ~13,500 method → permission mappings
```

## LLM comparison: Claude vs Gemini

### Why Claude was chosen as primary

| Metric | Gemini Flash | Claude Sonnet |
|---|---|---|
| **Reliability** | 504 timeouts, 53 errors in one run | **0 errors in 370+ batches** |
| **JSON output** | Unreliable — malformed JSON, markdown fences | **100% valid JSON** |
| **Hallucination rate** | ~7% (permissions not in IAM catalog) | **<2%** |
| **Mapping accuracy** | Good when it works | **Consistently correct** |
| **Cost** | Cheaper per token | Higher per token but fewer retries |

**Key finding:** Claude's reliability advantage is decisive for a batch pipeline. One Gemini run of 251 batches had 53 errors (21% failure rate) requiring re-runs. Claude ran 370+ batches with zero errors. The cost of retries, error handling, and manual review of Gemini failures exceeds the per-token premium for Claude.

### Where Gemini excels

| Capability | Gemini advantage |
|---|---|
| **Registry metadata correction** | Gemini corrects `iam_prefix` and `display_name` for 130 services in one pass. Works well for this structured, low-ambiguity task. |
| **Embedding generation** | Gemini's embedding API (`gemini-embedding-001`) produced the initial 519MB permission embedding index. Higher quality than local models for this use case. |
| **Large context window** | Gemini 1.5 Pro's 1M token context could process entire service documentation in one pass — useful for future enhancements. |
| **GCP integration** | Native integration with GCP services, Vertex AI deployment, IAM-based auth. |

### Recommendation

**Use Claude for structured output tasks** (permission mapping, JSON generation) where reliability matters more than cost. **Use Gemini for GCP-specific tasks** (metadata correction, embedding generation) where its GCP domain knowledge and integration provide value. The pipeline currently uses both.

## The Config D+ innovation

The key technical insight: **REST URIs extracted from SDK source code tell the LLM exactly what API each method calls**, eliminating the need for large permission lists in the prompt.

```
Traditional (v1):                        Config D+ (v2):
  Method: encrypt(args=0-2)                Method: encrypt(args=0-2)
  + 80 KMS permissions (1,500 tokens)        REST: POST /v1/.../cryptoKeys:encrypt
                                             + 80 KMS permissions as soft hint
  → 1,527 tokens                           → 1,006 tokens, higher accuracy
```

**v2 finds 49 more permissions** than v1 on the same methods while producing **87 more valid** (non-hallucinated) permissions. The REST URI provides structural knowledge that permission lists alone cannot.

## Project stats

| Component | Lines of code |
|---|---|
| Runtime scanner (`src/`) | 1,468 |
| Build pipeline (`build_pipeline/`) | 2,528 |
| Tests | 3,619 |
| **Total** | **7,615** |
| Test count | 281 passing |

## Cost

Full pipeline run (all 129 services): **~$6 in LLM API costs**, ~50 minutes.
