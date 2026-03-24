# GCP IAM Tools — Slide Deck Outline (5-min exec demo)

> **Design notes for Gemini Slides generation:**
> - Google brand colors: Blue (#4285F4), Red (#EA4335), Yellow (#FBBC04), Green (#34A853)
> - Google Sans font throughout
> - Icons: Material Symbols — code (VS Code), edit_note (AntiGravity), smart_toy (IAM Agent), vpn_key (permissions), shield (security), auto_awesome (Gemini), arrow_back (left shift), translate (common vocabulary)
> - Minimal text — presenter speaks, slides support
> - Code blocks in dark theme
> - Google Cloud architecture icons for diagrams
> - White background with may be a gray (very light and faded pattern) 
> - No images other than icons or SVG like things. No pictures really. 

---

## Slide 1: Title

**GCP IAM Tools**
Left-Shift IAM into the Developer Workflow

*Icons: vpn_key + auto_awesome (Gemini sparkle), large, centered*

A suite of tools powered by static analysis and Gemini

---

## Slide 2: The Problem

**Different personas. No common language.**

*Visual: three persona icons in silos with walls between them*

| Persona | Speaks | Sees |
|---------|--------|------|
| **Agent developer** | SDK methods, code, libraries | `client.list_assets()`, `client.query()` |
| **Security admin** | Permissions, risk, compliance | `cloudasset.assets.listResource`, `bigquery.jobs.create` |
| **Policy designer** | Roles, bindings, Terraform | `roles/cloudasset.viewer`, `roles/bigquery.jobUser` |

- Developer doesn't know which permissions their code needs
- Security admin can't read the code to find out
- Policy designer gets a vague request: "give it access to assets and billing"
- Result: **`roles/editor`** — over-permissioned, audit failure

**The personas speak different languages. There's no shared vocabulary.**

---

## Slide 3: The Solution

**A common vocabulary. Left-shifted to the code.**

*Visual: the three silos from Slide 2 now connected by a single artifact in the center — `iam-manifest.yaml`*

The **permission manifest** is the shared vocabulary:
- Developer generates it from code — sees permissions as they write
- Security admin reviews it — structured, auditable, traceable to source
- Policy designer consumes it — generates right-sized policies automatically

**Left-shift:** move IAM awareness to where the problem is created — the code. The manifest flows downstream to every persona who needs it.

---

## Slide 4: GCP IAM Tools — The Suite

**Two surfaces. One engine. Powered by Gemini.**

*Visual: Gemini sparkle in center, two surface cards radiating out*

| Surface | Who | What |
|---------|-----|------|
| **IDE Extension** *(VS Code · AntiGravity)* | Agent developer | See permissions inline as you code. Generate the manifest. |
| **IAM Agent** *(bespoke, Gemini-powered)* | Security admin / Policy designer | Takes code or manifest → generates right-sized policies interactively |

*Foundation bar:*
Static analysis engine — 209 GCP services · 25K+ Gemini-generated permission mappings

---

## Slide 5: 🎬 DEMO — IDE Extension

**[Switch to VS Code / AntiGravity]**

*Case study: GCP Cost Optimization Agent — 3 tools, 3 GCP services (Asset Inventory, Compute, BigQuery Billing)*

**Show:**
1. Open `agent/tools/assets.py` → CodeLens: `🔑 cloudasset.assets.listResource`
2. Open `agent/tools/compute.py` → CodeLens: `🔑 compute.instances.list`
3. Open `agent/tools/billing.py` → CodeLens: `🔑 bigquery.jobs.create, bigquery.tables.getData`
4. Status bar: `🔑 IAM permissions` — click for service-grouped view
5. Command Palette → "Generate Permission Manifest" → `iam-manifest.yaml` opens

*Talking point: "The developer sees permissions as they write code. 3 SDK calls across 3 services, permissions detected automatically, zero docs read. The manifest is the common vocabulary — the developer generated it, the security admin can read it, the policy designer can consume it."*

---

## Slide 6: The Permission Manifest — Common Vocabulary

**One artifact. Every persona understands it.**

*Visual: YAML on dark background, three persona icons pointing at different sections*

```yaml
services:                          # ← Policy designer: "which APIs to enable"
  enable:
  - bigquery.googleapis.com
  - cloudasset.googleapis.com
  - compute.googleapis.com
permissions:
  required:                        # ← Security admin: "what's non-negotiable"
  - bigquery.jobs.create
  - bigquery.tables.getData
  - cloudasset.assets.listResource
  - compute.instances.list
  conditional:                     # ← Security admin: "what's my call"
  - bigquery.tables.create
sources:                           # ← Developer: "where in my code"
  bigquery.jobs.create:
  - {file: agent/tools/billing.py, line: 51, method: query}
  cloudasset.assets.listResource:
  - {file: agent/tools/assets.py, line: 32, method: list_assets}
```

*Each persona reads the same document. Each finds what they need.*

---

## Slide 7: 🎬 DEMO — IAM Agent (Policy Designer)

**[Switch to IAM Agent]**

*Feed the manifest to the bespoke IAM Agent*

**Show:**
1. Agent analyzes: "3 GCP services — Asset Inventory, Compute, BigQuery"
2. Agent detects: "Agent Engine deployment — AGENT_IDENTITY"
3. Agent generates:
   - IAM Allow (4 roles: `cloudasset.viewer`, `compute.viewer`, `bigquery.jobUser`, `bigquery.dataViewer`)
   - Terraform HCL for AGENT_IDENTITY bindings
   - Summary table with justification per permission
4. "Make it tighter" → custom role with only the 4 exact permissions

*Talking point: "The policy designer speaks Terraform. The manifest translates. 3 SDK calls become 4 right-sized roles — or a custom role — in one conversation."*

---

## Slide 8: Close

**GCP IAM Tools**
A common vocabulary for IAM — left-shifted to the code

*Visual: three connected personas with manifest in center*

```
  Developer          Security Admin       Policy Designer
  (writes code)      (reviews manifest)   (generates policy)
       ↘                    ↕                    ↙
              iam-manifest.yaml
              common vocabulary
```

Two surfaces: **IDE Extension** (VS Code · AntiGravity) + **IAM Agent**
Powered by static analysis and Gemini

*Different personas. Same language. Right-sized policies by construction.*

---

## Speaker Notes

**Slide 2 (Problem) — 30 sec:**
"Three personas touch IAM: the developer, the security admin, the policy designer. Today they speak different languages. The developer thinks in SDK methods — `client.query()`. The security admin thinks in permissions — `bigquery.jobs.create`. The policy designer thinks in roles — `roles/bigquery.jobUser`. There's no shared vocabulary, so the handoff breaks down and everybody falls back to `roles/editor`."

**Slide 3 (Solution) — 30 sec:**
"The permission manifest is the common vocabulary. It translates between all three worlds — SDK methods become permissions, permissions become structured YAML, YAML becomes policy. And we left-shift it: the developer generates the manifest from their IDE, at the moment they write the code. The problem is created at the code level, so that's where awareness starts."

**Slide 4 (Suite) — 20 sec:**
"Two surfaces. The IDE extension puts this in the developer's hands — VS Code, AntiGravity. The IAM Agent puts it in the security admin's hands — a bespoke Gemini-powered agent that turns manifests into policies. Same engine underneath: 25,000 Gemini-generated permission mappings across 209 GCP services."

**Slide 5 (IDE Demo) — 90 sec:**
"This is a real agent — a cost optimization agent with 3 tool functions calling Asset Inventory, Compute Engine, and BigQuery for billing data. Watch the CodeLens annotations appear on each file. Permissions detected automatically. One click generates the manifest. The developer now has a vocabulary to hand off to security — not 'I need access to billing' but `bigquery.jobs.create` and `bigquery.tables.getData` traced to `billing.py` line 51."

**Slide 7 (IAM Agent Demo) — 90 sec:**
"The security admin feeds that manifest to the IAM Agent. The agent maps 4 permissions to 4 roles — `cloudasset.viewer`, `compute.viewer`, `bigquery.jobUser`, `bigquery.dataViewer`. Or generates a custom role. Or Terraform. The admin can refine interactively. The manifest was the bridge: developer generated it, agent consumed it, policies came out right-sized."

**Slide 8 (Close) — 20 sec:**
"Three personas, one vocabulary. Left-shifted to where the problem is created. The developer sees permissions in the IDE. The security admin reviews a structured artifact. The policy designer generates right-sized policies. No docs, no guessing, no `roles/editor`."
