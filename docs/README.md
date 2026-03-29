# Documentation

## Start Here

- **[Product Overview](platform/product.md)** — what IAMSpy is, how it works, what's built
- **[Getting Started](getting-started.md)** — CLI tutorial, first scan

## Platform

- **[Technical Design](platform/iamspy-platform.md)** — policy primitives, identity types, plan→execute flow, GCP API tools
- **[Action Items](platform/code-review-action-items.md)** — current refactoring work, prioritized

## Scanner

- **[Architecture](scanner/architecture.md)** — two-phase system (build time + runtime)
- **[Build Pipeline](scanner/build-pipeline.md)** — 7-stage offline pipeline, CLI, workflows
- **[Points-to Analysis](scanner/points-to-analysis.md)** — formal spec for type inference
- **[Accuracy](scanner/accuracy.md)** — benchmark results (3,144 calls, 100% mapped)

## Specs

- **[Permission Manifest](permission-manifest.md)** — v1 and v2 format specification
- **[CI Integration](ci-integration.md)** — GitHub Actions, Cloud Build recipes

## Agents

- **[Overview](agents/README.md)** — architecture, shared tools, three agents
- **[IAM Policy Agent](agents/iam-agent.md)** — batch policy generation, Agent Engine support
- **[IAM IDE Agent](agents/iam-ide-agent.md)** — interactive IDE assistant, single-file scanning
- **[Cost Optimizer Agent](agents/cost-optimizer-agent.md)** — resource inventory, billing, deployment

## Extension

- **[VS Code Extension](extension/vscode-extension.md)** — CodeLens, status bar, architecture

## Experiments

- **[Credential Provenance](experiments/credential-provenance.md)** — tree-sitter vs mypy, eval results

## Archive

Old design docs, completed RFCs, and future proposals in `archive/`.
