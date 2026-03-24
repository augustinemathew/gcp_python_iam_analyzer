/**
 * CodeLens provider that shows IAM permissions above GCP SDK calls.
 *
 * Each finding from the scanner becomes a CodeLens annotation at the
 * corresponding line. Clicking it shows the full permission detail.
 */

import * as vscode from 'vscode';
import type { IamspyFinding, FindingCache } from './types.js';
import { formatTitle, formatTooltip } from './format.js';

export class IamspyCodeLensProvider implements vscode.CodeLensProvider {
  private readonly onDidChange = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this.onDidChange.event;

  constructor(private readonly cache: FindingCache) {}

  /** Notify VS Code that CodeLenses need refreshing. */
  refresh(): void {
    this.onDidChange.fire();
  }

  provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    const findings = this.cache.get(document.uri.fsPath);
    if (!findings) {
      return [];
    }
    return findings
      .filter((f) => f.status === 'mapped')
      .map((f) => this.findingToCodeLens(f, document));
  }

  private findingToCodeLens(
    finding: IamspyFinding,
    document: vscode.TextDocument,
  ): vscode.CodeLens {
    const line = Math.max(0, finding.line - 1); // 1-indexed → 0-indexed
    const range = document.lineAt(line).range;

    return new vscode.CodeLens(range, {
      title: formatTitle(finding),
      tooltip: formatTooltip(finding),
      command: 'iamspy.showPermissionDetail',
      arguments: [finding],
    });
  }
}
