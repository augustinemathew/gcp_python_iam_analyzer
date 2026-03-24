/**
 * Status bar item showing aggregate IAM permission count for the active file.
 *
 * Clicking it opens a quick pick with all permissions grouped by service.
 */

import * as vscode from 'vscode';
import type { FindingCache } from './types.js';
import { countPermissions, groupByService } from './format.js';

export function createStatusBarItem(): vscode.StatusBarItem {
  const item = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    100,
  );
  item.command = 'iamspy.showPermissionSummary';
  return item;
}

/** Update the status bar text based on the active editor's findings. */
export function updateStatusBar(
  item: vscode.StatusBarItem,
  cache: FindingCache,
  editor: vscode.TextEditor | undefined,
): void {
  if (!editor || editor.document.languageId !== 'python') {
    item.hide();
    return;
  }

  const findings = cache.get(editor.document.uri.fsPath);
  if (!findings || findings.length === 0) {
    item.hide();
    return;
  }

  const { permCount, condCount } = countPermissions(findings);
  if (permCount === 0) {
    item.hide();
    return;
  }

  const condSuffix = condCount > 0 ? ` (+${condCount} conditional)` : '';
  item.text = `$(key) ${permCount} IAM permissions${condSuffix}`;
  item.tooltip = 'Click to view IAM permission summary';
  item.show();
}

/** Build grouped quick pick items for the permission summary. */
export function buildSummaryItems(
  cache: FindingCache,
  filePath: string,
): vscode.QuickPickItem[] {
  const findings = cache.get(filePath);
  if (!findings) {
    return [];
  }

  const byService = groupByService(findings);
  const items: vscode.QuickPickItem[] = [];

  for (const [service, perms] of byService) {
    items.push({ label: service, kind: vscode.QuickPickItemKind.Separator });
    for (const p of perms) {
      items.push({ label: p });
    }
  }

  return items;
}
