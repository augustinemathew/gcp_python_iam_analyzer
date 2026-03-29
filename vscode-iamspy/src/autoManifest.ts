/**
 * Auto-regenerate iam-manifest.yaml when Python files are saved.
 *
 * Only regenerates if the scan output differs from the existing manifest
 * content. This avoids noisy git diffs and unnecessary disk writes.
 *
 * Debounced: if multiple files are saved rapidly (e.g., format-on-save),
 * only one regeneration runs after the burst settles.
 */

import * as vscode from 'vscode';
import { execFile } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

const DEBOUNCE_MS = 2000;
const MANIFEST_FILENAME = 'iam-manifest.yaml';

let debounceTimer: ReturnType<typeof setTimeout> | undefined;
let lastManifestContent = '';

/** Register the auto-manifest handler on Python file saves. */
export function registerAutoManifest(
  context: vscode.ExtensionContext,
  outputChannel: vscode.OutputChannel,
): void {
  // Load existing manifest content for diffing
  const manifestPath = getManifestPath();
  if (manifestPath && fs.existsSync(manifestPath)) {
    lastManifestContent = fs.readFileSync(manifestPath, 'utf-8');
  }

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (doc.languageId !== 'python') {
        return;
      }
      const config = vscode.workspace.getConfiguration('iamspy');
      if (!config.get<boolean>('autoManifest', true)) {
        return;
      }
      scheduleRegenerate(outputChannel);
    }),
  );
}

function getManifestPath(): string | undefined {
  const wsRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!wsRoot) {
    return undefined;
  }
  return path.join(wsRoot, MANIFEST_FILENAME);
}

function getWorkspaceRoot(): string | undefined {
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

function scheduleRegenerate(outputChannel: vscode.OutputChannel): void {
  if (debounceTimer) {
    clearTimeout(debounceTimer);
  }
  debounceTimer = setTimeout(() => {
    debounceTimer = undefined;
    regenerateManifest(outputChannel);
  }, DEBOUNCE_MS);
}

function regenerateManifest(outputChannel: vscode.OutputChannel): void {
  const wsRoot = getWorkspaceRoot();
  const manifestPath = getManifestPath();
  if (!wsRoot || !manifestPath) {
    return;
  }

  const cliPath = vscode.workspace
    .getConfiguration('iamspy')
    .get<string>('cliPath', 'iamspy');

  const tempPath = manifestPath + '.tmp';
  outputChannel.appendLine('[autoManifest] Regenerating manifest...');

  execFile(
    cliPath,
    ['scan', '--manifest', tempPath, wsRoot],
    { timeout: 30_000, cwd: wsRoot },
    (error, _stdout, stderr) => {
      if (error) {
        outputChannel.appendLine(`[autoManifest] Failed: ${stderr || error.message}`);
        cleanupTemp(tempPath);
        return;
      }
      applyIfChanged(tempPath, manifestPath, outputChannel);
    },
  );
}

/** Compare temp manifest to existing and write only if content changed. */
function applyIfChanged(
  tempPath: string,
  manifestPath: string,
  outputChannel: vscode.OutputChannel,
): void {
  let newContent: string;
  try {
    newContent = fs.readFileSync(tempPath, 'utf-8');
  } catch {
    outputChannel.appendLine('[autoManifest] Failed to read temp manifest');
    cleanupTemp(tempPath);
    return;
  }

  // Strip generated_at timestamp for comparison (changes every run)
  const normalize = (s: string): string =>
    s.replace(/^generated_at:.*$/m, '');

  if (normalize(newContent) === normalize(lastManifestContent)) {
    outputChannel.appendLine('[autoManifest] No changes, skipping write');
    cleanupTemp(tempPath);
    return;
  }

  try {
    fs.renameSync(tempPath, manifestPath);
    lastManifestContent = newContent;
    outputChannel.appendLine(`[autoManifest] Updated ${MANIFEST_FILENAME}`);
  } catch {
    outputChannel.appendLine('[autoManifest] Failed to write manifest');
    cleanupTemp(tempPath);
  }
}

function cleanupTemp(tempPath: string): void {
  try {
    if (fs.existsSync(tempPath)) {
      fs.unlinkSync(tempPath);
    }
  } catch {
    // ignore cleanup failures
  }
}
