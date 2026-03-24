/**
 * "Generate Manifest" command handler.
 *
 * Prompts for scan scope (file vs workspace) and save location,
 * then shells out to `iamspy scan --manifest <path> <target>`.
 */

import * as vscode from 'vscode';
import { execFile } from 'node:child_process';
import * as path from 'node:path';

/** Register the generate manifest command. */
export function registerManifestCommand(
  context: vscode.ExtensionContext,
): void {
  const disposable = vscode.commands.registerCommand(
    'iamspy.generateManifest',
    () => generateManifest(),
  );
  context.subscriptions.push(disposable);
}

async function generateManifest(): Promise<void> {
  const target = await pickScanTarget();
  if (!target) {
    return;
  }

  const savePath = await pickSaveLocation();
  if (!savePath) {
    return;
  }

  await runManifestScan(target, savePath.fsPath);
}

async function pickScanTarget(): Promise<string | undefined> {
  const items: vscode.QuickPickItem[] = [];
  const activeFile = vscode.window.activeTextEditor?.document.uri.fsPath;

  if (activeFile) {
    items.push({ label: 'Current file', description: activeFile });
  }
  if (vscode.workspace.workspaceFolders?.[0]) {
    const wsRoot = vscode.workspace.workspaceFolders[0].uri.fsPath;
    items.push({ label: 'Workspace', description: wsRoot });
  }

  if (items.length === 0) {
    vscode.window.showErrorMessage('No file or workspace open.');
    return undefined;
  }

  const picked = await vscode.window.showQuickPick(items, {
    placeHolder: 'Scan scope for manifest generation',
  });
  return picked?.description;
}

async function pickSaveLocation(): Promise<vscode.Uri | undefined> {
  const wsRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  const defaultUri = wsRoot
    ? vscode.Uri.file(path.join(wsRoot, 'iam-manifest.yaml'))
    : undefined;

  return vscode.window.showSaveDialog({
    defaultUri,
    filters: { 'YAML files': ['yaml', 'yml'] },
    saveLabel: 'Save Manifest',
  });
}

async function runManifestScan(target: string, outputPath: string): Promise<void> {
  const cliPath = vscode.workspace
    .getConfiguration('iamspy')
    .get<string>('cliPath', 'iamspy');

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'Generating IAM manifest...',
      cancellable: false,
    },
    () =>
      new Promise<void>((resolve, reject) => {
        execFile(
          cliPath,
          ['scan', '--manifest', outputPath, target],
          { timeout: 30_000 },
          async (error, _stdout, stderr) => {
            if (error) {
              vscode.window.showErrorMessage(
                `Manifest generation failed: ${stderr || error.message}`,
              );
              reject(error);
              return;
            }

            const doc = await vscode.workspace.openTextDocument(outputPath);
            await vscode.window.showTextDocument(doc);
            resolve();
          },
        );
      }),
  );
}
