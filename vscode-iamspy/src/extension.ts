/**
 * Extension entry point. Wires up scanner, CodeLens, status bar, and commands.
 */

import * as vscode from 'vscode';
import type { FindingCache, IamspyFinding } from './types.js';
import { scanPath } from './scanner.js';
import { IamspyCodeLensProvider } from './codelens.js';
import { createStatusBarItem, updateStatusBar, buildSummaryItems } from './statusBar.js';
import { registerManifestCommand } from './manifest.js';
import { showDetailPanel } from './detailPanel.js';

/** Shared state across all providers and commands. */
interface ExtensionState {
  cache: FindingCache;
  codeLensProvider: IamspyCodeLensProvider;
  statusBarItem: vscode.StatusBarItem;
  outputChannel: vscode.OutputChannel;
}

const cache: FindingCache = new Map();

export function activate(context: vscode.ExtensionContext): void {
  const state: ExtensionState = {
    cache,
    codeLensProvider: new IamspyCodeLensProvider(cache),
    statusBarItem: createStatusBarItem(),
    outputChannel: vscode.window.createOutputChannel('IAMSpy'),
  };

  registerProviders(context, state);
  registerEventHandlers(context, state);
  registerCommands(context, state);
  registerManifestCommand(context);
  scanActiveEditor(state);

  state.outputChannel.appendLine('IAMSpy activated.');
}

export function deactivate(): void {
  cache.clear();
}

function registerProviders(
  context: vscode.ExtensionContext,
  state: ExtensionState,
): void {
  context.subscriptions.push(
    vscode.languages.registerCodeLensProvider(
      { language: 'python' },
      state.codeLensProvider,
    ),
    state.statusBarItem,
  );
}

function registerEventHandlers(
  context: vscode.ExtensionContext,
  state: ExtensionState,
): void {
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (doc.languageId === 'python') {
        triggerScan(doc.uri.fsPath, state);
      }
    }),
    vscode.workspace.onDidOpenTextDocument((doc) => {
      if (doc.languageId === 'python') {
        triggerScan(doc.uri.fsPath, state);
      }
    }),
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      updateStatusBar(state.statusBarItem, state.cache, editor);
    }),
  );

  registerFileWatcher(context, state);
}

function registerFileWatcher(
  context: vscode.ExtensionContext,
  state: ExtensionState,
): void {
  const watcher = vscode.workspace.createFileSystemWatcher('**/*.py');
  context.subscriptions.push(
    watcher.onDidChange((uri) => triggerScan(uri.fsPath, state)),
    watcher.onDidCreate((uri) => triggerScan(uri.fsPath, state)),
    watcher.onDidDelete((uri) => {
      state.cache.delete(uri.fsPath);
      state.codeLensProvider.refresh();
      updateStatusBar(state.statusBarItem, state.cache, vscode.window.activeTextEditor);
    }),
    watcher,
  );
}

function registerCommands(
  context: vscode.ExtensionContext,
  state: ExtensionState,
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand(
      'iamspy.showPermissionDetail',
      (finding: IamspyFinding) => showPermissionDetail(finding),
    ),
    vscode.commands.registerCommand('iamspy.showPermissionSummary', () => {
      showPermissionSummary(state);
    }),
  );
}

function triggerScan(filePath: string, state: ExtensionState): void {
  const config = vscode.workspace.getConfiguration('iamspy');
  if (!config.get<boolean>('scanOnSave', true)) {
    return;
  }

  const cliPath = config.get<string>('cliPath', 'iamspy');
  state.outputChannel.appendLine(`Scanning ${filePath} with ${cliPath}`);

  scanPath(filePath, cliPath)
    .then((findings) => {
      state.outputChannel.appendLine(`  → ${findings.length} finding(s)`);
      state.cache.set(filePath, findings);
      state.codeLensProvider.refresh();
      updateStatusBar(state.statusBarItem, state.cache, vscode.window.activeTextEditor);
    })
    .catch((error: unknown) => {
      state.outputChannel.appendLine(`  → FAILED: ${error}`);
    });
}

function scanActiveEditor(state: ExtensionState): void {
  const editor = vscode.window.activeTextEditor;
  if (editor?.document.languageId === 'python') {
    triggerScan(editor.document.uri.fsPath, state);
  }
}

function showPermissionDetail(finding: IamspyFinding): void {
  showDetailPanel(finding);
}

function showPermissionSummary(state: ExtensionState): void {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    return;
  }
  const items = buildSummaryItems(state.cache, editor.document.uri.fsPath);
  if (items.length === 0) {
    return;
  }
  vscode.window.showQuickPick(items, {
    placeHolder: 'IAM permissions required by this file',
  });
}
