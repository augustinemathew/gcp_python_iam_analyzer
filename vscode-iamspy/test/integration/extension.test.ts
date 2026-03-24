/**
 * Integration tests — run inside a real VS Code instance.
 *
 * These require `iamspy` to be installed and on PATH.
 * Run with: npm run test:integration
 *
 * Uses TDD interface (suite/test) to match @vscode/test-cli defaults.
 */

import { strict as assert } from 'node:assert';
import * as vscode from 'vscode';
import { openFixture, waitFor, sleep } from './helpers.js';

suite('Extension activation', () => {
  test('activates on Python file open', async () => {
    await openFixture('bigquery_app.py');
    await sleep(2_000);

    const ext = vscode.extensions.getExtension('iamspy.vscode-iamspy');
    assert.ok(ext, 'Extension should be found');
    assert.ok(ext.isActive, 'Extension should be active');
  });
});

suite('CodeLens', () => {
  suiteSetup(async () => {
    await openFixture('bigquery_app.py');
    await sleep(3_000);
  });

  test('provides CodeLens for GCP SDK calls', async () => {
    const editor = vscode.window.activeTextEditor;
    assert.ok(editor, 'Editor should be open');

    const lenses = await waitForCodeLenses(editor.document.uri);
    assert.ok(lenses.length > 0, 'Should have at least one CodeLens');
  });

  test('CodeLens title contains IAM prefix', async () => {
    const editor = vscode.window.activeTextEditor!;
    const lenses = await waitForCodeLenses(editor.document.uri);
    const titles = lenses
      .map((l) => l.command?.title ?? '')
      .filter((t) => t.length > 0);

    assert.ok(
      titles.some((t) => t.startsWith('🔑')),
      `Expected title starting with '🔑', got: ${titles.join(', ')}`,
    );
  });
});

suite('Multi-service file', () => {
  suiteSetup(async () => {
    await openFixture('multi_service_app.py');
    await sleep(3_000);
  });

  test('provides CodeLens for multiple GCP services', async () => {
    const editor = vscode.window.activeTextEditor!;
    const lenses = await waitForCodeLenses(editor.document.uri);

    // multi_service_app.py uses bigquery, storage, and secretmanager.
    assert.ok(lenses.length >= 3, `Expected >= 3 lenses, got ${lenses.length}`);
  });

  test('CodeLens titles reference different services', async () => {
    const editor = vscode.window.activeTextEditor!;
    const lenses = await waitForCodeLenses(editor.document.uri);
    const titles = lenses
      .map((l) => l.command?.title ?? '')
      .filter((t) => t.length > 0);

    // Should see permissions from multiple services.
    const allTitles = titles.join(' ');
    assert.ok(titles.length >= 2, `Expected multiple titles, got: ${allTitles}`);
  });
});

suite('Storage file', () => {
  suiteSetup(async () => {
    await openFixture('storage_app.py');
    await sleep(3_000);
  });

  test('provides CodeLens for storage SDK calls', async () => {
    const editor = vscode.window.activeTextEditor!;
    const lenses = await waitForCodeLenses(editor.document.uri);
    assert.ok(lenses.length > 0, 'Should have storage CodeLenses');

    const titles = lenses
      .map((l) => l.command?.title ?? '')
      .filter((t) => t.startsWith('🔑'));
    assert.ok(
      titles.some((t) => t.includes('storage')),
      `Expected storage permissions, got: ${titles.join(', ')}`,
    );
  });
});

suite('No GCP imports', () => {
  test('produces no CodeLens for non-GCP files', async () => {
    await openFixture('no_gcp.py');
    await sleep(2_000);

    const editor = vscode.window.activeTextEditor!;
    const lenses = await vscode.commands.executeCommand<vscode.CodeLens[]>(
      'vscode.executeCodeLensProvider',
      editor.document.uri,
    );

    assert.equal(
      lenses?.length ?? 0, 0,
      'Non-GCP file should have zero CodeLenses',
    );
  });
});

suite('Commands', () => {
  suiteSetup(async () => {
    // Ensure extension is activated by opening a Python file.
    await openFixture('bigquery_app.py');
    await sleep(2_000);
  });

  test('generateManifest command is registered', async () => {
    const commands = await vscode.commands.getCommands(true);
    assert.ok(
      commands.includes('iamspy.generateManifest'),
      'generateManifest command should be registered',
    );
  });
});

/** Poll for CodeLenses on a document URI. */
async function waitForCodeLenses(
  uri: vscode.Uri,
): Promise<vscode.CodeLens[]> {
  let lenses: vscode.CodeLens[] = [];

  await waitFor(async () => {
    const result = await vscode.commands.executeCommand<vscode.CodeLens[]>(
      'vscode.executeCodeLensProvider',
      uri,
    );
    lenses = result ?? [];
    return lenses.length > 0;
  });

  return lenses;
}
