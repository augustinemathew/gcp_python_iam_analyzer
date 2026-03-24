/**
 * Shared helpers for integration tests.
 */

import * as vscode from 'vscode';
import * as path from 'node:path';

// __dirname is out/test/integration/ at runtime. Fixtures live in the source
// tree, not the compiled output, so resolve relative to the project root.
const PROJECT_ROOT = path.resolve(__dirname, '../../..');
const FIXTURE_DIR = path.join(PROJECT_ROOT, 'test', 'fixtures');

/** Open a fixture file in the editor and wait for it to be active. */
export async function openFixture(
  filename: string,
): Promise<vscode.TextEditor> {
  const uri = vscode.Uri.file(path.join(FIXTURE_DIR, filename));
  const doc = await vscode.workspace.openTextDocument(uri);
  return vscode.window.showTextDocument(doc);
}

/** Wait for a condition to become true, polling at `intervalMs`. */
export async function waitFor(
  condition: () => boolean | Promise<boolean>,
  timeoutMs: number = 10_000,
  intervalMs: number = 200,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await condition()) {
      return;
    }
    await sleep(intervalMs);
  }
  throw new Error(`waitFor timed out after ${timeoutMs}ms`);
}

/** Sleep for `ms` milliseconds. */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
