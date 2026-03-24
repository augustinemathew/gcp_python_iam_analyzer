/**
 * Wraps the iamspy CLI to scan Python files for GCP IAM permissions.
 *
 * Shells out to `iamspy scan --json <file>` and parses the JSON output.
 * Each scan spawns a short-lived process (~180ms). A long-running daemon
 * (`iamspy serve`) can replace this later if latency becomes an issue.
 */

import { execFile, type ChildProcess } from 'node:child_process';
import type { IamspyFinding } from './types.js';

const DEFAULT_TIMEOUT_MS = 10_000;

/** In-flight scan processes, keyed by file path. Allows cancellation on re-scan. */
const inflightScans = new Map<string, ChildProcess>();

/** Run `iamspy scan --json` on a single file or directory. */
export function scanPath(
  target: string,
  cliPath: string = 'iamspy',
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<IamspyFinding[]> {
  cancelInflight(target);

  return new Promise((resolve, reject) => {
    const child = execFile(
      cliPath,
      ['scan', '--json', target],
      { timeout: timeoutMs, maxBuffer: 10 * 1024 * 1024 },
      (error, stdout, stderr) => {
        inflightScans.delete(target);

        if (error) {
          // Timeout or CLI not found — resolve empty, don't crash.
          console.error(`[iamspy] CLI error: ${error.message}`);
          if (stderr) {
            console.error(`[iamspy] stderr: ${stderr}`);
          }
          resolve([]);
          return;
        }

        try {
          resolve(parseFindings(stdout));
        } catch (parseError) {
          reject(new Error(`Failed to parse iamspy output: ${parseError}`));
        }
      },
    );

    inflightScans.set(target, child);
  });
}

/** Parse JSON output from the CLI into typed findings. */
export function parseFindings(json: string): IamspyFinding[] {
  const trimmed = json.trim();
  if (!trimmed) {
    return [];
  }
  const parsed: unknown = JSON.parse(trimmed);
  if (!Array.isArray(parsed)) {
    throw new Error(`Expected JSON array, got ${typeof parsed}`);
  }
  return parsed as IamspyFinding[];
}

/** Cancel an in-flight scan for a given target. */
function cancelInflight(target: string): void {
  const existing = inflightScans.get(target);
  if (existing) {
    existing.kill();
    inflightScans.delete(target);
  }
}
