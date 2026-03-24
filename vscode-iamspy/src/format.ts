/**
 * Pure formatting functions for findings — no VS Code API dependency.
 *
 * Shared between CodeLens (titles/tooltips) and tests.
 */

import type { IamspyFinding } from './types.js';

/** Short title for a CodeLens annotation. */
export function formatTitle(finding: IamspyFinding): string {
  const perms = finding.permissions;
  const condCount = finding.conditional.length;
  const suffix = condCount > 0 ? `  +${condCount} conditional` : '';

  if (perms.length === 1) {
    return `🔑 ${perms[0]}${suffix}`;
  }
  return `🔑 ${perms.length} permissions${suffix}`;
}

/** Detailed tooltip showing all permissions. */
export function formatTooltip(finding: IamspyFinding): string {
  const className = finding.class.length <= 3
    ? finding.class.join(', ')
    : finding.class[0];
  const lines = [
    `${className}.${finding.method}`,
    `Service: ${finding.service.join(', ')}`,
    '',
    'Required:',
    ...finding.permissions.map((p) => `  ${p}`),
  ];

  if (finding.conditional.length > 0) {
    lines.push('', 'Conditional:');
    lines.push(...finding.conditional.map((c) => `  ${c}`));
  }

  if (finding.notes) {
    lines.push('', `Note: ${finding.notes}`);
  }

  lines.push('', `Resolution: ${finding.resolution}`);
  lines.push('', 'Click for full details');

  return lines.join('\n');
}

/** Count unique required and conditional permissions across findings. */
export function countPermissions(
  findings: IamspyFinding[],
): { permCount: number; condCount: number } {
  const perms = new Set<string>();
  const conds = new Set<string>();

  for (const f of findings) {
    for (const p of f.permissions) {
      perms.add(p);
    }
    for (const c of f.conditional) {
      conds.add(c);
    }
  }

  return { permCount: perms.size, condCount: conds.size };
}

/** Group all permissions by service display name. */
export function groupByService(
  findings: IamspyFinding[],
): Map<string, string[]> {
  const grouped = new Map<string, Set<string>>();

  for (const f of findings) {
    const serviceName = f.service[0] ?? 'Unknown';
    if (!grouped.has(serviceName)) {
      grouped.set(serviceName, new Set());
    }
    const servicePerms = grouped.get(serviceName)!;
    for (const p of f.permissions) {
      servicePerms.add(p);
    }
    for (const c of f.conditional) {
      servicePerms.add(`${c} (conditional)`);
    }
  }

  const result = new Map<string, string[]>();
  for (const [service, perms] of grouped) {
    result.set(service, [...perms].sort());
  }
  return result;
}
