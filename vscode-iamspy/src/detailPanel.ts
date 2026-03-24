/**
 * Webview panel showing full permission detail for a finding.
 *
 * Opened when the user clicks a CodeLens annotation.
 */

import * as vscode from 'vscode';
import type { IamspyFinding } from './types.js';

let currentPanel: vscode.WebviewPanel | undefined;

/** Show or update the permission detail webview panel. */
export function showDetailPanel(finding: IamspyFinding): void {
  if (currentPanel) {
    currentPanel.webview.html = buildHtml(finding);
    currentPanel.title = `IAM: ${finding.method}`;
    currentPanel.reveal();
    return;
  }

  currentPanel = vscode.window.createWebviewPanel(
    'iamspyDetail',
    `IAM: ${finding.method}`,
    vscode.ViewColumn.Beside,
    { enableScripts: false },
  );

  currentPanel.webview.html = buildHtml(finding);
  currentPanel.onDidDispose(() => { currentPanel = undefined; });
}

function buildHtml(finding: IamspyFinding): string {
  const service = esc(finding.service.join(', '));
  const className = finding.class.length <= 3
    ? esc(finding.class.join(', '))
    : esc(finding.class[0]);
  const method = esc(finding.method);
  const rows = buildPermissionRows(finding);
  const meta = buildMetaSection(finding);
  const docsLink = buildDocsLink(finding);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>${CSS}</style>
</head>
<body>
  <h1>${className}.${method}</h1>
  <div class="service">${service}</div>
  <table>
    <thead><tr><th>Permission</th><th>Type</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  ${meta}
  ${docsLink}
</body>
</html>`;
}

function buildPermissionRows(finding: IamspyFinding): string {
  const required = finding.permissions.map(
    (p) => `<tr><td class="perm">${permissionLink(p)}</td><td><span class="tag required">required</span></td></tr>`,
  );
  const conditional = finding.conditional.map(
    (c) => `<tr><td class="perm">${permissionLink(c)}</td><td><span class="tag conditional">conditional</span></td></tr>`,
  );
  return [...required, ...conditional].join('\n');
}

/** Build a link to the IAM roles-permissions docs page for a permission. */
function permissionLink(permission: string): string {
  const service = permission.split('.')[0];
  const url = `https://cloud.google.com/iam/docs/roles-permissions/${esc(service)}#${esc(permission)}`;
  return `<a href="${url}">${esc(permission)}</a>`;
}

function buildMetaSection(finding: IamspyFinding): string {
  const parts: string[] = [];

  if (finding.notes) {
    parts.push(`<div class="meta-item">
      <span class="meta-label">Notes</span>
      <span>${esc(finding.notes)}</span>
    </div>`);
  }

  parts.push(`<div class="meta-item">
    <span class="meta-label">Resolution</span>
    <span class="tag ${finding.resolution}">${finding.resolution}</span>
  </div>`);

  const shortFile = finding.file.split('/').slice(-3).join('/');
  parts.push(`<div class="meta-item">
    <span class="meta-label">Location</span>
    <span class="perm">${esc(shortFile)}:${finding.line}</span>
  </div>`);

  return `<div class="meta">${parts.join('\n')}</div>`;
}

function buildDocsLink(finding: IamspyFinding): string {
  const links: string[] = [];

  // Link to the service-specific roles-permissions page.
  const firstPerm = finding.permissions[0] ?? finding.conditional[0];
  if (firstPerm) {
    const service = firstPerm.split('.')[0];
    const url = `https://cloud.google.com/iam/docs/roles-permissions/${esc(service)}`;
    links.push(`<a href="${url}">${esc(service)} Roles &amp; Permissions</a>`);
  }

  // Service-specific access control docs follow a predictable pattern.
  const serviceId = finding.service_id[0];
  if (serviceId) {
    const slug = iamDocsSlug(serviceId);
    const url = `https://cloud.google.com/${slug}/docs/access-control`;
    const name = finding.service[0] ?? serviceId;
    links.push(`<a href="${url}">${esc(name)} Access Control</a>`);
  }

  return links.length > 0
    ? `<div class="docs">${links.join(' · ')}</div>`
    : '';
}

/** Map service_id to GCP docs URL slug. */
function iamDocsSlug(serviceId: string): string {
  const overrides: Record<string, string> = {
    bigquery: 'bigquery',
    storage: 'storage',
    compute: 'compute',
    pubsub: 'pubsub',
    kms: 'kms',
    secretmanager: 'secret-manager',
    cloudbuild: 'build',
    artifactregistry: 'artifact-registry',
    cloudfunctions: 'functions',
    cloudrun: 'run',
    spanner: 'spanner',
    firestore: 'firestore',
    bigtable: 'bigtable',
    dataflow: 'dataflow',
    dataproc: 'dataproc',
    aiplatform: 'vertex-ai',
  };
  return overrides[serviceId] ?? serviceId;
}

function esc(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

const CSS = `
  body {
    font-family: var(--vscode-font-family);
    color: var(--vscode-foreground);
    background: var(--vscode-editor-background);
    padding: 16px 24px; line-height: 1.6;
  }
  h1 { font-size: 1.3em; margin: 0 0 4px 0; }
  .service {
    color: var(--vscode-descriptionForeground);
    font-size: 0.9em; margin-bottom: 16px;
  }
  table { border-collapse: collapse; width: 100%; }
  th {
    text-align: left; padding: 6px 12px 6px 0;
    border-bottom: 1px solid var(--vscode-panel-border);
    color: var(--vscode-descriptionForeground);
    font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px;
  }
  td { padding: 6px 12px 6px 0; }
  .perm { font-family: var(--vscode-editor-font-family); font-size: 0.95em; }
  .tag {
    font-size: 0.75em; padding: 2px 8px; border-radius: 4px;
    text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600;
    display: inline-block;
  }
  .required { background: #2ea043; color: #fff; }
  .conditional { background: #d29922; color: #fff; }
  .exact { background: #2ea043; color: #fff; }
  .ambiguous { background: #d29922; color: #fff; }
  .unresolved { background: #6e7681; color: #fff; }
  .meta {
    margin-top: 20px; padding-top: 16px;
    border-top: 1px solid var(--vscode-panel-border);
  }
  .meta-item { margin-bottom: 8px; }
  .meta-label {
    color: var(--vscode-descriptionForeground);
    font-size: 0.85em; text-transform: uppercase;
    letter-spacing: 0.5px; display: inline-block;
    width: 100px;
  }
  .docs {
    margin-top: 20px; padding-top: 16px;
    border-top: 1px solid var(--vscode-panel-border);
    font-size: 0.9em;
  }
  a {
    color: var(--vscode-textLink-foreground);
    text-decoration: none;
  }
  a:hover { text-decoration: underline; }
`;
