import { strict as assert } from 'node:assert';
import { describe, it } from 'mocha';
import { formatTitle, formatTooltip } from '../../src/format.js';
import type { IamspyFinding } from '../../src/types.js';

function makeFinding(overrides: Partial<IamspyFinding> = {}): IamspyFinding {
  return {
    file: 'app.py',
    line: 8,
    method: 'query',
    service_id: ['bigquery'],
    service: ['BigQuery'],
    class: ['Client'],
    permissions: ['bigquery.jobs.create'],
    conditional: [],
    status: 'mapped',
    resolution: 'exact',
    notes: '',
    ...overrides,
  };
}

describe('formatTitle', () => {
  it('shows single permission directly', () => {
    const title = formatTitle(makeFinding());
    assert.ok(title.includes('bigquery.jobs.create'));
  });

  it('shows count for multiple permissions', () => {
    const title = formatTitle(makeFinding({
      permissions: ['bigquery.jobs.create', 'bigquery.tables.getData'],
    }));
    assert.ok(title.includes('2 permissions'));
  });

  it('appends conditional count when present', () => {
    const title = formatTitle(makeFinding({
      conditional: ['bigquery.tables.getData', 'bigquery.tables.create'],
    }));
    assert.ok(title.includes('+2 conditional'));
  });

  it('shows identity tag when present', () => {
    const title = formatTitle(makeFinding({ identity: 'app' }));
    assert.ok(title.includes('[app]'));
  });

  it('no conditional suffix when empty', () => {
    const title = formatTitle(makeFinding({ conditional: [] }));
    assert.ok(!title.includes('conditional'));
  });
});

describe('formatTooltip', () => {
  it('includes method and service', () => {
    const tooltip = formatTooltip(makeFinding());
    assert.ok(tooltip.includes('Client'));
    assert.ok(tooltip.includes('query'));
    assert.ok(tooltip.includes('BigQuery'));
  });

  it('lists all permissions', () => {
    const tooltip = formatTooltip(makeFinding({
      permissions: ['bigquery.jobs.create', 'bigquery.tables.getData'],
    }));
    assert.ok(tooltip.includes('bigquery.jobs.create'));
    assert.ok(tooltip.includes('bigquery.tables.getData'));
  });

  it('marks conditional permissions', () => {
    const tooltip = formatTooltip(makeFinding({
      conditional: ['bigquery.tables.create'],
    }));
    assert.ok(tooltip.includes('CONDITIONAL'));
    assert.ok(tooltip.includes('bigquery.tables.create'));
  });
});
