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
    assert.equal(title, '🔑 bigquery.jobs.create');
  });

  it('shows count for multiple permissions', () => {
    const title = formatTitle(makeFinding({
      permissions: ['bigquery.jobs.create', 'bigquery.tables.getData'],
    }));
    assert.equal(title, '🔑 2 permissions');
  });

  it('appends conditional count when present', () => {
    const title = formatTitle(makeFinding({
      conditional: ['bigquery.tables.getData', 'bigquery.tables.create'],
    }));
    assert.equal(title, '🔑 bigquery.jobs.create  +2 conditional');
  });

  it('no conditional suffix when empty', () => {
    const title = formatTitle(makeFinding({ conditional: [] }));
    assert.ok(!title.includes('conditional'));
  });
});

describe('formatTooltip', () => {
  it('includes method and service', () => {
    const tooltip = formatTooltip(makeFinding());
    assert.ok(tooltip.includes('Client.query'));
    assert.ok(tooltip.includes('Service: BigQuery'));
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
    assert.ok(tooltip.includes('Conditional:'));
    assert.ok(tooltip.includes('bigquery.tables.create'));
  });
});
