import { strict as assert } from 'node:assert';
import { describe, it } from 'mocha';
import { countPermissions, groupByService } from '../../src/format.js';
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

describe('countPermissions', () => {
  it('counts unique required permissions', () => {
    const findings = [
      makeFinding({ permissions: ['bigquery.jobs.create'] }),
      makeFinding({ permissions: ['bigquery.jobs.create', 'bigquery.tables.getData'] }),
    ];
    const { permCount } = countPermissions(findings);
    assert.equal(permCount, 2);
  });

  it('counts unique conditional permissions', () => {
    const findings = [
      makeFinding({ conditional: ['bigquery.tables.create'] }),
      makeFinding({ conditional: ['bigquery.tables.create', 'bigquery.tables.getData'] }),
    ];
    const { condCount } = countPermissions(findings);
    assert.equal(condCount, 2);
  });

  it('returns zero for empty findings', () => {
    const { permCount, condCount } = countPermissions([]);
    assert.equal(permCount, 0);
    assert.equal(condCount, 0);
  });
});

describe('groupByService', () => {
  it('groups permissions by service name', () => {
    const findings = [
      makeFinding({ service: ['BigQuery'], permissions: ['bigquery.jobs.create'] }),
      makeFinding({ service: ['Cloud Storage'], permissions: ['storage.buckets.get'] }),
    ];
    const grouped = groupByService(findings);
    assert.equal(grouped.size, 2);
    assert.deepEqual(grouped.get('BigQuery'), ['bigquery.jobs.create']);
    assert.deepEqual(grouped.get('Cloud Storage'), ['storage.buckets.get']);
  });

  it('deduplicates permissions within a service', () => {
    const findings = [
      makeFinding({ permissions: ['bigquery.jobs.create'] }),
      makeFinding({ permissions: ['bigquery.jobs.create'] }),
    ];
    const grouped = groupByService(findings);
    assert.deepEqual(grouped.get('BigQuery'), ['bigquery.jobs.create']);
  });

  it('marks conditional permissions', () => {
    const findings = [
      makeFinding({ conditional: ['bigquery.tables.create'] }),
    ];
    const grouped = groupByService(findings);
    assert.ok(grouped.get('BigQuery')?.includes('bigquery.tables.create (conditional)'));
  });

  it('sorts permissions alphabetically', () => {
    const findings = [
      makeFinding({
        permissions: ['bigquery.tables.getData', 'bigquery.jobs.create'],
      }),
    ];
    const grouped = groupByService(findings);
    const perms = grouped.get('BigQuery')!;
    assert.equal(perms[0], 'bigquery.jobs.create');
    assert.equal(perms[1], 'bigquery.tables.getData');
  });
});
