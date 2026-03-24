import { strict as assert } from 'node:assert';
import { describe, it } from 'mocha';
import { parseFindings } from '../../src/scanner.js';

describe('parseFindings — valid input', () => {
  it('parses valid JSON array into findings', () => {
    const json = JSON.stringify([
      {
        file: 'app.py',
        line: 8,
        method: 'query',
        service_id: ['bigquery'],
        service: ['BigQuery'],
        class: ['Client'],
        permissions: ['bigquery.jobs.create'],
        conditional: ['bigquery.tables.getData'],
        status: 'mapped',
      },
    ]);

    const findings = parseFindings(json);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].method, 'query');
    assert.equal(findings[0].line, 8);
    assert.deepEqual(findings[0].permissions, ['bigquery.jobs.create']);
    assert.deepEqual(findings[0].conditional, ['bigquery.tables.getData']);
    assert.equal(findings[0].status, 'mapped');
  });

});

describe('parseFindings — multiple findings', () => {
  it('handles multiple findings', () => {
    const json = JSON.stringify([
      {
        file: 'app.py', line: 8, method: 'query',
        service_id: ['bigquery'], service: ['BigQuery'], class: ['Client'],
        permissions: ['bigquery.jobs.create'], conditional: [], status: 'mapped',
      },
      {
        file: 'app.py', line: 12, method: 'get_bucket',
        service_id: ['storage'], service: ['Cloud Storage'], class: ['Client'],
        permissions: ['storage.buckets.get'], conditional: [], status: 'mapped',
      },
    ]);

    const findings = parseFindings(json);
    assert.equal(findings.length, 2);
    assert.equal(findings[0].method, 'query');
    assert.equal(findings[1].method, 'get_bucket');
  });
});

describe('parseFindings — edge cases', () => {
  it('returns empty array for empty string', () => {
    assert.deepEqual(parseFindings(''), []);
    assert.deepEqual(parseFindings('  '), []);
  });

  it('returns empty array for empty JSON array', () => {
    assert.deepEqual(parseFindings('[]'), []);
  });

  it('throws on non-array JSON', () => {
    assert.throws(() => parseFindings('{"key": "value"}'), /Expected JSON array/);
  });

  it('throws on invalid JSON', () => {
    assert.throws(() => parseFindings('not json'));
  });
});
