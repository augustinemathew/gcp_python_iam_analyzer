/**
 * TypeScript interfaces mirroring the iamspy CLI JSON output.
 *
 * Contract defined by `_finding_to_dict()` in `src/iamspy/cli.py`.
 */

/** A single GCP SDK call detected by the scanner. */
export interface IamspyFinding {
  file: string;
  line: number;
  method: string;
  service_id: string[];
  service: string[];
  class: string[];
  permissions: string[];
  conditional: string[];
  status: FindingStatus;
  resolution: 'exact' | 'ambiguous' | 'unresolved';
  notes: string;
}

export type FindingStatus = 'mapped' | 'unmapped' | 'no_api_call';

/** Scan results grouped by file URI. */
export type FindingCache = Map<string, IamspyFinding[]>;
