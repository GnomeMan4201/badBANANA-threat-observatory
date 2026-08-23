import type { NormalizedObservation } from "./threat-types";
import type { ValidationDiagnostic } from "./rejection-diagnostics";

export interface AdapterFetchResult {
  records: NormalizedObservation[];
  upstreamRecords: number;
  rejectedRecords: number;
  validationDiagnostics: ValidationDiagnostic[];
  upstreamDataDate?: string;
}

export interface ThreatSourceAdapter {
  readonly id: string;
  readonly name: string;
  readonly credentialKey?: "THREATFOX_AUTH_KEY" | "URLHAUS_AUTH_KEY" | "MALWAREBAZAAR_AUTH_KEY";
  readonly cacheTtlMs: number;
  readonly authMode: string;
  readonly refreshPolicy: string;
  readonly upstreamUrl: string;
  readonly dataUsed: string;
  readonly coverage: string;
  readonly coverageMode: "full-current" | "bounded-window" | "bounded-latest";
  fetchRecent(credential?: string): Promise<AdapterFetchResult>;
}

export function findSourceAdapter(adapters: readonly ThreatSourceAdapter[], id: string): ThreatSourceAdapter | undefined {
  return adapters.find((adapter) => adapter.id === id);
}
