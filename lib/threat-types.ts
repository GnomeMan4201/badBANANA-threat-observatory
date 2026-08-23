export type SourceStatus = "healthy" | "stale" | "offline" | "disabled";
export type ObservationKind = "vulnerability" | "ipv4" | "ipv6" | "domain" | "url" | "hash" | "malware" | "infrastructure";
export type TimeWindow = "15m" | "1h" | "6h" | "24h" | "7d";
export type HistoryMode = "persistent" | "snapshot-only";
export type IngestState = "new" | "seen" | "updated";
export type ObservationEventType = "new" | "updated" | "removed";
export type IngestionMode = "scheduled" | "demand-driven";
export type SourceCoverageMode = "full-current" | "bounded-window" | "bounded-latest";
export type ObservationScope = "all" | "urlhaus" | "malwarebazaar" | "infrastructure";

export interface NormalizedObservation {
  id: string;
  source: string;
  sourceRecordId?: string;
  kind: ObservationKind;
  indicator?: string;
  indicatorType?: string;
  title?: string;
  malwareFamily?: string;
  threatType?: string;
  confidence?: number;
  firstSeen?: string;
  lastSeen?: string;
  observedAt: string;
  tags: string[];
  reference?: string;
  ingestedAt: string;
  firstIngestedAt?: string;
  lastIngestedAt?: string;
  lastChangedAt?: string;
  lastObservedInSnapshotAt?: string;
  revisionCount?: number;
  recordHash?: string;
  ingestState?: IngestState;
  metadata: Record<string, string | number | boolean | null | undefined>;
}

export interface SourceHealth {
  id: string;
  name: string;
  status: SourceStatus;
  configured: boolean;
  lastAttempt?: string;
  lastSuccess?: string;
  recordCount: number;
  historyRecordCount?: number;
  latencyMs?: number;
  fetchedAt?: string;
  expiresAt?: string;
  upstreamDataDate?: string;
  consecutiveFailures?: number;
  nextRetryAt?: string;
  error?: string;
  reason?: string;
  authMode: string;
  refreshPolicy: string;
  upstreamUrl: string;
  dataUsed: string;
  coverage: string;
  coverageMode: SourceCoverageMode;
}

export interface SourceSnapshot {
  records: NormalizedObservation[];
  fetchedAt: string;
  expiresAt: string;
  health: SourceHealth;
}

export interface Correlation {
  indicator: string;
  observationIds: string[];
  sources: string[];
}

export interface HistoryHealth {
  mode: HistoryMode;
  status: "healthy" | "degraded";
  retentionDays: number;
  observationsStored?: number;
  oldestObservation?: string;
  newestObservation?: string;
  lastWrite?: string;
  lastPrune?: string;
  reason?: string;
}

export interface FieldDiff {
  field: string;
  before?: string | number | boolean | null | string[];
  after?: string | number | boolean | null | string[];
}

export interface ObservationEvent {
  eventId: string;
  observationId: string;
  source: string;
  sourceRecordId?: string;
  eventType: ObservationEventType;
  detectedAt: string;
  previousHash?: string;
  newHash?: string;
  previous?: NormalizedObservation;
  current?: NormalizedObservation;
  diff: FieldDiff[];
}

export interface SourceIngestCycle {
  id?: number;
  source: string;
  startedAt: string;
  completedAt: string;
  status: "success" | "failure" | "backoff" | "lease-held";
  upstreamRecords: number;
  validRecords: number;
  rejectedRecords: number;
  newRecords: number;
  updatedRecords: number;
  unchangedRecords: number;
  removedRecords: number;
  latencyMs: number;
  validationDiagnostics?: import("./rejection-diagnostics").ValidationDiagnostic[];
}

export interface IngestionHealth {
  mode: IngestionMode;
  status: "healthy" | "degraded";
  schedulerSupported: boolean;
  lastCycleStarted?: string;
  lastCycleCompleted?: string;
  lastSuccessfulCycle?: string;
  sourcesEligible: number;
  totalSources: number;
  leaseBackend: "d1" | "isolate-memory";
  reason?: string;
  latestSourceCycles: SourceIngestCycle[];
}

export interface PaginationInfo {
  nextCursor?: string;
  hasMore: boolean;
}

export interface FreshnessSummary {
  snapshotGenerated: string;
  latestSourceSuccess?: string;
  oldestEnabledSourceSuccess?: string;
  state: "fresh" | "stale" | "offline" | "disabled";
}

export interface ObservatoryAnalytics {
  bySource: Array<{ label: string; count: number }>;
  byKind: Array<{ label: string; count: number }>;
  topMalwareFamilies: Array<{ label: string; count: number }>;
  overTime: Array<{ label: string; count: number }>;
}

export interface ObservatoryPayload {
  records: NormalizedObservation[];
  recentEvents: ObservationEvent[];
  sources: SourceHealth[];
  correlations: Correlation[];
  correlationCoverage: { scope: "window-current-state"; truncated: boolean };
  analytics: ObservatoryAnalytics;
  history: HistoryHealth;
  freshness: FreshnessSummary;
  ingestion: IngestionHealth;
  pagination: PaginationInfo;
  window: TimeWindow;
  generatedAt: string;
}

export interface SearchPayload {
  records: NormalizedObservation[];
  query: string;
  sources: string[];
  window: TimeWindow;
  history: HistoryHealth;
  pagination: PaginationInfo;
}

export interface KevCatalogPayload {
  records: NormalizedObservation[];
  total: number;
  vendors: string[];
  products: string[];
  pagination: PaginationInfo;
  health?: SourceHealth;
  generatedAt: string;
}

export interface EventPayload {
  events: ObservationEvent[];
  pagination: PaginationInfo;
  history: HistoryHealth;
  ledger: EventLedgerBounds;
}

export interface EventLedgerBounds {
  oldestRetainedDetectedAt?: string;
  newestRetainedDetectedAt?: string;
  totalRetained: number;
}

export interface RevisionPayload {
  observation?: NormalizedObservation;
  events: ObservationEvent[];
  pagination: PaginationInfo;
  history: HistoryHealth;
}

export interface GeoPoint {
  ip: string;
  provider: "GEOJS" | "FREEIPAPI";
  latitude: number;
  longitude: number;
  city?: string;
  region?: string;
  country: string;
  countryCode: string;
  continent?: string;
  asn?: string;
  organization?: string;
  enrichedAt: string;
  observationIds: string[];
  sources: string[];
  latestObservedAt: string;
}

export interface GeoPayload {
  points: GeoPoint[];
  records: NormalizedObservation[];
  candidates: number;
  excluded: number;
  unavailable: number;
  pending: number;
  candidateRecords: number;
  candidateRecordsTruncated: boolean;
  cacheMode: "d1" | "isolate-memory";
  provider: {
    name: string;
    url: string;
    accuracy: "APPROXIMATE IP GEOLOCATION";
  };
  generatedAt: string;
}
