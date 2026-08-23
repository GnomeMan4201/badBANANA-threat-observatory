export const createObservationsTable = "CREATE TABLE IF NOT EXISTS observations (id TEXT PRIMARY KEY NOT NULL, source TEXT NOT NULL, source_record_id TEXT, kind TEXT NOT NULL, indicator TEXT, indicator_type TEXT, malware_family TEXT, observed_at TEXT NOT NULL, first_ingested_at TEXT NOT NULL, last_ingested_at TEXT NOT NULL, last_changed_at TEXT, last_observed_snapshot_at TEXT, revision_count INTEGER NOT NULL DEFAULT 1, record_hash TEXT NOT NULL, ingest_state TEXT NOT NULL, is_current INTEGER NOT NULL DEFAULT 1, search_text TEXT NOT NULL, payload_json TEXT NOT NULL)";

export const observationColumnAdditions: Array<[string, string]> = [
  ["last_changed_at", "TEXT"],
  ["last_observed_snapshot_at", "TEXT"],
  ["revision_count", "INTEGER NOT NULL DEFAULT 1"],
  ["is_current", "INTEGER NOT NULL DEFAULT 1"],
];

export const currentStateSchemaStatements = [
  "CREATE INDEX IF NOT EXISTS idx_observations_current_time ON observations(is_current, observed_at DESC, id ASC)",
  "CREATE INDEX IF NOT EXISTS idx_observations_ingest ON observations(last_ingested_at DESC)",
  "CREATE INDEX IF NOT EXISTS idx_observations_source_current_time ON observations(source, is_current, observed_at DESC, id ASC)",
  "CREATE INDEX IF NOT EXISTS idx_observations_indicator ON observations(indicator)",
];

export const eventLedgerSchemaStatements = [
  "CREATE TABLE IF NOT EXISTS observation_events (event_id TEXT PRIMARY KEY NOT NULL, observation_id TEXT NOT NULL, source TEXT NOT NULL, source_record_id TEXT, event_type TEXT NOT NULL, detected_at TEXT NOT NULL, previous_hash TEXT, new_hash TEXT, previous_payload_json TEXT, new_payload_json TEXT, diff_json TEXT NOT NULL)",
  "CREATE INDEX IF NOT EXISTS idx_observation_events_time ON observation_events(detected_at DESC, event_id ASC)",
  "CREATE INDEX IF NOT EXISTS idx_observation_events_observation ON observation_events(observation_id, detected_at DESC, event_id ASC)",
];

export const operationsSchemaStatements = [
  "CREATE TABLE IF NOT EXISTS source_fetch_log (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, attempted_at TEXT NOT NULL, completed_at TEXT NOT NULL, status TEXT NOT NULL, latency_ms INTEGER, record_count INTEGER, error_class TEXT)",
  "CREATE INDEX IF NOT EXISTS idx_fetch_log_source_time ON source_fetch_log(source, attempted_at DESC)",
  "CREATE TABLE IF NOT EXISTS source_ingest_cycles (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, started_at TEXT NOT NULL, completed_at TEXT NOT NULL, status TEXT NOT NULL, upstream_records INTEGER NOT NULL, valid_records INTEGER NOT NULL, rejected_records INTEGER NOT NULL, new_records INTEGER NOT NULL, updated_records INTEGER NOT NULL, unchanged_records INTEGER NOT NULL, removed_records INTEGER NOT NULL DEFAULT 0, latency_ms INTEGER NOT NULL)",
  "CREATE INDEX IF NOT EXISTS idx_ingest_cycles_source_time ON source_ingest_cycles(source, completed_at DESC)",
  "CREATE TABLE IF NOT EXISTS source_refresh_lease (source TEXT PRIMARY KEY NOT NULL, holder TEXT NOT NULL, expires_at TEXT NOT NULL)",
  "CREATE TABLE IF NOT EXISTS ingestion_runtime (id INTEGER PRIMARY KEY CHECK(id = 1), payload_json TEXT NOT NULL, updated_at TEXT NOT NULL)",
];

export const operationColumnAdditions: Array<[string, string, string]> = [
  ["source_ingest_cycles", "validation_diagnostics_json", "TEXT"],
];

export const geoSchemaStatements = [
  "CREATE TABLE IF NOT EXISTS geo_ip_cache (ip TEXT PRIMARY KEY NOT NULL, status TEXT NOT NULL, latitude REAL, longitude REAL, city TEXT, region TEXT, country TEXT, country_code TEXT, continent TEXT, asn TEXT, organization TEXT, provider TEXT NOT NULL, enriched_at TEXT NOT NULL, expires_at TEXT NOT NULL, error TEXT)",
  "CREATE INDEX IF NOT EXISTS idx_geo_ip_cache_expiry ON geo_ip_cache(expires_at)",
];
