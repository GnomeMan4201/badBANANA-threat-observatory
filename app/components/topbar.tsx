import { formatUtcTime } from "./observatory-format";

interface TopbarProps {
  now: Date;
  query: string;
  dataState?: string;
  searchEnabled?: boolean;
  compact?: boolean;
  onHome(): void;
  onQueryChange(value: string): void;
}

export function Topbar({ now, query, dataState, searchEnabled = true, compact = false, onHome, onQueryChange }: TopbarProps) {
  const state = dataState?.toUpperCase() ?? "CHECKING";
  return (
    <header className={`topbar ${searchEnabled ? "" : "noSearch"} ${compact ? "compact" : ""}`}>
      <button className="brand" onClick={onHome} aria-label="Open device briefing">
        <span className="sigil" aria-hidden="true">
          <img className="sigilStatic" src="/brand-eye-poster.jpg" alt="" draggable={false} decoding="async" />
          <video
            className="sigilMotion"
            src="/brand-eye-loop.mp4"
            poster="/brand-eye-poster.jpg"
            autoPlay
            muted
            loop
            playsInline
            preload="metadata"
            tabIndex={-1}
          />
        </span>
        <span><b>badBANANA</b><small>THREAT OBSERVATORY</small></span>
      </button>
      <div className="statusStrip">
        <span className={`health ${state === "FRESH" ? "healthy" : "degraded"}`}>DATA STATE // {state}</span>
        <time>{formatUtcTime(now)}</time>
      </div>
      {searchEnabled && <label className="search">
        <span aria-hidden="true">⌕</span>
        <input
          value={query}
          onChange={(event) => onQueryChange(event.target.value.slice(0, 120))}
          placeholder="Search selected window"
          aria-label="Search records"
        />
      </label>}
    </header>
  );
}
