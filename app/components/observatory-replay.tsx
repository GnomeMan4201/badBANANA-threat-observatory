"use client";
import { useEffect, useMemo, useState } from "react";
import type { CSSProperties } from "react";
import type { NormalizedObservation, ObservationEvent } from "../../lib/threat-types";
import { buildReplayFrame, orderReplayEvents, replaySourceOrder } from "../../lib/replay";
import { formatTimestamp } from "./observatory-format";

const SPEEDS = [0.5, 1, 2, 4] as const;

export function ObservatoryReplay({ events, pageBounded, onSelect }: { events: ObservationEvent[]; pageBounded: boolean; onSelect(record: NormalizedObservation): void }) {
  const ordered = useMemo(() => orderReplayEvents(events), [events]);
  const sources = useMemo(() => replaySourceOrder(ordered), [ordered]);
  const [cursor, setCursor] = useState(0);
  const [playing, setPlaying] = useState(() => Boolean(events.length > 1 && !(globalThis.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false)));
  const [speed, setSpeed] = useState<(typeof SPEEDS)[number]>(1);
  const active = ordered[cursor];
  const frame = useMemo(() => buildReplayFrame(ordered, cursor), [cursor, ordered]);

  useEffect(() => {
    if (!playing || ordered.length < 2) return;
    const timer = setInterval(() => setCursor((value) => {
      if (value >= ordered.length - 1) { setPlaying(false); return value; }
      return value + 1;
    }), 1_100 / speed);
    return () => clearInterval(timer);
  }, [ordered.length, playing, speed]);

  const move = (next: number) => {
    setPlaying(false);
    setCursor(Math.max(0, Math.min(ordered.length - 1, next)));
  };

  if (!ordered.length) return <section className="replayWorkbench"><div className="replayEmpty"><b>NO MATERIAL TRANSITIONS TO REPLAY</b><span>The ledger does not contain NEW, UPDATED, or REMOVED events on this page.</span></div></section>;

  return <section className="replayWorkbench" aria-label="Observatory event replay">
    <header className="replayHeader">
      <div><p>LEDGER-DRIVEN / OBSERVATORY TIME</p><h1>Transition replay</h1></div>
      <div className="replayBoundary"><b>PAGE-BOUNDED RECONSTRUCTION</b><span>Not a full historical snapshot</span></div>
    </header>

    <div className="replayConsole">
      <div className="replayStage" style={{ "--replay-progress": `${ordered.length > 1 ? cursor / (ordered.length - 1) * 100 : 100}%` } as CSSProperties}>
        <div className="replayScan" aria-hidden="true" />
        {sources.map((source) => <div className="replayLane" key={source}>
          <b>{source}</b><div className="replayRail">
            {ordered.map((event, index) => event.source === source ? <button
              key={event.eventId}
              className={`replayNode ${event.eventType} ${index < cursor ? "past" : index === cursor ? "active" : "future"}`}
              style={{ left: `${ordered.length > 1 ? index / (ordered.length - 1) * 100 : 50}%`, "--node-scale": String(Math.min(1.65, 1 + event.diff.length * .09)) } as CSSProperties}
              onClick={() => move(index)}
              aria-label={`${event.eventType} ${event.source} at ${formatTimestamp(event.detectedAt)}`}
            ><i /></button> : null)}
          </div>
        </div>)}
        <div className="replayLegend"><span><i className="new" />NEW</span><span><i className="updated" />UPDATED</span><span><i className="removed" />REMOVED</span><em>SIZE = CHANGED FIELD COUNT</em></div>
      </div>

      <aside className={`replayReadout ${active.eventType}`}>
        <div className="replaySequence"><span>TRANSITION</span><b>{String(cursor + 1).padStart(2, "0")} / {String(ordered.length).padStart(2, "0")}</b></div>
        <time>{formatTimestamp(active.detectedAt)}</time>
        <strong>{active.eventType.toUpperCase()}</strong>
        <small>{active.source}</small>
        <code>{indicator(active)}</code>
        <dl><dt>CHANGED FIELDS</dt><dd>{active.diff.length ? active.diff.map((item) => item.field).join(" · ") : active.eventType === "new" ? "NEW SOURCE RECORD" : "NO LONGER PRESENT"}</dd><dt>VISIBLE REPLAY STATE</dt><dd>{frame.filter((entity) => entity.state === "present").length} PRESENT · {frame.filter((entity) => entity.state === "removed").length} REMOVED</dd></dl>
        {(active.current ?? active.previous) && <button onClick={() => onSelect((active.current ?? active.previous) as NormalizedObservation)}>INSPECT EVIDENCE RECORD</button>}
      </aside>
    </div>

    <div className="replayTransport">
      <button onClick={() => move(0)} disabled={cursor === 0}>FIRST</button>
      <button onClick={() => move(cursor - 1)} disabled={cursor === 0}>PREVIOUS</button>
      <button className="play" onClick={() => cursor >= ordered.length - 1 ? (setCursor(0), setPlaying(true)) : setPlaying((value) => !value)}>{playing ? "PAUSE" : cursor >= ordered.length - 1 ? "REPLAY" : "PLAY"}</button>
      <button onClick={() => move(cursor + 1)} disabled={cursor >= ordered.length - 1}>NEXT</button>
      <label><span>PLAYHEAD</span><input aria-label="Replay position" type="range" min="0" max={Math.max(0, ordered.length - 1)} value={cursor} onChange={(event) => move(Number(event.target.value))} /></label>
      <div className="replaySpeed" aria-label="Playback speed">{SPEEDS.map((value) => <button className={speed === value ? "active" : ""} onClick={() => setSpeed(value)} key={value}>{value}×</button>)}</div>
    </div>
    <footer className="replayFoot"><span>{pageBounded ? `${ordered.length} EVENTS SHOWN · MORE RETAINED` : `${ordered.length} EVENTS SHOWN`}</span><b>Motion represents ledger transitions only. It does not represent network traffic volume.</b></footer>
  </section>;
}

function indicator(event: ObservationEvent): string {
  const record = event.current ?? event.previous;
  return record?.indicator ?? record?.title ?? record?.sourceRecordId ?? event.observationId;
}
