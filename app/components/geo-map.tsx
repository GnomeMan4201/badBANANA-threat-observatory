"use client";
import { useEffect, useRef } from "react";
import { feature } from "topojson-client";
import countries from "world-atlas/countries-110m.json";
import type { FeatureCollection, GeoJsonProperties, Geometry } from "geojson";
import type { GeometryCollection, Topology } from "topojson-specification";
import type { GeoPayload, GeoPoint, NormalizedObservation } from "../../lib/threat-types";

const topology = countries as unknown as Topology<{ countries: GeometryCollection }>;
const world = feature(topology, topology.objects.countries) as unknown as FeatureCollection<Geometry, GeoJsonProperties>;

interface Marker {
  latitude: number;
  longitude: number;
  points: GeoPoint[];
}

export function GeoMap({ payload, loading, error, records, onSelect }: {
  payload: GeoPayload | null;
  loading: boolean;
  error: string | null;
  records: NormalizedObservation[];
  onSelect(record: NormalizedObservation): void;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const selectRef = useRef(onSelect);
  useEffect(() => { selectRef.current = onSelect; }, [onSelect]);

  useEffect(() => {
    const canvas = canvasRef.current;
    const context = canvas?.getContext("2d");
    if (!canvas || !context) return;
    const markers = clusterPoints(payload?.points ?? []);
    const recordsById = new Map([...(payload?.records ?? []), ...records].map((record) => [record.id, record]));
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let width = 1, height = 1, dpr = 1, frame = 0, hover = -1;

    const resize = () => {
      const box = canvas.getBoundingClientRect();
      dpr = Math.min(2, window.devicePixelRatio || 1);
      width = Math.max(1, box.width); height = Math.max(1, box.height);
      canvas.width = Math.round(width * dpr); canvas.height = Math.round(height * dpr);
    };
    const markerAt = (clientX: number, clientY: number) => {
      const box = canvas.getBoundingClientRect();
      const x = clientX - box.left, y = clientY - box.top;
      let found = -1, distance = 18;
      markers.forEach((marker, index) => {
        const projected = project(marker.longitude, marker.latitude, width, height);
        const candidate = Math.hypot(projected.x - x, projected.y - y);
        if (candidate < distance) { distance = candidate; found = index; }
      });
      return found;
    };
    const move = (event: PointerEvent) => { hover = markerAt(event.clientX, event.clientY); canvas.style.cursor = hover >= 0 ? "pointer" : "crosshair"; };
    const leave = () => { hover = -1; };
    const select = (event: PointerEvent) => {
      const index = markerAt(event.clientX, event.clientY);
      const observationId = index >= 0 ? markers[index].points[0]?.observationIds[0] : undefined;
      const record = observationId ? recordsById.get(observationId) : undefined;
      if (record) selectRef.current(record);
    };
    const keydown = (event: KeyboardEvent) => {
      if (!markers.length) return;
      if (event.key === "ArrowRight" || event.key === "ArrowDown") hover = (hover + 1) % markers.length;
      else if (event.key === "ArrowLeft" || event.key === "ArrowUp") hover = (hover - 1 + markers.length) % markers.length;
      else if (event.key === "Home") hover = 0;
      else if (event.key === "Enter" || event.key === " ") {
        const observationId = hover >= 0 ? markers[hover].points[0]?.observationIds[0] : undefined;
        const record = observationId ? recordsById.get(observationId) : undefined;
        if (record) selectRef.current(record);
      } else return;
      event.preventDefault();
    };
    const observer = new ResizeObserver(resize);
    observer.observe(canvas); resize();
    canvas.addEventListener("pointermove", move);
    canvas.addEventListener("pointerleave", leave);
    canvas.addEventListener("pointerup", select);
    canvas.addEventListener("keydown", keydown);

    const drawFrame = (time: number) => {
      drawMap(context, width, height, dpr, markers, hover, reduced ? 0 : time);
      frame = requestAnimationFrame(drawFrame);
    };
    frame = requestAnimationFrame(drawFrame);
    return () => {
      cancelAnimationFrame(frame); observer.disconnect();
      canvas.removeEventListener("pointermove", move);
      canvas.removeEventListener("pointerleave", leave);
      canvas.removeEventListener("pointerup", select);
      canvas.removeEventListener("keydown", keydown);
    };
  }, [payload, records]);

  return <div className="geoField">
    <canvas ref={canvasRef} tabIndex={0} role="application" aria-label={error ? "Geographic enrichment unavailable; no geolocated count is claimed." : loading || !payload ? "Geographic enrichment results unresolved; no geolocated count is claimed." : `Geographic map of ${payload.points.length} enriched public IP observations. Use arrow keys to move between plotted locations and Enter to inspect.`} />
    {loading && !payload && <div className="geoState"><b>ENRICHING PUBLIC IP OBSERVATIONS</b><span>Reading the persistent cache and resolving a bounded set of new addresses.</span></div>}
    {loading && payload && <div className="geoProgress">ENRICHING <b>{payload.pending}</b> REMAINING</div>}
    {!loading && error && <div className="geoState error"><b>GEO ENRICHMENT UNAVAILABLE</b><span>{error}</span></div>}
    {!loading && !error && payload && !payload.points.length && <div className="geoState"><b>NO GEOLOCATED PUBLIC IPs</b><span>{payload.candidates ? "Provider results are unavailable for the current candidates." : "No validated public IP observations exist in this window."}</span></div>}
    <div className="geoAccuracy">IP GEOLOCATION IS APPROXIMATE · NOT ACTOR LOCATION OR ATTRIBUTION</div>
  </div>;
}

function clusterPoints(points: GeoPoint[]): Marker[] {
  const clusters = new Map<string, Marker>();
  for (const point of points) {
    const key = `${point.latitude.toFixed(2)}:${point.longitude.toFixed(2)}`;
    const current = clusters.get(key);
    if (current) current.points.push(point);
    else clusters.set(key, { latitude: point.latitude, longitude: point.longitude, points: [point] });
  }
  return [...clusters.values()];
}

function drawMap(ctx: CanvasRenderingContext2D, width: number, height: number, dpr: number, markers: Marker[], hover: number, time: number) {
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);
  const ocean = ctx.createRadialGradient(width * .48, height * .46, 20, width * .48, height * .46, width * .68);
  ocean.addColorStop(0, "#111815"); ocean.addColorStop(.55, "#090c0a"); ocean.addColorStop(1, "#050605");
  ctx.fillStyle = ocean; ctx.fillRect(0, 0, width, height);
  drawGrid(ctx, width, height);
  ctx.fillStyle = "#171b16"; ctx.strokeStyle = "#515449"; ctx.lineWidth = .65;
  for (const item of world.features) drawGeometry(ctx, item.geometry, width, height);

  markers.forEach((marker, index) => {
    const point = project(marker.longitude, marker.latitude, width, height);
    const count = marker.points.reduce((total, entry) => total + entry.observationIds.length, 0);
    const radius = Math.min(15, 4.5 + Math.sqrt(count) * 2.1);
    const active = index === hover;
    const pulse = time ? (time * .0013 + index * .37) % 1 : .45;
    ctx.globalAlpha = .34 * (1 - pulse);
    ctx.strokeStyle = active ? "#fff2c8" : "#dfc44a";
    ctx.lineWidth = 1;
    ctx.beginPath(); ctx.arc(point.x, point.y, radius + 5 + pulse * 13, 0, Math.PI * 2); ctx.stroke();
    ctx.globalAlpha = 1;
    ctx.shadowColor = active ? "#fff2c8" : "#dfc44a"; ctx.shadowBlur = active ? 18 : 10;
    ctx.fillStyle = active ? "#fff2c8" : "#dfc44a";
    ctx.beginPath(); ctx.arc(point.x, point.y, radius + (active ? 2 : 0), 0, Math.PI * 2); ctx.fill();
    ctx.shadowBlur = 0; ctx.strokeStyle = "#090a08"; ctx.lineWidth = 1.5; ctx.stroke();
    if (count > 1) {
      ctx.fillStyle = "#090907"; ctx.font = "700 9px ui-monospace, monospace"; ctx.textAlign = "center"; ctx.textBaseline = "middle";
      ctx.fillText(String(count), point.x, point.y + .5);
    }
  });
  if (hover >= 0 && markers[hover]) drawTooltip(ctx, markers[hover], width, height);
  ctx.globalAlpha = 1;
}

function drawGrid(ctx: CanvasRenderingContext2D, width: number, height: number) {
  ctx.strokeStyle = "rgba(216,208,184,.09)"; ctx.lineWidth = .5; ctx.setLineDash([2, 5]);
  for (let longitude = -150; longitude <= 150; longitude += 30) {
    const start = project(longitude, -75, width, height), end = project(longitude, 75, width, height);
    ctx.beginPath(); ctx.moveTo(start.x, start.y); ctx.lineTo(end.x, end.y); ctx.stroke();
  }
  for (let latitude = -60; latitude <= 60; latitude += 30) {
    const start = project(-180, latitude, width, height), end = project(180, latitude, width, height);
    ctx.beginPath(); ctx.moveTo(start.x, start.y); ctx.lineTo(end.x, end.y); ctx.stroke();
  }
  ctx.setLineDash([]);
}

function drawGeometry(ctx: CanvasRenderingContext2D, geometry: Geometry, width: number, height: number) {
  if (geometry.type !== "Polygon" && geometry.type !== "MultiPolygon") return;
  const polygons = geometry.type === "Polygon" ? [geometry.coordinates] : geometry.coordinates;
  for (const polygon of polygons) {
    ctx.beginPath();
    for (const ring of polygon) {
      let previousX: number | undefined;
      ring.forEach(([longitude, latitude], index) => {
        const point = project(longitude, latitude, width, height);
        if (index === 0 || (previousX !== undefined && Math.abs(point.x - previousX) > width * .5)) ctx.moveTo(point.x, point.y);
        else ctx.lineTo(point.x, point.y);
        previousX = point.x;
      });
      ctx.closePath();
    }
    ctx.fill("evenodd"); ctx.stroke();
  }
}

function drawTooltip(ctx: CanvasRenderingContext2D, marker: Marker, width: number, height: number) {
  const point = project(marker.longitude, marker.latitude, width, height);
  const first = marker.points[0];
  const count = marker.points.reduce((total, entry) => total + entry.observationIds.length, 0);
  const lines = [
    [first.city, first.region, first.country].filter(Boolean).join(", "),
    `${count} OBSERVATION${count === 1 ? "" : "S"} · ${marker.points.length} IP${marker.points.length === 1 ? "" : "s"}`,
    [...new Set(marker.points.flatMap((entry) => entry.sources))].join(" · ").toUpperCase(),
    first.organization ?? first.asn ?? "NETWORK NOT PROVIDED",
    `GEO PROVIDER · ${first.provider}`,
  ];
  ctx.font = "9px ui-monospace, monospace";
  const boxWidth = Math.min(290, Math.max(190, ...lines.map((line) => ctx.measureText(line).width + 24)));
  const x = Math.min(width - boxWidth - 8, Math.max(8, point.x + 14));
  const y = Math.min(height - 104, Math.max(8, point.y - 52));
  ctx.fillStyle = "rgba(7,8,7,.94)"; ctx.strokeStyle = "#77715f"; ctx.lineWidth = 1;
  ctx.fillRect(x, y, boxWidth, 94); ctx.strokeRect(x, y, boxWidth, 94);
  lines.forEach((line, index) => { ctx.fillStyle = index === 0 ? "#eee9d7" : index === 1 ? "#dfc44a" : "#9b978b"; ctx.fillText(line, x + 12, y + 17 + index * 16); });
}

function project(longitude: number, latitude: number, width: number, height: number) {
  const paddingX = Math.max(10, width * .025), paddingY = Math.max(18, height * .08);
  const mapWidth = width - paddingX * 2, mapHeight = height - paddingY * 2;
  return { x: paddingX + ((longitude + 180) / 360) * mapWidth, y: paddingY + ((90 - latitude) / 180) * mapHeight };
}
