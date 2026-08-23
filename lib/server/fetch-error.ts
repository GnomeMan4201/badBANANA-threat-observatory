export class UpstreamHttpError extends Error {
  readonly retryAfterMs?: number;

  constructor(status: number, retryAfter: string | null) {
    super(`Upstream HTTP ${status}`);
    this.name = "UpstreamHttpError";
    this.retryAfterMs = parseRetryAfter(retryAfter);
  }
}

export function assertUpstreamOk(response: Response): void {
  if (!response.ok) throw new UpstreamHttpError(response.status, response.headers.get("Retry-After"));
}

function parseRetryAfter(value: string | null): number | undefined {
  if (!value) return undefined;
  if (/^\d+$/.test(value)) return Number(value) * 1_000;
  const date = Date.parse(value);
  return Number.isNaN(date) ? undefined : Math.max(0, date - Date.now());
}
