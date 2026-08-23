import { env } from "cloudflare:workers";

export type CredentialKey = "THREATFOX_AUTH_KEY" | "URLHAUS_AUTH_KEY" | "MALWAREBAZAAR_AUTH_KEY";

export function getCredential(key: CredentialKey): string | undefined {
  const value = (env as unknown as Record<string, unknown>)[key];
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

export function getDatabase(): D1Database | undefined {
  return (env as unknown as { DB?: D1Database }).DB;
}
