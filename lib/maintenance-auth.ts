// Compare bearer credentials without a data-dependent token-string comparison.
export async function isAuthorizedMaintenanceBearer(header: string, configured: string | undefined): Promise<boolean> {
  if (typeof configured !== "string" || configured.length < 32) return false;
  const match = /^Bearer ([^\s]+)$/.exec(header);
  if (!match) return false;

  const encoder = new TextEncoder();
  const [providedDigest, configuredDigest] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(match[1])),
    crypto.subtle.digest("SHA-256", encoder.encode(configured)),
  ]);
  const provided = new Uint8Array(providedDigest);
  const expected = new Uint8Array(configuredDigest);
  let difference = 0;
  for (let index = 0; index < expected.length; index += 1) {
    difference |= provided[index] ^ expected[index];
  }
  return difference === 0;
}
