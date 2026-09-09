# Independent release verification

This repository exposes one supported verification entry point:

```bash
npm run verify
```

The verifier is intentionally narrow. It does not require Cloudflare credentials, trigger ingestion, mutate production data, or claim that upstream feeds were independently validated. It verifies the checked-out source and its deterministic local gates.

## What it records

Before running the gates, the verifier prints:

- the checked-out Git commit SHA;
- Node.js and npm versions;
- the SHA-256 digest of `package-lock.json` when a local SHA-256 utility is available;
- a warning when tracked working-tree modifications are present.

This gives an external verifier enough context to identify the source state and dependency lockfile used for the run.

## Verification gates

`npm run verify` executes, in order:

1. `npm ci`
2. `npm audit --omit=dev --audit-level=high`
3. `npm audit --audit-level=high`
4. `npm run lint`
5. `npm test`

`npm test` performs a production build before running the deterministic Node test suite. This is required because some integrity checks inspect built client artifacts, including the client-secret isolation boundary.

Any failed command terminates the verifier with a non-zero exit status. A successful run ends with:

```text
verification: PASS
```

## Clean-room procedure

For the strongest reproduction, use a fresh clone and a pinned release or commit:

```bash
git clone https://github.com/GnomeMan4201/badBANANA-threat-observatory.git
cd badBANANA-threat-observatory
git checkout <release-tag-or-commit>
npm run verify
```

Record the verifier preamble and final result together. Do not report a run from a modified working tree as a pristine reproduction.

## Evidence boundary

A passing local verification supports only the following claims:

- the lockfile can be installed by npm in the verifier environment;
- configured high-severity dependency audits pass at run time;
- the repository lint gate passes;
- the production build completes;
- the deterministic test suite passes against that checkout.

It does not prove continuous upstream availability, Cloudflare account configuration, D1 production state, or the correctness of third-party threat-intelligence sources beyond the repository's own validation and test boundaries.
