#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

printf 'badBANANA Threat Observatory release verification\n'
printf 'repository: %s\n' "$ROOT_DIR"
printf 'commit: %s\n' "$(git rev-parse HEAD 2>/dev/null || printf 'unavailable')"
printf 'node: %s\n' "$(node --version)"
printf 'npm: %s\n' "$(npm --version)"

node - <<'NODE'
const [major, minor, patch] = process.versions.node.split('.').map(Number);
const ok = major > 22 || (major === 22 && (minor > 13 || (minor === 13 && patch >= 0)));
if (!ok) {
  console.error(`Node ${process.versions.node} is unsupported; require >=22.13.0`);
  process.exit(1);
}
NODE

if command -v sha256sum >/dev/null 2>&1; then
  printf 'package-lock.sha256: '
  sha256sum package-lock.json | awk '{print $1}'
elif command -v shasum >/dev/null 2>&1; then
  printf 'package-lock.sha256: '
  shasum -a 256 package-lock.json | awk '{print $1}'
else
  printf 'package-lock.sha256: unavailable (no sha256sum/shasum)\n'
fi

if ! git diff --quiet -- 2>/dev/null || ! git diff --cached --quiet -- 2>/dev/null; then
  printf 'warning: tracked working tree modifications are present; results are not from a pristine checkout\n' >&2
fi

printf '\n[1/5] clean dependency install\n'
npm ci

printf '\n[2/5] production dependency audit\n'
npm audit --omit=dev --audit-level=high

printf '\n[3/5] full dependency audit\n'
npm audit --audit-level=high

printf '\n[4/5] lint\n'
npm run lint

printf '\n[5/5] production build + deterministic test suite\n'
npm test

printf '\nverification: PASS\n'
printf 'commit: %s\n' "$(git rev-parse HEAD 2>/dev/null || printf 'unavailable')"
