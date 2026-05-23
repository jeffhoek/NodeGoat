# Container Security TODO

Generated from: `hadolint`, `trivy config`, `trivy fs` — 2026-05-22

Ranked by **severity × confidence × (1/fix-effort)**. All findings in
`node_modules/getos/**` are false positives — see bottom of file.

---

## Scoring key

| Factor | CRIT=4 | HIGH=3 | MED=2 | LOW=1 |
|--------|--------|--------|-------|-------|
| Confidence | HIGH=3 | MED=2 | LOW=1 | |
| Fix effort (inverted) | Easy=3 | Medium=2 | Hard=1 | |

---

## P0 — Score 36 (CRITICAL × HIGH × Easy)

### [C-1] TLS private key baked into container image

**File**: `artifacts/cert/server.key`  
**Source**: trivy-fs secret scan (`artifacts/cert/server.key` — PEM RSA private key)  
**Root cause**: The file is git-tracked (`git ls-files` confirms it) and `.dockerignore`
does not exclude `artifacts/cert/`. `COPY --chown=node . $WORKDIR` (Dockerfile:13)
copies it into every image layer.

Anyone with `docker inspect`, `docker save`, or registry pull access can extract
the private key. If this image is ever pushed to Docker Hub or a shared registry,
the key is fully compromised.

**Fix**:
1. Add `artifacts/cert/` to `.dockerignore` immediately.
2. For the app to still work, mount the cert at runtime via a Docker volume or
   inject via environment + tmpfs (pass paths as `CERT_KEY_PATH` / `CERT_CRT_PATH`).
3. If the key has ever been pushed to a registry, treat it as compromised and
   re-generate it.

```diff
# .dockerignore
+artifacts/cert/
```

**Note**: NodeGoat is intentionally vulnerable for training. If the self-signed cert
is deliberately checked in as a lab artifact, suppress the scanner finding with
a `.trivyignore` rule and document the intent — but the key must not reach a
production or shared registry.

---

## P1 — Score 24 (CRITICAL × HIGH × Medium)

### [C-2] CRITICAL npm CVEs — direct and transitive dependencies

**Source**: trivy-fs, `package-lock.json` — 10 CRITICAL findings  
**Root cause**: All stem from pinned-old dependency versions in `package.json`.
Upgrading the base image (see C-3) will not automatically fix these; each needs
an explicit package bump.

| Package | CVE | Vector | Fixed in |
|---------|-----|--------|----------|
| `bson@1.0.9` | CVE-2020-7610 | Deserialization → RCE | ≥1.1.4 |
| `minimist@0.0.8/0.0.10/1.2.0/1.2.5` | CVE-2021-44906 | Prototype pollution | ≥1.2.6 |
| `set-value@0.4.3/2.0.0` | CVE-2019-10747 | Prototype pollution | ≥2.0.1 |
| `underscore@1.9.1` | CVE-2021-23358 | Arbitrary code exec via `.template()` | ≥1.12.1 |
| `fsevents@1.2.9` | CVE-2023-45311 | Code injection | ≥1.2.11 |

`fsevents` is a macOS-only filesystem watcher. If it only appears in
`devDependencies`, it does not land in the production image (`npm install --production`).
Verify with `npm ls fsevents --production` before treating as a runtime risk.

`underscore` is a direct dependency used in templates — this is a real runtime RCE
vector if any user-controlled input reaches `_.template()`.

**Fix**: Run `npm audit fix` and pin resolutions for transitive deps that lack direct
fixes:

```jsonc
// package.json
"overrides": {
  "minimist": ">=1.2.6",
  "set-value": ">=2.0.1"
}
```

---

## P2 — Score 18 (HIGH × HIGH × Medium)

### [C-3] EOL base image: `node:12-alpine`

**File**: `Dockerfile:1`, `Dockerfile:6`  
**Source**: Dockerfile analysis  
**Root cause**: Node.js 12 reached end-of-life April 2022. No further security patches
are published for the Node 12 runtime or the npm 6.x toolchain it ships. This is the
*structural root cause* of a large fraction of the 75 CVEs in the npm scan — older
npm resolves older transitive dependency ranges.

Upgrading to a supported LTS image (node:20-alpine or node:22-alpine) will collapse
many transitive CVEs automatically via npm's newer resolution algorithm.

**Fix**:
```diff
-FROM node:12-alpine
+FROM node:20-alpine
```
Apply to both build stage and final stage. Run test suite after upgrade. Pay
attention to any deprecation warnings from Node.js API calls.

---

### [C-4] HIGH npm CVEs — actionable with fixed versions

**Source**: trivy-fs, `package-lock.json` — 39 HIGH findings (top actionable subset)

| Package | CVE | Impact | Fixed in |
|---------|-----|--------|----------|
| `body-parser@1.18.3` | CVE-2024-45590 | DoS | ≥1.20.3 |
| `path-to-regexp@0.1.7` | CVE-2024-45296 + CVE-2024-52798 | ReDoS | ≥0.1.10 |
| `mongodb@2.2.36` | GHSA-mh5c-679w-hh4r | DoS | ≥3.1.13 |
| `nconf@0.10.0/0.6.9` | CVE-2022-21803 | Prototype pollution | ≥0.11.4 |
| `semver@5.6.0/5.7.0` | CVE-2022-25883 | ReDoS | ≥5.7.2 |
| `minimatch@3.0.4` | CVE-2022-3517 | ReDoS | ≥3.0.5 |
| `marked@0.3.5` | CVE-2022-21680/21681 + others | ReDoS, XSS | ≥4.0.10 |
| `y18n@3.2.1` | CVE-2020-7774 | Prototype pollution | ≥3.2.2 |
| `ini@1.3.5` | CVE-2020-7788 | Prototype pollution | ≥1.3.6 |
| `decode-uri-component@0.2.0` | CVE-2022-38900 | DoS | ≥0.2.1 |

`marked` has multiple XSS CVEs in addition to ReDoS — if it renders any user-supplied
content to HTML it is a direct reflected-XSS vector. Check all call sites.

**Fix**: After base image upgrade (C-3), run `npm audit fix`. For packages where
`npm audit fix --force` would break API compatibility (e.g., `mongodb` 2→3 is a
breaking change), plan migration work separately.

---

### [C-5] `swig@1.4.2` — no upstream fix available

**CVE**: CVE-2023-25345 — arbitrary local file read during template rendering  
**Status**: `affected` (no fixed version from upstream)  
**Confidence**: HIGH — the CVE is confirmed against this version  

If user input can influence template file paths (e.g., `include` directives),
this allows reading arbitrary files from the container filesystem.

**Fix options**:
1. Replace `swig` with a maintained fork such as `swig-templates` and verify
   that template inputs are never user-controlled.
2. Treat template file paths as constants and add an integration test that
   asserts the template renderer cannot include files outside `views/`.

---

## P3 — Score 9 (LOW × HIGH × Easy)

### [C-6] No HEALTHCHECK in project Dockerfile

**File**: `Dockerfile`  
**Source**: trivy-config DS-0026, hadolint (both agree)  
**Impact**: Docker and orchestrators (Swarm, ECS) cannot detect a hung or crashed
Node.js process inside a running container. The container appears healthy until
the restart policy fires.

**Fix** — add one instruction before `EXPOSE`:
```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:4000/ || exit 1
```

---

### [C-7] MEDIUM npm CVEs — lower runtime exposure

| Package | CVE | Impact |
|---------|-----|--------|
| `helmet-csp@1.2.2` | GHSA-c3m8-x3cg-qm2c | CSP policy can be overridden by caller |
| `express@4.16.4` | CVE-2024-29041 | Malformed URL bypass |
| `qs@6.5.2` | CVE-2022-24999 | Prototype pollution → hang |
| `brace-expansion@1.1.11` | CVE-2026-33750 | ReDoS |
| `ms@0.7.1` | CVE-2017-20162 | ReDoS |

`helmet-csp` being out of date means the Content-Security-Policy header that the
app sets can be bypassed by a downstream middleware. Upgrade `helmet` and
`helmet-csp` together.

**Fix**: Covered by `npm audit fix` after C-3/C-4 work.

---

### [C-8] Packages with no upstream fix (`affected` status)

| Package | Advisory | Notes |
|---------|----------|-------|
| `swig@1.4.2` | CVE-2023-25345 | Covered above in C-5 |
| `utile@0.2.1/0.3.0` | NSWG-ECO-445 | Out-of-bounds read; no fix |

`utile` is a transitive dependency (via `nconf`). If `nconf` is upgraded to
≥0.11.4 (C-4), the `utile` exposure may be pulled along. Verify with
`npm ls utile` after upgrade.

---

## FALSE POSITIVES — Do Not Action

All findings flagged against paths under `node_modules/getos/**` are false positives:

| Rule | Files | Reason |
|------|-------|--------|
| DS-0002 (no USER) | `node_modules/getos/Dockerfile` and 8 test fixtures | These are test fixture Dockerfiles shipped inside the `getos` npm package. They are never built as part of this project. |
| DS-0005 (ADD vs COPY) | same | Same reason |
| DS-0017 (update without install) | same | Same reason |
| DS-0022 (MAINTAINER) | same | Same reason |
| DS-0026 (no HEALTHCHECK) | same | Same reason |
| DS-0029 (--no-install-recommends) | same | Same reason |
| DL3008/DL3009/DL3015/DL3018/DL3020/DL3032/DL3033/DL3059/DL4000/DL4006 (hadolint) | same | Same reason |

**Remediation for false positives**: Add `--skip-dirs node_modules` to both
`hadolint` and `trivy` invocations, or add a `.trivyignore` / `.hadolint.yaml`
exclude rule. This eliminates ~50 phantom findings from future scans.

```yaml
# .hadolint.yaml
ignore:
  - DL4000   # already accounted for in node_modules
trustedRegistries: []
skipFiles:
  - node_modules
```

```
# .trivyignore (or pass --skip-dirs node_modules to trivy)
# Suppress node_modules fixture Dockerfiles
```

---

## Summary table

| ID | Severity | Confidence | Fix Effort | Score | Status |
|----|----------|------------|------------|-------|--------|
| C-1 Private key in image | CRITICAL | HIGH | Easy | **36** | Open |
| C-2 CRITICAL npm CVEs | CRITICAL | HIGH | Medium | **24** | Open |
| C-3 node:12 EOL base image | HIGH | HIGH | Medium | **18** | Open |
| C-4 HIGH npm CVEs | HIGH | HIGH | Medium | **18** | Open |
| C-5 swig, no upstream fix | HIGH | HIGH | Medium | **18** | Open |
| C-6 No HEALTHCHECK | LOW | HIGH | Easy | **9** | Open |
| C-7 MEDIUM npm CVEs | MEDIUM | HIGH | Easy | **12** | Open |
| C-8 No-fix packages | LOW | HIGH | Hard | **3** | Monitor |
| node_modules/* findings | — | — | — | — | **FALSE POSITIVE** |
