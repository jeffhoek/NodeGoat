# Fix Summary

---

## 46307fd — fix(contributions): replace eval() with parseInt()
**Severity:** CRITICAL | **OWASP:** A1 — Injection

**Problem:** `eval(req.body.preTax)`, `eval(req.body.afterTax)`, `eval(req.body.roth)` in `app/routes/contributions.js:32–34` executed arbitrary JS strings in the server process. Any authenticated user could run OS commands via `require('child_process').exec(...)`.

**Impact:** Critical — authenticated remote code execution; full server compromise.

**Root cause:** Raw Express body strings passed directly to `eval()`. Downstream `isNaN()` / range checks at line 47 were bypassable.

**Fix:** Replaced all three `eval()` calls with `parseInt(..., 10)`. Commented replacement was already present at lines 38–40.

**Tests:** Existing contributions handler test suite exercised the fix path; confirmed no regressions.

---

## 827c5be — fix(allocations): sanitize threshold to prevent NoSQL injection
**Severity:** CRITICAL | **OWASP:** A1 — Injection

**Problem:** `threshold` from `req.query.threshold` injected raw into a MongoDB `$where` clause (`app/data/allocations-dao.js:78`). Payloads like `1'; while(true){}'` caused DoS; `1'; return 1 == '1` bypassed the filter.

**Impact:** Critical — authenticated NoSQL injection; DoS or data exfiltration.

**Root cause:** `parseInt(userId)` was applied to the userId half of the query but `threshold` received no type coercion or bounds check.

**Fix:** `parseInt(threshold, 10)` with a `0 ≤ n ≤ 99` range guard before injecting into the query. Used commented fix at lines 70–75.

**Tests:** New unit test (`allocations-dao-test.js`) with 5 assertions covering injection strings, range rejection, and valid input. Written as failing tests first.

---

## 381fc41 — fix(csrf): enable csurf middleware and add tokens to all forms
**Severity:** HIGH | **OWASP:** A8 — CSRF

**Problem:** `app.use(csrf())` was commented out in `server.js:107`. No token validation anywhere. All POST routes — `/profile`, `/contributions`, `/benefits`, `/memos`, `/login` — were forgeable cross-site.

**Impact:** High — any authenticated user could be forced to perform state-changing actions by a malicious page.

**Root cause:** CSRF middleware deliberately disabled; no token generation or validation in place.

**Fix:** Uncommented `csurf` middleware in `server.js`; added `csrftoken` to `res.locals` via middleware; added `<input type="hidden" name="_csrf" value="{{ csrftoken }}">` to all five vulnerable form templates.

**Tests:** New unit test (`csrf-config-test.js`) asserting middleware is imported, registered, and all five templates contain the hidden field.

---

## 01633e4 — fix(auth): hash passwords with bcrypt on store and compare
**Severity:** HIGH | **OWASP:** A2 — Broken Authentication

**Problem:** `password: password` on insert and `fromDB === fromUser` on comparison in `app/data/user-dao.js`. Any MongoDB read (via other vulns) or DB breach exposed all passwords immediately.

**Impact:** High — full credential exposure on any DB read; mass account takeover.

**Root cause:** `bcrypt.hashSync` / `bcrypt.compareSync` calls existed but were commented out.

**Fix:** Uncommented bcrypt lines in `addUser` and `validateLogin`. Updated `artifacts/db-reset.js` to use pre-hashed seed passwords (commented hashes already present).

**Tests:** New unit test (`user-dao-test.js`) asserting bcrypt hash stored (not plaintext), correct password accepted, wrong password rejected. Written as failing tests first.

---

## ef64809 — fix(redirect): allowlist /learn redirect destination
**Severity:** HIGH | **OWASP:** A10 — Unvalidated Redirects

**Problem:** `res.redirect(req.query.url)` in `app/routes/index.js:72` with zero validation. Any URL accepted — used for phishing via trusted domain.

**Impact:** High — open redirect; attackers share `nodegoat.com/learn?url=evil.com` and victims land on attacker-controlled pages.

**Root cause:** No allowlist or validation on the `url` query parameter.

**Fix:** Defined an `ALLOWED` array of permitted domains; gated redirect with `.includes()` check; returns 400 on disallowed URLs.

**Tests:** New unit test (`open-redirect-test.js`) asserting `ALLOWED` constant exists and the redirect is gated.

---

## c7f1957 — fix(xss): enable swig autoescape and add | safe to intentional HTML
**Severity:** HIGH | **OWASP:** A3 — XSS

**Problem:** `swig.setDefaults({ autoescape: false })` in `server.js:135–142`. Every template variable rendered raw. Memos rendered user-supplied `marked` output directly into the DOM — any memo could contain `<script>` tags.

**Impact:** High — stored XSS on memos; every template variable throughout the app was a raw injection vector.

**Root cause:** Autoescape globally disabled.

**Fix:** Set `autoescape: true`. Audited templates; added `| safe` only where intentional HTML rendering was required (`memos.html` for marked output, `layout.html`/`login.html`/`signup.html` for `{{script}}`).

**Tests:** New unit test (`xss-autoescape-test.js`) asserting autoescape is enabled and each `| safe` usage is present and correct.

---

## 70acb33 — fix(session): set httpOnly: true on session cookie
**Severity:** HIGH | **OWASP:** A3/A2

**Problem:** `cookie: { httpOnly: true }` block was commented out in `server.js:78–102`. Session cookie was readable by JS — any XSS could steal it directly.

**Impact:** High — session hijacking on any successful XSS; compounds with H-4.

**Root cause:** Cookie options block commented out; httpOnly not set.

**Fix:** Uncommented `cookie: { httpOnly: true }` in session options.

**Tests:** New unit test (`session-cookie-test.js`) asserting httpOnly is set in active server.js code.

---

## b204bcf — fix(ssrf): allowlist url and symbol on research endpoint
**Severity:** HIGH | **OWASP:** A10/SSRF

**Problem:** `needle.get(req.query.url + req.query.symbol, ...)` in `app/routes/research.js:15–16`. Both params fully attacker-controlled — used to probe internal services or cloud metadata endpoints (`169.254.169.254`).

**Impact:** High — SSRF; internal service enumeration, credential theft from metadata endpoints.

**Root cause:** No validation on either query parameter.

**Fix:** Defined `ALLOWED_BASE_URL` constant; validated `req.query.url` against it; validated `req.query.symbol` with a `[A-Z]{1,5}` regex allowlist.

**Tests:** New unit test (`ssrf-research-test.js`) asserting both constants exist and validation gates are in place.

---

## bfbed1b — fix(authz): add isAdmin gate to both /benefits routes
**Severity:** HIGH | **OWASP:** A7 — Missing Function Level Access Control

**Problem:** `isAdmin` middleware existed (`app/routes/session.js:25`) but was not applied to `GET /benefits` or `POST /benefits` in `app/routes/index.js:57–60`. Any authenticated user could view and modify any user's benefit start date.

**Impact:** High — horizontal privilege escalation; authenticated non-admin can access admin-only functionality.

**Root cause:** `isLoggedIn` applied; `isAdmin` missing.

**Fix:** Added `isAdmin` to both route definitions (commented fix at lines 58–60).

**Tests:** New unit test (`benefits-access-test.js`) asserting isAdmin is present in both route middleware chains.

---

## 20c9cae — fix(session): regenerate session ID on login to prevent fixation
**Severity:** HIGH | **OWASP:** A2 — Broken Authentication

**Problem:** `req.session.userId = user._id` set directly on the existing session in `app/routes/session.js:116` without regenerating. A pre-login session ID obtained by an attacker (e.g. via network sniff on HTTP) remained valid after login.

**Impact:** High — session fixation; attacker can hijack any session they observe before login.

**Root cause:** `handleSignup` correctly called `req.session.regenerate()` at line 234; `handleLoginRequest` did not.

**Fix:** Wrapped `req.session.userId = ...` assignment in `req.session.regenerate(() => { ... res.redirect(...); })`.

**Tests:** New unit test (`session-fixation-test.js`) asserting `regenerate` is called in `handleLoginRequest`.

---

## 2543763 — fix(crypto): encrypt SSN/DOB at rest in profile-dao
**Severity:** MEDIUM | **OWASP:** A6 — Sensitive Data Exposure

**Problem:** `user.ssn` and `user.dob` written to MongoDB in plaintext in `app/data/profile-dao.js:42–91`. Any DB read or secondary vulnerability exposed raw PII.

**Impact:** Medium — SSN, DOB exposed on any DB read; compounds with other vulns.

**Root cause:** `encrypt()`/`decrypt()` helpers existed but were commented out due to three bugs: IV stored as mutable `config.iv` (lost on restart), wrong IV size (512 bytes vs 16 required by AES), wrong key size (28 bytes vs 32 required by aes-256-cbc), and a space-join bug producing malformed ciphertext.

**Fix:** Replaced broken helpers with correct implementation: `crypto.randomBytes(16)` for a fresh IV per call, `scryptSync` for a 32-byte derived key, `ivHex:cipherHex` format so IV travels with ciphertext. Uncommented encrypt-on-write and decrypt-on-read for `ssn` and `dob`.

**Tests:** New unit test (`profile-dao-encryption-test.js`) — 5 assertions: plaintext not stored, roundtrip correct for SSN and DOB, unique ciphertext per call. Written as failing tests first.

---

## e0608fd — fix(redos): remove nested quantifier in bankRouting regex
**Severity:** MEDIUM | **OWASP:** ReDoS/DoS

**Problem:** `/([0-9]+)+\#/` in `app/routes/profile.js:59`. Nested quantifiers cause exponential backtracking on digit strings with no trailing `#`. An authenticated user could stall the Node.js event loop with a ~25-char input.

**Impact:** Medium — authenticated DoS; event loop blocked until process killed.

**Root cause:** Outer `+` wrapping `([0-9]+)` — engine must try every partition of the digit sequence.

**Fix:** Removed outer `+` → `/([0-9]+)\#/`. Semantics for valid input identical.

**Tests:** New unit test (`redos-profile-routing-test.js`) asserting valid input passes, invalid rejected, and 30-digit malicious input resolves in < 100 ms. Skipped failing-test-first: running the buggy regex would hang the suite for minutes.

---

## a3caf50 — fix(config): read cookie/crypto secrets from env vars
**Severity:** MEDIUM | **OWASP:** A5 — Security Misconfiguration

**Problem:** `cookieSecret: "session_cookie_secret_key_here"` and `cryptoKey: "a_secure_key_for_crypto_here"` committed as literals in `config/env/all.js:8–9`. Anyone with repo read access could forge session cookies and had the key material for the M-1 SSN/DOB encryption.

**Impact:** Medium — session forgery and encryption key exposure for all repo readers.

**Root cause:** No env var override path; no `.env.example` to guide operators.

**Fix:** `process.env.COOKIE_SECRET || "..."` and `process.env.CRYPTO_KEY || "..."` — fallback to originals so dev works without a `.env`. Added `.env.example` documenting both vars. `.env` was already in `.gitignore`.

**Tests:** Config change — skipped failing-test-first per EXAM_NOTES. All 43 existing tests passed.

---

## ca7ffc9 — fix(xss): validate website scheme; safe href in profile
**Severity:** MEDIUM | **OWASP:** A3 — XSS

**Problem:** Two related issues in `app/routes/profile.js`:
1. `displayProfile` encoded `doc.website` with `encodeForHTML` but applied no scheme check — a stored `javascript:` URI would execute if website were ever placed in an `href`.
2. `handleProfileUpdate` error path set `firstNameSafeString = firstName` (raw POST body) and rendered it as `<a href="{{firstNameSafeString}}">`. Since `javascript:alert(1)` contains no HTML-special chars, autoescape did not protect it — reflected XSS on bankRouting validation failure.

**Impact:** Medium — (1) stored XSS risk if website added to href; (2) active reflected XSS on validation error path.

**Root cause:** No URL scheme validation on `website`; raw user input used directly as href value despite `@FIXME` comments flagging both issues.

**Fix:** (1) Blank `doc.website` unless it matches `^https?:\/\/` — removed `encodeForHTML` (redundant with autoescape for input value context). (2) Built `firstNameSafeString` as a full Google search URL using `encodeURIComponent` so it is safe in any href context.

**Tests:** New unit test (`profile-xss-test.js`) — 5 assertions: scheme validation (valid pass-through, `javascript:` blocked, `ftp:` blocked) and `firstNameSafeString` (not equal to raw input, is a safe `google.com` search URL). Written as failing tests first.
