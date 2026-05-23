# TODO — Security Fix Backlog

Ranked by: **severity × confidence ÷ fix effort**.
Scanner provenance: semgrep, detect-secrets, pnpm-audit, pip-audit, ruff, bandit.

**Scanner false positives are called out at the bottom.**

---

## CRITICAL

### C-1 — SSJS / RCE via `eval()` on POST body ✅ Fixed
- **File:** `app/routes/contributions.js:32–34`
- **OWASP:** A1 — Injection
- **Scanners:** semgrep (2 rules, 6 findings collapsed to 3 lines)
- **Root cause:** `eval(req.body.preTax)`, `eval(req.body.afterTax)`, `eval(req.body.roth)` execute arbitrary JS strings in the server process context. An authenticated user can run OS commands.
- **Symptom vs root cause:** These three lines are the root cause. The downstream `isNaN()` / range checks at line 47 are symptoms of trying to work around it — they can be bypassed.
- **Evidence:** Confirmed in code. `eval()` receives raw Express body strings with no pre-sanitization.
- **Fix:** `parseInt(req.body.preTax, 10)` × 3. Commented fix already present at line 38–40.
- **Effort:** Low (3-line change)

---

### C-2 — NoSQL injection via `$where` with unsanitized `threshold` ✅ Fixed
- **File:** `app/data/allocations-dao.js:78`
- **OWASP:** A1 — Injection
- **Scanners:** NOT caught by any scanner (gap)
- **Root cause:** `$where: \`this.userId == ${parsedUserId} && this.stocks > '${threshold}'\`` — `threshold` comes directly from `req.query.threshold` with no type check. An attacker can inject arbitrary JS into the MongoDB `$where` clause (e.g. `1'; while(true){}'` for DoS, or `1'; return 1 == '1` to bypass the filter).
- **Symptom vs root cause:** The `parsedUserId = parseInt(userId)` on line 58 is a correct fix for the userId half but the `threshold` parameter is the separate unfixed root cause.
- **Fix:** `parseInt(threshold, 10)` and validate `0 ≤ n ≤ 99` before injecting into query. Commented fix at line 70–75.
- **Effort:** Low (6-line change)

---

## HIGH

### H-1 — No CSRF protection on any state-changing form ✅ Fixed
- **File:** `server.js:107–113` (root cause); symptoms in all POST routes and 5 templates
- **OWASP:** A8 — CSRF
- **Scanners:** semgrep (`express-check-csurf-middleware-usage`); semgrep also fires django-no-csrf-token on `benefits.html`, `login.html`, `memos.html` — the django rule is a false positive for the rule match but the underlying CSRF issue is **real**.
- **Root cause:** `app.use(csrf())` is commented out in `server.js:107`. No token validation anywhere.
- **Symptoms:** All forms — `/profile`, `/contributions`, `/benefits`, `/memos`, `/login` — are vulnerable to cross-site request forgery.
- **Fix:** Uncomment `csurf` middleware + add `csrftoken` to session locals + add `<input type="hidden" name="_csrf" value="{{ csrftoken }}">` to each form template. Already templated in the commented code.
- **Effort:** Medium (server.js + ~5 templates)

---

### H-2 — Plaintext password storage ✅ Fixed
- **File:** `app/data/user-dao.js:25` (storage), `user-dao.js:61` (comparison)
- **OWASP:** A2 — Broken Authentication
- **Scanners:** NOT caught by any scanner (gap)
- **Root cause:** `password: password` on insert; `fromDB === fromUser` on comparison. `bcrypt.hashSync` / `bcrypt.compareSync` calls exist but are commented out.
- **Symptom vs root cause:** This is the root cause. Any MongoDB read (via other vulns) or DB breach exposes all passwords immediately.
- **Fix:** Uncomment bcrypt lines in `addUser` and `validateLogin`. Update `artifacts/db-reset.js` to use hashed passwords (commented hashes already present at lines 19/28/36).
- **Effort:** Medium (user-dao.js + db-reset.js; requires re-seeding DB)

---

### H-3 — Open redirect — `GET /learn` ✅ Fixed
- **File:** `app/routes/index.js:72`
- **OWASP:** A10 — Unvalidated Redirects and Forwards
- **Scanners:** semgrep (`express-open-redirect`)
- **Root cause:** `res.redirect(req.query.url)` with zero validation. Any URL accepted.
- **Fix:** Validate against an allowlist of known-good domains or remove the dynamic redirect entirely.
- **Effort:** Low (1–5 lines)

---

### H-4 — Swig `autoescape: false` — stored XSS on memos (and elsewhere) ✅ Fixed
- **File:** `server.js:135–142` (root cause); `app/views/memos.html` (primary impact surface)
- **OWASP:** A3 — XSS
- **Scanners:** NOT caught by any scanner (gap)
- **Root cause:** `swig.setDefaults({ autoescape: false })`. Every template variable is rendered raw. The memos page renders user-supplied content with `marked` (Markdown → HTML), then injects it directly into the DOM. Any memo can contain `<script>` tags.
- **Symptoms:** All template variables throughout the app are potential XSS vectors; memos is the most obvious stored-XSS path.
- **Fix:** `autoescape: true`. Then audit templates for places that intentionally render HTML (memos uses `marked` output — needs `| safe` filter only there, with DOMPurify or marked's own sanitizer ensuring it is safe first).
- **Effort:** Medium (1-line toggle is easy; template audit to avoid breaking intentional HTML rendering takes more care)

---

### H-5 — Session cookie has no `httpOnly` flag ✅ Fixed
- **File:** `server.js:78–102`
- **OWASP:** A3 / A2
- **Scanners:** semgrep (`express-cookie-session-no-httponly`)
- **Root cause:** `cookie: { httpOnly: true }` block is commented out. If any XSS fires (H-4), the session cookie is directly readable by JS.
- **Symptom vs root cause:** This is a separate root cause from H-4 (XSS), but they compound. Fixing H-4 without H-5 still leaves the cookie accessible.
- **Fix:** Add `cookie: { httpOnly: true }` to session options. Commented fix at line 93.
- **Effort:** Low (1-line uncomment + test)

---

### H-6 — SSRF — research endpoint fetches arbitrary attacker-controlled URL ✅ Fixed
- **File:** `app/routes/research.js:15–16`
- **OWASP:** A10 / SSRF
- **Scanners:** NOT caught by any scanner (gap)
- **Root cause:** `needle.get(req.query.url + req.query.symbol, ...)` — both `url` and `symbol` are fully attacker-controlled. Can be used to probe internal services, cloud metadata endpoints (e.g. `http://169.254.169.254/`), or exfiltrate data.
- **Fix:** Validate `url` against an allowlist of permitted stock-data domains; reject or strip `symbol` of special characters.
- **Effort:** Medium

---

### H-7 — Missing `isAdmin` gate on `/benefits` ✅ Fixed
- **File:** `app/routes/index.js:57–60`
- **OWASP:** A7 — Missing Function Level Access Control
- **Scanners:** NOT caught by any scanner (gap)
- **Root cause:** The `isAdmin` middleware exists (`session.js:25`) but is not applied to the benefits routes. Any authenticated user can access and modify any user's benefit start date.
- **Fix:** Change `app.get("/benefits", isLoggedIn, ...)` → `app.get("/benefits", isLoggedIn, isAdmin, ...)` (commented fix at line 58–60).
- **Effort:** Low (2-line change)

---

### H-8 — Session not regenerated on login — session fixation ✅ Fixed
- **File:** `app/routes/session.js:116`
- **OWASP:** A2 — Broken Authentication
- **Scanners:** NOT caught by any scanner (gap)
- **Root cause:** `req.session.userId = user._id` is set directly on the existing session without regenerating a new session ID. An attacker who obtains a pre-login session ID (e.g. via network sniffing on HTTP) retains that session after the victim logs in.
- **Note:** `handleSignup` correctly calls `req.session.regenerate()` at line 234 — this is only missing in `handleLoginRequest`.
- **Fix:** Wrap `req.session.userId = ...` in `req.session.regenerate(() => { req.session.userId = user._id; res.redirect(...); })`.
- **Effort:** Low

---

## MEDIUM

### M-1 — Sensitive data (SSN, DOB, bank account) stored in plaintext ✅ Fixed
- **File:** `app/data/profile-dao.js:42–91`
- **OWASP:** A6 — Sensitive Data Exposure
- **Scanners:** NOT caught by any scanner (gap)
- **Root cause:** `user.ssn`, `user.dob`, `user.bankAcc`, `user.bankRouting` written directly to MongoDB without encryption. The `encrypt()` / `decrypt()` helpers are implemented but commented out.
- **Fix:** Uncomment encrypt/decrypt in `profile-dao.js`. Note: the current `createIV()` implementation stores `config.iv` as a mutable module-level property — that's a bug in the commented fix that must be addressed before uncommenting (IV must be stored alongside the ciphertext, not in config).
- **Effort:** Medium (crypto fix requires care to avoid breaking the decrypt path)

---

### M-2 — ReDoS — catastrophic backtracking in bank routing validation ✅ Fixed
- **File:** `app/routes/profile.js:59`
- **OWASP:** ReDoS / DoS
- **Scanners:** NOT caught by any scanner (gap)
- **Root cause:** `/([0-9]+)+\#/` — nested quantifiers. Input like `"111111111111111111111"` (no trailing `#`) causes exponential backtracking. An authenticated user can stall the Node.js event loop.
- **Fix:** Remove the outer `+`: `/([0-9]+)\#/`. Commented fix at line 57.
- **Effort:** Low (1-line change)

---

### M-3 — Hardcoded cookie secret and crypto key ✅ Fixed
- **File:** `config/env/all.js:7–10`
- **OWASP:** A5 — Security Misconfiguration
- **Scanners:** detect-secrets (`Secret Keyword` at line 8)
- **Root cause:** `cookieSecret: "session_cookie_secret_key_here"` and `cryptoKey: "a_secure_key_for_crypto_here"` are literal strings committed to source. Any session cookie signed with this known secret can be forged.
- **Fix:** Replace with `process.env.COOKIE_SECRET` and `process.env.CRYPTO_KEY`; document in `.env.example`.
- **Effort:** Low

---

### M-4 — Wrong ESAPI encoding context for `website` field ✅ Fixed
- **File:** `app/routes/profile.js:28`
- **OWASP:** A3 — XSS
- **Scanners:** NOT caught by any scanner (gap)
- **Root cause:** `ESAPI.encoder().encodeForHTML(doc.website)` — but `website` is rendered as a URL in an `<a href>` attribute. HTML encoding does not prevent `javascript:` URIs or other URL-context injection. The comment at line 25 explicitly flags this as a known bug.
- **Fix:** Replace with `ESAPI.encoder().encodeForURL(doc.website)` and also validate that the URL starts with `http://` or `https://`.
- **Effort:** Low

---

### M-5 — Log injection — unsanitized `userName` written to console
- **File:** `app/routes/session.js:73`
- **OWASP:** A1 — Log Injection
- **Scanners:** NOT caught by any scanner (gap)
- **Root cause:** `console.log("Error: attempt to login with invalid user: ", userName)` — `userName` is raw user input. CRLF characters can forge log lines.
- **Fix:** `userName.replace(/(\r\n|\r|\n)/g, '_')` before logging. Commented fix at line 69–79.
- **Effort:** Low

---

### M-6 — Default session cookie name (`connect.sid`)
- **File:** `server.js:78`
- **OWASP:** A5 — Security Misconfiguration
- **Scanners:** semgrep (`express-cookie-session-default-name`)
- **Root cause:** No `key:` option set in session config. Exposes server technology fingerprint.
- **Fix:** Add `key: "sessionId"` (commented fix at line 89).
- **Effort:** Low

---

### M-7 — HTTP only — no TLS
- **File:** `server.js:145`
- **OWASP:** A6 — Sensitive Data Exposure
- **Scanners:** semgrep (`using-http-server`); also flagged by `express-cookie-session-no-secure`
- **Root cause:** `http.createServer(app)`. Session cookies, passwords, SSNs, bank data all transit in plaintext. HTTPS setup is implemented but commented out (lines 19–28, 150–155).
- **Note:** The `secure: true` cookie flag (semgrep `express-cookie-session-no-secure`) is a **symptom** — it only becomes meaningful once HTTPS is active. Fix both together.
- **Fix:** Uncomment `https.createServer(httpsOptions, app)` block; add `secure: true` to cookie config. The self-signed cert in `artifacts/cert/` is suitable for dev.
- **Effort:** Low (uncomment blocks); Medium for prod (real cert provisioning)

---

### M-8 — Hardcoded seed credentials committed to source
- **File:** `artifacts/db-reset.js:16–37`
- **OWASP:** A2 — Broken Authentication / Hardcoded Credentials
- **Scanners:** detect-secrets (`Secret Keyword` at lines 18, 27, 35)
- **Root cause:** `"password": "Admin_123"` etc. in plain JS. Once bcrypt is enabled (H-2), this file should use the pre-computed hashes (already in comments at lines 19, 28, 36) instead of plaintexts.
- **Effort:** Low (swap plaintexts for hashed values after H-2 is done)
- **Dependency:** H-2 must land first.

---

## LOW / INFORMATIONAL

### L-1 — Insecure Direct Object Reference (IDOR) on allocations
- **File:** `app/routes/allocations.js:18`
- **OWASP:** A4 — Insecure Direct Object Reference
- **Scanners:** NOT caught by any scanner (gap)
- **Root cause:** `userId` read from `req.params` (URL) instead of `req.session`. Any logged-in user can view any other user's allocations by changing the URL `userId`.
- **Fix:** Use `req.session.userId` (commented fix at line 13–14).
- **Effort:** Low

---

### L-2 — `saveUninitialized: true` and `resave: true` on session
- **File:** `server.js:84–85`
- **OWASP:** A5 — Session Management
- **Scanners:** NOT flagged
- **Root cause:** Both options create/update sessions unconditionally, enabling session-riding and unnecessary session proliferation.
- **Fix:** Set both to `false` for standard hardening.
- **Effort:** Low

---

### L-3 — Private key committed to repository
- **File:** `artifacts/cert/server.key`
- **Scanners:** semgrep (`detected-private-key`); detect-secrets (`Private Key`)
- **Assessment:** This is an intentional self-signed **demo cert** for the dev HTTPS path. It is not a production credential. However, it is in git history and would trigger automated secret scanners in any real pipeline.
- **Fix:** Move to `.gitignore`; generate at first use or document that it is intentionally public. For a training app, acceptable as-is if `.gitignore` is updated to prevent real cert accidents.
- **Effort:** Low

---

### L-4 — Session cookie has no `expires` / `maxAge`
- **File:** `server.js:78`
- **Scanners:** semgrep (`express-cookie-session-no-expires`)
- **Root cause:** Sessions never expire on the client side.
- **Fix:** Add `cookie: { maxAge: 3600000 }` (1 hour).
- **Effort:** Low

---

### L-5 — `x-powered-by` header exposes Express
- **File:** `server.js` (implicit — Express default)
- **OWASP:** A5
- **Scanners:** NOT caught
- **Fix:** `app.disable("x-powered-by")`. Commented fix at line 42.
- **Effort:** Low (1 line)

---

### L-6 — Helmet headers not enabled
- **File:** `server.js:40–65`
- **OWASP:** A5 — Security Misconfiguration
- **Scanners:** NOT caught
- **Root cause:** `helmet` is installed but entirely commented out. Missing: frameguard (clickjacking), noCache, HSTS (when HTTPS is enabled), CSP.
- **Fix:** Uncomment helmet block (after M-7 / HTTPS is done).
- **Effort:** Low

---

### L-7 — `dont-sniff-mimetype` not enabled
- **File:** `server.js:14` (import commented out), `server.js:65` (usage commented out)
- **Fix:** Uncomment.
- **Effort:** Low

---

## FALSE POSITIVES

The following scanner findings are **not real issues in this codebase** and should be suppressed or ignored:

| Finding | Scanner | Reason |
|---|---|---|
| All 60 bandit findings | bandit | Every finding is in `node_modules/npm/node_modules/node-gyp/gyp/pylib/gyp/` — Python files inside npm's bundled build tool. Not application code. bandit was run against the wrong scope. |
| `artifacts/db-reset.js` — bcrypt hash detected | semgrep `detected-bcrypt-hash` | These are **commented-out** example bcrypt hashes in code comments (`// "password": "$2a$10$..."`), not active secrets. |
| `app/routes/session.js:61` — Secret Keyword | detect-secrets | Line 61 is `const invalidPasswordErrorMessage = "Invalid password"`. The keyword "password" in a variable name triggers this. Not a secret. |
| `app/routes/session.js:172` — Secret Keyword | detect-secrets | Line 172 is `const PASS_RE = /^.{1,20}$/`. Variable name contains "PASS". Not a secret. |
| `app/views/tutorial/a2.html:153` — Secret Keyword | detect-secrets | Tutorial page showing example auth code. Educational content, not a live secret. |
| `app/views/tutorial/a3.html:176` — Secret Keyword | detect-secrets | Same — tutorial content. |
| `app/views/tutorial/a2.html`, `a5.html` — plaintext HTTP links | semgrep `plaintext-http-link` | These are reference links in tutorial documentation (Wikipedia, nodejs.org blog, etc.). Not app transport security. |
| `app/views/benefits.html`, `login.html`, `memos.html` — django-no-csrf-token | semgrep | Wrong rule family (Django) applied to Swig templates. The underlying CSRF issue is real (H-1), but this specific signal is a false positive. |
| `config/env/development.js:6`, `config/env/test.js:6` — Secret Keyword | detect-secrets | ZAP API key `v9dn0balpqas1pcc281tn5ood1` is the well-known public default in OWASP ZAP documentation. Not a sensitive credential. |
| `test/security/profile-test.js:37` — Secret Keyword | detect-secrets | `var sutUserPassword = "User1_123"` — known test credential for the intentionally vulnerable seed data. Already in public repo. |
| `docker-compose.yml` — no-new-privileges, writable filesystem | semgrep | Dev-only compose file for local MongoDB. Container hardening concerns are valid in production but out of scope for this training app. |
| pnpm-audit | pnpm-audit | No `pnpm-lock.yaml` — project uses npm. Not applicable. |
| ruff | ruff | No Python source files in project. Not applicable. |
| pip-audit | pip-audit | Clean — no Python deps with known CVEs. |

---

## SCANNER COVERAGE GAPS

Semgrep missed the following confirmed vulnerabilities found by manual review:

- C-2 NoSQL injection (`$where` + raw threshold)
- H-4 Swig autoescape disabled (stored XSS root cause)
- H-6 SSRF in research route
- H-7 Missing `isAdmin` gate
- H-8 Session fixation on login
- M-1 Sensitive data plaintext storage
- M-2 ReDoS
- M-4 Wrong ESAPI encoding context
- M-5 Log injection
- L-1 IDOR on allocations

These gaps mean scanner-only coverage would leave more than half the real vulnerabilities unfixed.
