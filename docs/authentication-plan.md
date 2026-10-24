# Authentication and Protected Scan History

## Implemented

The dashboard remains static HTML, CSS, and browser JavaScript served by Express. `/login` and `/register` provide accessible forms. The browser obtains server-confirmed state and a synchronizer token from `GET /api/auth/me`; it stores neither session IDs nor bearer secrets in web storage. The private console redirects an unauthenticated browser to `/login`, while API access controls remain authoritative.

`POST /api/auth/register` normalizes email by trimming and lowercasing, validates a simple address shape, enforces passwords of 12 to 128 UTF-8 bytes, hashes with the maintained `argon2` package using Argon2id, and stores only the encoded hash. Normalized duplicate email returns `409`. `POST /api/auth/login` returns one generic `401` error for unknown users and incorrect passwords. Login and registration request bodies are not logged.

Sessions use `express-session` with a local `better-sqlite3` store in `sessions`, not MemoryStore. The cookie is named `secureflow.sid`, opaque, `HttpOnly`, `SameSite=Lax`, path `/`, and `Secure` according to explicit deployment configuration. Login and successful registration regenerate the session ID. Session rows enforce a 30-minute idle expiry; authenticated requests also enforce a 12-hour absolute lifetime. Logout destroys the row and expires the cookie. The session payload includes only user ID, authentication time, and CSRF token.

All state-changing JSON endpoints require a synchronizer token from the session. Supplied Origin headers must match the configured public origin, or the same request origin outside production. SameSite is defense-in-depth, not the CSRF check. No permissive credentialed CORS is enabled.

Registration is limited to five attempts per source per hour. Login is limited to five attempts per source/account bucket per 15 minutes and 50 attempts per source per 15 minutes. Rate counters are in SQLite; bucket keys are HMAC digests using the session secret. These limits work across processes sharing this SQLite database, but may need tuning for an actual deployment.

`GET /api/scans` and `GET /api/scans/:id` require authentication and filter by the session-derived user ID. `POST /api/scans` requires authentication and CSRF; it ignores any client-provided `user_id`. `POST /api/scan-upload` retains the existing public single-file upload behavior but requires a CSRF token; it is owned by the session user when authenticated, otherwise remains unowned. The scanner engine behavior and existing upload route remain unchanged.

## Report trust boundary

`POST /api/scans` accepts structurally valid caller-supplied reports and does not invoke scanners or recompute the complete policy. Such records are always stored with `verified = 0`, regardless of a submitted `PASS` or `promotion_allowed: true`. Dashboard summaries label these reports `UNVERIFIED`, exclude them from verified decision counts, and state not to use them to authorize promotion. A scanner-produced upload result is marked `verified = 1` because the API ran the local CLI and validated its output; this still does not prove scanner completeness, provenance beyond this API process, or production readiness. Authentication does not turn a client-submitted result into verified evidence.

## SQLite migration and historical data

`api/src/db.js` applies schema version 1 transactionally using SQLite `user_version`. It adds `users`, `sessions`, `auth_rate_limits`, nullable `scans.user_id` with `ON DELETE SET NULL`, `scans.verified` defaulting to `0`, and indexes. Existing scan and finding rows are retained. Old rows stay unowned and unverified; there is no first-user assignment, admin role, or automatic ownership mapping. Unowned historical records are not returned by normal account history APIs.

The migration test starts from the old scans/findings schema with representative rows, applies the migration, and confirms both records remain queryable and unowned.

## Configuration

Set `SECUREFLOW_SESSION_SECRET` to a random value of at least 32 bytes. Set `SECUREFLOW_COOKIE_SECURE=false` explicitly for local HTTP development. Production requires `NODE_ENV=production`, `SECUREFLOW_COOKIE_SECURE=true`, and an exact `SECUREFLOW_PUBLIC_ORIGIN` such as `https://secureflow.example`. Use a secret manager, not checked-in configuration. `SECUREFLOW_TRUST_PROXY_HOPS` defaults to `0`; when TLS terminates at a reverse proxy, set it only to the exact trusted hop count from `0` through `5`, and prevent direct clients from spoofing forwarded headers. The API does not infer a proxy topology. `SECUREFLOW_DB_PATH` selects the SQLite file.

## Tests and remaining limitations

The API suite covers Argon2id hash storage, duplicate and invalid registration, login success and generic failure, session rotation/logout/expiry/invalid IDs, cookie flags, CSRF and origin checks, rate limits, auth boundaries, ownership isolation, migration preservation, and unverified submitted PASS reports. Existing Python and JavaScript upload behavior is also exercised.

Authentication does not sandbox uploaded source or scanner processes. The API currently has no global upload concurrency cap, CPU/memory quota, account recovery, email verification, MFA, admin roles, retention policy, automated session/rate-counter cleanup job, or production key rotation workflow. The custom SQLite session store deletes expired rows on writes and rejects/deletes expired rows when read; operational cleanup and SQLite backup/restore procedures still need deployment-specific validation. Submitted report provenance remains unresolved and must not be used as deployment authorization.
