# UAE PASS: what MIRA ships, and the real integration path

## What ships in this build — SIMULATED FOR DEMONSTRATION

`/signin` is a **MIRA demonstration prototype** of a national-digital-identity style sign-in. It is labelled on every screen,
is not UAE PASS, does not contact UAE PASS, and never asks for or accepts real credentials, Emirates ID numbers or OTPs.

| Step | Prototype | Real integration |
|---|---|---|
| Start | `POST /api/signin-demo/start` creates a request ID (2-minute expiry) | MIRA redirects the browser to the UAE PASS authorisation endpoint |
| QR code | encodes `MIRA-DEMO-SIGNIN:<id>` | shown by UAE PASS |
| Approval and consent | buttons on a simulated phone; consent box required | the citizen approves in the UAE PASS app |
| Result | `GET /api/signin-demo/{id}` hands out a MIRA session token **once** (no replay) for a MIRA demo account | authorisation code → server-side token exchange → user info → MIRA session |
| Availability | only with `MIRA_DEMO=1`; returns 403 otherwise | production |

The session issued is MIRA's normal one (`raqeeb/auth.py`): random 256-bit token, only its SHA-256 stored, 12 h for officials
and 30 days for citizens, logout deletes it. Automatic sign-in (the token kept by the apps) is unchanged. The apps send the token
as a `Bearer` header, never as a cookie, so cross-site requests can't ride on it (no CSRF surface); a new token is minted at every
sign-in (no session fixation).

`/signin` → *Security simulator* walks through seven fictional attack steps (SMS, look-alike address, redirect chain, OTP page,
QR poster, fake app, phone script). Every link check there runs on MIRA's real engine. The phone step is a written script:
**MIRA never places, records or spoofs calls.** Real call screening exists only in the Android app (`ScamCallScreening.kt`,
after the user makes MIRA the call-screening app), comparing numbers on the phone against analyst-confirmed numbers.

## Real integration (after authorisation)

Based on the official UAE PASS developer documentation at `https://docs.uaepass.ae`:

1. **Onboarding.** Request integration through the UAE PASS developer portal, stating the entity type (government or private).
   The onboarding team shares documentation; the service provider shares the user-journey workflow and UI mock-ups, completes
   development on staging, passes assessment, then receives production access.
2. **Client registration.** UAE PASS issues a `client_id` and `client_secret` for the registered redirect URI. Staging needs a dev
   or staging redirect URL; the production redirect URL is registered after assessment sign-off.
3. **Authorisation request.** Browser redirect to the `/idshub/authorize` endpoint (staging host `stg-id.uaepass.ae`) with
   `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state` and `acr_values`. MIRA must generate and check `state`.
4. **Callback.** UAE PASS redirects to `MIRA_UAE_PASS_REDIRECT_URI?code=…&state=…`. A new MIRA route (to be added:
   `GET /auth/uaepass/callback`) verifies `state`.
5. **Token exchange.** Server-side `POST /idshub/token` with `grant_type=authorization_code`, the `code` and the same
   `redirect_uri`, authenticated with HTTP Basic using the client credentials. Never in the browser.
6. **User identity.** Fetch the user info with the access token, map the verified identity to a MIRA citizen account, store only
   what MIRA needs (no Emirates ID unless legally required), and record consent.
7. **Session and logout.** Issue the normal MIRA session (`auth.issue_session`). Logout clears it and redirects to the UAE PASS
   logout endpoint with a registered post-logout URL.
8. **Security.** HTTPS only, `state` and nonce checks, exact redirect-URI match, secrets in the server environment
   (`MIRA_UAE_PASS_CLIENT_ID`, `MIRA_UAE_PASS_CLIENT_SECRET`, `MIRA_UAE_PASS_REDIRECT_URI`), audit every sign-in.

Status: the environment variables are reserved; the callback route and token exchange are **NOT IMPLEMENTED** and are blocked by
missing UAE PASS onboarding and credentials. Endpoint names above come from the official documentation and must be re-checked
against the version current at onboarding.
