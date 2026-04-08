# Vouch Server OIDC Compliance Plan

Updated after second test run on 2026-04-07 against the OpenID Foundation Conformance Suite.

## Test Results Summary

### OIDC Dynamic (`oidcc-dynamic-certification-test-plan`)
- 6 passed, 11 failed, 6 skipped (23 modules total)

### OIDC Form Post (`oidcc-formpost-basic-certification-test-plan`)
- 22 passed, 1 failed, 3 review, 3 warning, 9 skipped (38 modules total)

---

## Remaining Implementation Tasks

Tasks are ordered by impact and grouped by the area of the Vouch server that needs changes.

---

### Task 1: Form post error responses (LOW effort — fixes 1 formpost test)

**What:** When `response_mode=form_post` is requested, error responses must also be delivered via form POST, not via query redirect.

**Failing module:** `oidcc-response-type-missing` (formpost plan)

**Current behavior:** When `response_type` is missing from the authorization request and `response_mode=form_post` was requested, Vouch returns the error via a 302 redirect with `?error=...&state=...` in the URL query string.

**Required behavior:** Error responses must use the same response mode as success responses. When `response_mode=form_post`:
1. Return an HTML page with an auto-submitting form that POSTs the error parameters to the `redirect_uri`
2. Form fields: `error`, `error_description`, `state` (same parameters, just delivered via POST body instead of query string)

**Spec references:** OAuth2-FP-2, OAuth2-RT-5, RFC6749-3.1.1

---

### Task 2: Redirect URI validation (MEDIUM — fixes 3 dynamic test modules)

**What:** Three redirect URI validation scenarios are failing.

#### 2a: Missing redirect_uri error page (fixes oidcc-ensure-redirect-uri-in-authorization-request)

When `redirect_uri` is omitted from the authorization request and the client has multiple registered redirect URIs, the server must **display an error page** (not redirect). The conformance test times out (300s WAITING status) because it expects to see an error page.

**Required behavior:** Return an HTML error page with an appropriate message (e.g., "Missing redirect URI") rather than redirecting to any URI.

**Spec reference:** OIDCC-3.1.2.1

#### 2b: Reject mismatched redirect_uri query params (fixes oidcc-redirect-uri-query-mismatch)

When the `redirect_uri` in the authorization request has different query parameter values than the registered redirect URI, the server must reject the request. The test shows `ExpectRedirectUriErrorPage` (REVIEW) followed by a browser timeout — Vouch redirects to the tampered URI instead of showing an error.

**Required behavior:** Reject the request and show an error page (do NOT redirect to the mismatched URI).

**Spec reference:** OIDCC-3.1.2.1

#### 2c: Reject redirect_uri with added query params (fixes oidcc-redirect-uri-query-added)

When the `redirect_uri` in the authorization request has additional query parameters not present in the registered redirect URI, the server must reject the request.

**Required behavior:** Exact-match redirect URIs per RFC 6749 Section 3.1.2.3. Reject and show error page.

**Spec reference:** OIDCC-3.1.2.1

---

### Task 3: Client JWKS URI support (MEDIUM — fixes oidcc-registration-jwks-uri)

**What:** Support `jwks_uri` in client registration as an alternative to inline `jwks`.

**Current behavior:** Token endpoint returns HTTP 401 when the client registered with `jwks_uri` instead of `jwks`. The server can't fetch the client's keys to verify the `private_key_jwt` client assertion.

**Required behavior:**
1. Accept `jwks_uri` during client registration (mutual exclusion with `jwks` per RFC 7591)
2. When authenticating a `private_key_jwt` client assertion, if the client registered with `jwks_uri`, fetch the JWKS from that URI and use it to verify the assertion
3. Consider caching the fetched JWKS with a reasonable TTL

**Spec references:** RFC 7591, OIDCR-2

---

### Task 4: Client key rotation support (MEDIUM — fixes oidcc-refresh-token-rp-key-rotation)

**What:** When a client rotates its keys (updates its `jwks` or `jwks_uri` points to new keys), the token endpoint must accept the new keys.

**Current behavior:** Token endpoint returns HTTP 401 when the client uses a new key after rotation.

**Required behavior:**
- When validating `private_key_jwt`, always use the client's current keys (re-read `jwks` from registration or re-fetch `jwks_uri`)
- Don't cache client keys indefinitely; support key rotation

This is closely related to Task 3 — implementing both together makes sense.

---

### Task 5: Request URI (`request_uri`) support (MEDIUM — fixes oidcc-request-uri-signed-rs256)

**What:** The authorization endpoint must support the `request_uri` parameter for passing request objects by reference.

**Current behavior:** Discovery correctly advertises `request_uri_parameter_supported: true` and RS256 in `request_object_signing_alg_values_supported`. However, when the conformance suite sends an authorization request with a `request_uri` pointing to an RS256-signed request object, the browser automation times out — the authorization endpoint doesn't fetch and process the request object from the URI.

**Required behavior:**
1. When `request_uri` is present in the authorization request, fetch the JWT from that URI
2. Verify the JWT signature using the client's registered public key (RS256)
3. Merge the request object claims with the authorization request parameters
4. Proceed with the authorization flow using the merged parameters

**Spec references:** OIDCC-6.2

---

### Task 6: Display client registration metadata on login page (LOW — fixes 3 dynamic test modules)

**What:** Display client-provided `logo_uri`, `policy_uri`, and `tos_uri` on the login/consent page.

**Affected modules (all timeout at 300s WAITING):**
- `oidcc-registration-logo-uri` — expects the client's logo image on the login page
- `oidcc-registration-policy-uri` — expects a link to the client's privacy policy
- `oidcc-registration-tos-uri` — expects a link to the client's terms of service

**Required behavior:**
1. Store `logo_uri`, `policy_uri`, `tos_uri` during client registration
2. On the login/consent page, render:
   - The client logo (as an `<img>` tag) if `logo_uri` was registered
   - A link to the privacy policy if `policy_uri` was registered
   - A link to the terms of service if `tos_uri` was registered

**Note:** These tests also require browser automation config updates in this repo (vouch-conformance) to interact with the new UI elements. The current browser config doesn't know how to handle these pages.

**Spec reference:** OIDCR-2

---

### Task 7: Implicit flow support (HIGH effort — fixes oidcc-discovery-endpoint-verification)

**What:** The Dynamic OP certification profile requires implicit flow support. The discovery endpoint verification test checks for mandatory response types and grant types.

**Current state:**
- `response_types_supported`: `["code"]` — must also include `"id_token"` and `"token id_token"`
- `grant_types_supported`: missing `"implicit"` — must be present alongside `"authorization_code"`

**This is a large feature.** Implementing implicit flow requires:
1. Support `response_type=id_token` and `response_type=token id_token`
2. Support `grant_type=implicit`
3. Return tokens in the URL fragment (`#access_token=...&id_token=...`) instead of via the token endpoint
4. Add `"implicit"` to `grant_types_supported` in discovery
5. Add `"id_token"` and `"token id_token"` to `response_types_supported` in discovery

**Alternative:** If implicit flow is not a priority, skip pursuing the "dynamic" certification profile. The "basic" profile does not require implicit flow. This test (`oidcc-discovery-endpoint-verification`) will continue to fail without it.

**Spec references:** OIDCD-3, OIDCC-15.2

---

### Task 8: Server key rotation (LOW — fixes oidcc-server-rotate-keys)

**What:** This is an interactive test that asks the operator to rotate the server's signing keys and then press "Start" to continue. It cannot be automated with the current browser automation setup.

**Current behavior:** The test times out at 300s (WAITING) because no one presses the button.

**To fix:** This requires either:
- Manual test execution (not automatable)
- An API endpoint on Vouch to trigger key rotation, plus a custom browser automation step

This is low priority since the test infrastructure limitation is the blocker, not a Vouch code issue.

---

## Modules That Pass or Are Expected Skips

**Passing (dynamic, 6):** oidcc-idtoken-rs256, oidcc-userinfo-rs256, oidcc-redirect-uri-query-OK, oidcc-redirect-uri-regfrag, oidcc-server, oidcc-ensure-client-assertion-with-iss-aud-succeeds

**Passing (formpost, 22):** oidcc-server, oidcc-idtoken-signature, oidcc-userinfo-get, oidcc-userinfo-post-header, oidcc-userinfo-post-body, oidcc-ensure-request-without-nonce-succeeds-for-code-flow, oidcc-display-page, oidcc-display-popup, oidcc-prompt-none-not-logged-in, oidcc-prompt-none-logged-in, oidcc-max-age-10000, oidcc-ensure-request-with-unknown-parameter-succeeds, oidcc-id-token-hint, oidcc-login-hint, oidcc-ui-locales, oidcc-claims-locales, oidcc-ensure-request-with-acr-values-succeeds, oidcc-codereuse, oidcc-codereuse-30seconds, oidcc-ensure-post-request-succeeds, oidcc-server-client-secret-post, oidcc-ensure-request-with-valid-pkce-succeeds

**Skipped (expected):** oidcc-idtoken-unsigned, oidcc-registration-sector-uri, oidcc-registration-sector-bad, oidcc-request-uri-unsigned, oidcc-ensure-request-object-with-redirect-uri, oidcc-refresh-token, oidcc-scope-profile, oidcc-scope-address, oidcc-scope-phone, oidcc-scope-all

## How to Verify

After implementing changes, rebuild and retest:

```bash
# In the vouch-conformance repo
make restart-vouch         # Rebuild vouch with changes
make test-oidc-dynamic     # Run dynamic test suite
make test-oidc-formpost    # Run form post test suite
make rerun-failures        # Rerun only failed modules
python3 scripts/debug.py failures  # Inspect remaining failures
```
