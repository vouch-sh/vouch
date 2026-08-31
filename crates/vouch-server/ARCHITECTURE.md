# vouch-server architecture

How a request travels from the Axum listener, through the middleware stack, into a
handler, past every proof and verification, and back out as a response.

This document is for people reading or changing the code. It is **not** operator
documentation. For deployment, configuration, endpoint tables, rate-limit tiers and
request limits, see the [Vouch Server Operator Guide](../../docs/src/README.md) — in
particular [Ports and Endpoints](../../docs/src/reference/ports-and-endpoints.md), which
lists every endpoint with its authentication type and rate-limit tier, and
[Behind a Reverse Proxy](../../docs/src/configuration/reverse-proxy.md).

Coverage here is the auth and credential paths. SCIM, the admin UI, GitHub webhooks and
the SAML SP run the same global stages and diverge at the route group.

## Two registers

Vouch enforces its security invariants in two registers. Neither is visible from the
other.

**At runtime** the server validates DPoP proofs, WebAuthn assertions, RFC 9421 message
signatures, JWT-secured authorization requests, PKCE verifiers, mTLS certificates, and
client secrets.

**At compile time** one function mints access tokens: `create_oauth_access_token`. It
takes a `TokenIssuanceProof` — a value that is not `Clone` and carries `#[must_use]`,
assembled from three witnesses: a grant-level replay claim, a client-authentication
claim, and a sender-constraint decision. Production builds ship 9 grant variants and four
client-authentication variants. Each supplies its own witness. A grant that skips its
replay primitive has nothing to put in the field, so it does not compile.

The second register does not appear in handler bodies. The enforcement lives in the
signature of `create_oauth_access_token`, so reading a grant arm top-to-bottom will not
show it.

## The global middleware stack

Every request passes the same stages before reaching a route group — API, UI and health
probe alike. **In tower and axum the last `.layer()` call is the outermost**, so
`build_app` lists the stack in reverse of the order a request meets it. Read
`infra/router.rs` bottom-up, or read the diagram below, which runs in request order.

```mermaid
flowchart TB
  req(["HTTPS request"]) --> l1["set_request_id"]
  l1 --> l2["request_span_middleware"]
  l2 --> l3["propagate_request_id"]
  l3 --> l4["DefaultBodyLimit<br/>256 KiB"]
  l4 -- "outside the timeout,<br/>so 408s are still counted" --> l5["metrics_middleware"]
  l5 --> l6["TimeoutLayer<br/>30 s"]
  l6 --> l7["org_host_gate"]
  l7 --> l8["i18n_layer"]
  l8 --> l9["security header bundle"]
  l9 --> grp{{"merged router<br/>API + UI + metrics + certification"}}
  l6 -. "handler future dropped" .-> to["408 Request Timeout"]
  l7 -. "org subdomain, path outside<br/>discovery / jwks / health" .-> nf["404 Not Found"]
```

Stage 9 is nine response-header layers, plus a tenth (HSTS) when TLS is configured.
CORS is **not** in that bundle: `build_api_cors_layer` and `build_ui_cors_layer` are
applied inside the API and UI routers respectively, so the two groups get different
CORS policies.

**One ordering is load-bearing.** `metrics_middleware` records after
`next.run(req).await` resolves. Placed inside `TimeoutLayer`, the timeout cancels that
future and Prometheus never sees the request — commit `7bbcbb0f` shipped exactly that.
Placed outside, the 408 is counted. Two tests in `router.rs` hold the order: one asserts
the recorded status is 408, the other asserts the source position of the two calls.

The i18n layer covers the merged router, not the UI group alone: two API endpoints return
HTML (`/oauth/authorize` renders consent and error pages, `/oauth/callback` renders
enrollment errors), so the locale task-local has to exist for both groups.

## Route families

Past the global stages the route groups diverge. The sub-router a path lives in decides
which rate-limit tier applies, whether the body cap drops below the global 256 KiB,
whether a 401 carries an RFC 9728 `resource_metadata` pointer, and whether an RFC 9421
signature is mandatory.

```mermaid
flowchart TB
  subgraph T["token tier"]
    direction TB
    t0["/oauth/token<br/>/oauth/par<br/>/oauth/fido2/challenge<br/>/oauth/device"] --> t1["auth rate limit"] --> t2["handler"]
  end
  subgraph K["key registration"]
    direction TB
    k0["/v1/keys/register/start<br/>/v1/keys/register/complete"] --> k1["auth rate limit"] --> k2["require_signature<br/>RFC 9421"] --> k3["handler"]
  end
  subgraph C["credential issuance"]
    direction TB
    c0["/v1/credentials/ssh<br/>/v1/credentials/aws/token<br/>/v1/credentials/github/token"] --> c1["body limit"] --> c2["credential rate limit"] --> c3["resource_metadata<br/>RFC 9728"] --> c4["require_signature<br/>RFC 9421"] --> c5["handler"]
  end
  subgraph M["protected management"]
    direction TB
    m0["/oauth/introspect<br/>/v1/keys<br/>/api/v1/applications/*"] --> m1["general rate limit"] --> m2["resource_metadata"] --> m3["require_signature<br/>keys routes only"] --> m4["handler"]
  end
```

Per-endpoint tiers and the body-cap table live in the
[operator reference](../../docs/src/reference/ports-and-endpoints.md); they are not
duplicated here.

**Signature enforcement is default-deny within `/v1`.** `require_signature` matches the
route template against `PUBLIC_V1_PATHS`: five templates pass unsigned, every other `/v1`
path must be signed. Paths outside `/v1` are out of scope. With no matched template it
falls back to the concrete URI, which lands in deny, not passthrough. A signature must
cover two components — method and path. Bodies up to 1 MiB are buffered for RFC 9530
`Content-Digest`, and signatures older than 300 s are rejected.

`maybe_rate_limit!` replaces all three limiters with a no-op when
`VOUCH_CERTIFICATION_TEST_TOKEN` is set. That variable changes three things: it disables
rate limiting, activates `GET /certification/complete-login` (a session for a synthetic
user, no FIDO2), and relaxes the upstream-IdP requirement. It must not be set in
production.

## The proof chain

Access tokens are minted in one function, and it takes evidence rather than arguments a
caller can fabricate. Each consume-once database operation returns a sealed witness type
on success. Those witnesses are the only material a `TokenIssuanceProof` can be built
from. The proof is not `Clone` and carries `#[must_use]`, so it authorizes one issuance
and cannot be dropped without a lint.

```mermaid
flowchart TB
  store[("DocumentStore<br/>atomic consume-once")]
  store -- "try_consume_challenge_state" --> w1["ChallengeStateClaim"]
  store -- "claim authorization code" --> w2["AuthCodeClaim"]
  store -- "transition device code" --> w3["DeviceCodeClaim"]
  store -- "consume OIDC state" --> w4["OidcStateClaim"]
  store -- "insert assertion jti" --> w5["JwtAssertionJtiClaim"]
  store -. "race loser, expired,<br/>never existed" .-> ce["ClaimError::AlreadyConsumed"]
  w1 & w2 & w3 & w4 --> gp["GrantProof<br/>one variant per grant"]
  w5 --> jw["JwtClientAuthProof"]
  jw --> cap["ClientAuthProof"]
  sec["ClientSecretVerification<br/>MtlsCertVerification<br/>NoClientAuth witness"] --> cap
  reg["client registration flags"] --> scv["SenderConstraintProof::validate"] --> scp["SenderConstraintProof"]
  gp --> tip["TokenIssuanceProof<br/>not Clone<br/>must_use"]
  cap --> tip
  scp --> tip
  tip --> mint["create_oauth_access_token"]
  mint --> at["ES256 at+jwt<br/>cnf.jkt for DPoP, cnf.x5t for mTLS"]
```

All three arrows into `TokenIssuanceProof` are required fields. A grant arm that skips
its replay primitive has nothing for `grant`. One that skips the sender-constraint
decision has nothing for `sender_constraint`. The build fails; no reviewer has to catch
it.

| `GrantProof` variant | Replay primitive consumed first |
|---|---|
| `AuthorizationCode` | `AuthCodeClaim` — the code was atomically claimed |
| `Fido2Assertion` | `ChallengeStateClaim` — the challenge state JWT was marked consumed |
| `DeviceCode` | `DeviceCodeClaim` — the device code transitioned to Consumed |
| `EnrollmentBootstrap` | `OidcStateClaim` — closes the read-vs-consume TOCTOU window |
| `EnrollmentComplete`, `BrowserLogin` | `ChallengeStateClaim` |
| `ClientCredentials`, `TokenExchange` | none — replay protection rests on `ClientAuthProof` |
| `CertificationBypass` | none — gated by an environment variable |

`ClaimError` has three variants, and one of them collapses four conditions. *Not found*,
*expired*, *already consumed* and *lost the race* all return `AlreadyConsumed`. Error text
and response timing are identical across all four, so a client cannot probe whether a
code, challenge or jti exists. Preserve that property when adding a claim primitive.

`ClientAuthProof` has four variants; the no-auth one has two named constructors.
`NoClientAuth::for_public_client` returns an error if the client is registered with any
`token_endpoint_auth_method` other than `None`, so a confidential client cannot use the
no-auth arm. `NoClientAuth::internal_endpoint` covers the four flows where the server is
both issuer and client: browser login, enrollment callbacks, device polling, and the
certification bypass. **Adding a caller to `internal_endpoint` is an audit-relevant
change** — grep for it before merging.

`SenderConstraintProof::validate` checks three registered requirements: FAPI 2.0
§5.3.2.1, RFC 9449 §5, and RFC 8705 §3. `ParCreationProof` applies the same pattern to
PAR storage, which issues no token and cannot use the token chokepoint.

## FIDO2 login

`vouch login` runs this path. The CLI is not a browser and has no page origin, so
`clientDataJSON.origin` is `https://{rp_id}` and the server compares against that string.
`verify_login_assertion` passes `require_user_verification: true` as a literal, so a
touch-only assertion is rejected for every client and every registration.

```mermaid
sequenceDiagram
  autonumber
  participant CLI as vouch CLI
  participant YK as YubiKey CTAP2
  participant SRV as vouch-server
  participant DB as DocumentStore
  CLI->>SRV: POST /oauth/fido2/challenge
  SRV->>DB: store challenge state JWT
  SRV-->>CLI: challenge, rp_id, allowCredentials
  CLI->>YK: authenticatorGetAssertion
  YK-->>CLI: authData, clientDataJSON, signature
  CLI->>SRV: POST /oauth/token, FIDO2 grant + DPoP header
  SRV->>SRV: validate_dpop_proof: sig, jti, nonce, htm, htu, iat
  SRV->>SRV: AssertionGrant::validate
  par consume the challenge
    SRV->>DB: try_consume_challenge_state
    DB-->>SRV: ChallengeStateClaim
  and resolve the key
    SRV->>DB: lookup_and_verify_authenticator
    DB-->>SRV: authenticator + user
  end
  SRV->>SRV: verify_login_assertion
  alt assertion verifies
    SRV->>DB: update counter
    SRV->>SRV: evaluate_posture_policies
    SRV->>DB: audit login_success
    SRV->>SRV: build TokenIssuanceProof
    SRV-->>CLI: access token, cnf.jkt bound to the DPoP key
  else rp_id, origin, challenge, UP, UV, counter or signature fails
    SRV->>DB: audit login_failed
    SRV-->>CLI: 400 invalid_grant, Authentication failed
  end
```

The parallel step produces a witness, not just latency. The `ChallengeStateClaim`
returned by `try_consume_challenge_state` is threaded into `GrantProof::Fido2Assertion`.
No other code path constructs that variant.

**The posture gate runs before the success audit.** A policy-denied attempt records
`login_failed`, never `login_success`. Temporal policies — step-up recency on token
exchange — read `login_success` as proof of a completed, policy-compliant hardware login.
Writing it before the gate would hand that proof to a denied attempt.

### The eight checks in `verify_assertion`

| Step | Check | Rejection |
|---|---|---|
| 1 | authenticator data at least 37 bytes | `InvalidAuthDataLength` |
| 2 | SHA-256 of the expected rp_id equals bytes 0..32 | `RpIdMismatch` |
| 3 | flags: user present, and user verified | `UserNotPresent` / `UserNotVerified` |
| 4-5 | signature counter strictly increasing once non-zero | `CounterNotIncreasing` |
| 6 | clientDataJSON type is `webauthn.get`, challenge matches, origin matches | `ChallengeMismatch` / `InvalidOrigin` |
| 7-8 | COSE signature over `authData \|\| SHA-256(clientDataJSON)` | signature verification failure |

Counter regression fails the ceremony, and that is our choice rather than the
specification's. WebAuthn Level 2 §7.2 leaves it open: *"Whether the Relying Party
updates storedSignCount in this case, or not, or fails the authentication ceremony or
not, is Relying Party-specific."* (`specs/w3c/webauthn-2.txt`). A stalled counter is as
consistent with a malfunctioning authenticator as with a cloned one, and the code
declines to distinguish them. Credentials that have only ever reported 0 keep
`stored_counter == 0` and stay accepted.

## Authorization code: PAR, JAR, PKCE, JARM

Request parameters reach `/oauth/authorize` from four sources: a pushed request
(RFC 9126), an inline signed JWT (RFC 9101), an HTTPS `request_uri` the server fetches,
or plain query parameters. The endpoint resolves one authoritative set before running any
validation.

```mermaid
flowchart TB
  par0["POST /oauth/par"] --> pauth["client auth"] --> pproof["ParCreationProof"] --> pstore[("PAR record")]
  authz["GET /oauth/authorize"] --> resolve{"parameter source"}
  resolve -- "request_uri, urn prefix" --> pstore
  resolve -- "request, inline JWT" --> jar["validate_request_object<br/>RFC 9101"]
  resolve -- "request_uri, https" --> fetch["fetch_request_object<br/>SSRF-guarded"] --> jar
  resolve -- "plain query params" --> plain["query parameters"]
  pstore --> checks
  jar --> checks
  plain --> checks
  checks["require_pkce_for_client<br/>redirect_uri, scope, response_type"] --> sess{"session cookie<br/>hardware-verified?"}
  sess -- "no" --> login["/login, browser WebAuthn"] --> sess
  sess -- "yes" --> code["issue_authorization_code<br/>binds code_challenge"]
  code --> mode{"response_mode"}
  mode -- "query or fragment" --> plainredir["302 with code and state"]
  mode -- "jwt, query.jwt, form_post.jwt" --> jarm["build_jarm_success_jwt"]
  plainredir --> tok["POST /oauth/token"]
  jarm --> tok
  tok --> tauth["authenticate_client / _mtls / _jwt"]
  tauth --> tdpop["validate_dpop_if_present"]
  tdpop --> tsc["SenderConstraintProof::validate"]
  tsc --> tex["exchange_authorization_code<br/>claims the code, verifies PKCE"]
  tex --> tproof["TokenIssuanceProof"] --> out["access token + id_token"]
```

All four parameter sources converge before validation runs, so a query-string parameter
cannot weaken a pushed or signed one. `response_mode` in the query string is a hint; the
mode used is the one resolved with the rest of the request. `request` and `request_uri`
are mutually exclusive and the handler rejects a request carrying both. An HTTPS
`request_uri` is dialled only after `infra::ssrf::assert_public_destination` clears the
resolved address.

## Resource side: the extractor is the policy

The handler signature states the authentication a route demands.
`extract_resource_token` is private to its module, so a handler obtains a validated
token through one of the extractors below; the choice declares the strength required.
`AuthenticatedToken` means the token validated; an enrollment bootstrap session
satisfies it. `HardwareVerifiedToken` additionally requires
`hardware_verified == true` and returns 403 otherwise. `SteppedUpToken` additionally
requires a FIDO2 assertion within `KEY_DELETE_MAX_AGE_SECS`, so a destructive action
rests on a touch from seconds ago rather than the hours a session lives; it rejects
with RFC 9470 `insufficient_user_authentication` (401) instead, and both key-deletion
handlers name it. All three credential-issuance endpoints name `HardwareVerifiedToken`;
`/v1/credentials/github/status` is a public read route and names `AuthenticatedToken`.

```mermaid
flowchart TB
  req(["POST /v1/credentials/ssh"]) --> sig["require_signature<br/>RFC 9421 + RFC 9530"]
  sig --> e1["extract token:<br/>Authorization DPoP, then Bearer, then cookie"]
  e1 --> e2["decode_token<br/>ES256 at+jwt, RFC 9068"]
  e2 --> e3["enforce_audience_coverage"]
  e3 --> e4[("session lookup by token hash")]
  e4 --> bind{"cnf claim present?"}
  bind -- "cnf.jkt" --> dpop["validate_dpop_at_resource<br/>ath binds proof to this token"]
  dpop --> jkt{"jkt equals cnf.jkt?<br/>constant-time"}
  jkt -- "no" --> r401["401 invalid_token"]
  bind -- "cnf.x5t, no jkt" --> mtls["client certificate thumbprint<br/>must match, constant-time"]
  mtls --> hw
  jkt -- "yes" --> hw
  bind -- "none" --> hw
  hw{"hardware_verified claim"} -- "false" --> r403["403 hardware_required"]
  hw -- "true" --> tokty["HardwareVerifiedToken"]
  tokty --> h["handler"]
  h --> ssh["SshCa::sign_certificate<br/>Ed25519, on a blocking thread"]
  ssh --> rec[("record issuance for revocation")]
  rec -- "write fails" --> r500["500, certificate withheld"]
  rec -- "written" --> resp(["SshCertificateResponse"])
```

A sender-constrained token presented the wrong way is rejected, not downgraded. Tokens
arrive from three sources, in precedence order: `Authorization: DPoP`,
`Authorization: Bearer`, then the `__Host-vouch_session` cookie. A token carrying
`cnf.jkt` returns 401 on the second and 401 on the third. The binding is a property of
the token, not of the scheme it arrived under.

**An untracked certificate cannot be revoked.** If `record_ssh_certificate_issuance`
fails, the signed certificate is discarded and the request returns 500. The revocation
record is the load-bearing write; the audit event beside it is the queryable one.

DPoP validation differs by endpoint, and the difference is which mechanism binds the
proof. At `/oauth/token`, `NoncePolicy::Required` rejects a proof with no nonce and
returns a fresh one, so a client cannot precompute proofs. At a resource endpoint
`NoncePolicy::Optional` applies, because the `ath` claim — the SHA-256 of the presented
access token — already binds the proof to one token. Both paths insert the `jti`
atomically and consume any nonce with a single statement. Nonces live 300 s. Proofs
older than `VOUCH_DPOP_MAX_AGE` are rejected, as are proofs dated more than 60 s in the
future.

## Error paths

One error type carries every failure. It has three response shapes, picked by audience:
an OAuth envelope for clients parsing `error` and `error_description`, a JSON API
envelope for the CLI, and a localized HTML template for a browser. Rejections that fire
*before* the handler — malformed form bodies, unparseable query strings — are intercepted
so they land in the same envelopes instead of axum's `text/plain` default.

```mermaid
flowchart LR
  ext["extractor rejection<br/>OAuthForm, OAuthQuery,<br/>ValidJson, ValidPath"] --> se
  svc["service or handler failure"] --> se
  se["ServiceError"] --> k{"variant"}
  k -- "OAuth" --> oa["OAuthErrorResponse<br/>RFC 6749 5.2"]
  k -- "Api / ApiWithHeaders" --> ja["JSON API envelope"]
  k -- "StepUpRequired" --> su["401 + WWW-Authenticate<br/>RFC 9470"]
  k -- "Validation, NotFound,<br/>Forbidden, Conflict" --> ja
  k -- "Database, Internal" --> int["500 server_error<br/>detail logged, not returned"]
  k -- "OccConflict" --> retry["with_dsql_retry, bounded"]
  oa --> rm{"401 on a<br/>protected resource?"}
  rm -- "yes" --> rmd["WWW-Authenticate gains<br/>resource_metadata pointer"]
  rm -- "no" --> plain["response as-is"]
  ja --> rm
  tmpl["UI route failure"] --> html["localized Askama template<br/>Tr fields, not String"]
```

Two audiences, two strings, never one. RFC 6749 §5.2 defines `error_description` as
*"Human-readable ASCII [USASCII] text providing additional information, used to assist
the client developer in understanding the error that occurred,"* and requires that its
values *"MUST NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E."*
(`specs/rfc/rfc6749.txt`). OAuth text stays ASCII English. Free-text template fields are
typed `Tr<'static>` rather than `String`, so a bare literal fails to compile and every
construction names a catalog key. `AppValidationError` carries both spellings:
`message()` for the API, `localized()` for the page.

`OAuthForm` exists because axum's default rejection is the wrong shape. It rejects into
the OAuth error envelope instead of `text/plain`, answers 415 to any media type other
than `application/x-www-form-urlencoded`, and drops empty-valued parameters before
deserializing. RFC 6749 §3.2: *"Parameters sent without a value MUST be treated as if
they were omitted from the request."* (`specs/rfc/rfc6749.txt`). So `scope=` and an
omitted `scope` arrive identically, a repeated recognized parameter fails, and an
unrecognized one is ignored. `ValidJson` does the same for the browser WebAuthn flows,
which read `errResp.message` from a JSON body and cannot see a plain-text rejection.

`OccConflict` is the only variant that reports itself retryable. Aurora DSQL offers no
`SELECT … FOR UPDATE`, so cross-row invariants are written as one transaction that
version-bumps an owning document, wrapped in the single shared bounded-retry macro. A
business-logic 409 is a `Conflict`, not an `OccConflict`, and propagates immediately. The
test `occ_conflict_is_the_only_retryable_service_error` pins both halves.

## Where things live

| Concern | Path |
|---|---|
| Router, layer stack, route groups | `src/infra/router.rs` |
| Proof types and the issuance chokepoint | `src/services/auth.rs` |
| Single-use claim errors | `src/db/claim.rs` |
| FIDO2 grant | `src/services/oidc/fido2_grant.rs` |
| WebAuthn assertion and attestation | `src/crypto/webauthn_verify.rs` |
| DPoP | `src/services/oidc/dpop.rs` |
| Client auth, token exchange | `src/services/oidc/token.rs` |
| JAR / JARM | `src/services/oidc/jar.rs`, `jarm.rs` |
| Resource-token extraction | `src/handlers/session.rs` |
| Extractor rejections | `src/handlers/extractors.rs` |
| Error type and response mapping | `src/error.rs` |
| RFC 9421 middleware and resolver | `../vouch-httpsig/`, `src/infra/httpsig.rs` |
| Layer-boundary rules (enforced by test) | `tests/arch_boundaries.rs` |

Line numbers move; the function and type names do not.
