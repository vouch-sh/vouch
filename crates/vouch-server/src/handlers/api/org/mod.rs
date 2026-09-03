// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JSON handlers for `/api/v1/org/*` — organization-admin endpoints reached
//! by SIEM pollers, CI provisioning scripts, and the admin UI's own `fetch`
//! calls; `validate_policy_api`'s only known caller is the admin policy
//! editor, which calls it with same-origin session credentials rather than
//! a bearer token.
//!
//! `list_scim_tokens`, `delete_scim_token`, and `validate_policy_api` take
//! the `OrgAdmin` extractor, which accepts a Bearer or DPoP access token, or
//! — falling back — the session cookie. A certificate-bound token (RFC 8705
//! `cnf.x5t#S256`) additionally requires the matching mTLS client
//! certificate; the certificate is never a credential on its own.
//! `create_scim_token` calls the same `extract_org_admin` chain directly
//! instead of through the extractor, so it accepts the identical set of
//! credentials; the one real difference is that `OrgAdmin` forwards an
//! mTLS client certificate when present, while `create_scim_token` always
//! passes `None`. `audit_events` is the outlier: it additionally accepts
//! an org API token carrying the `audit:read` scope as its principal, and
//! it hard-401s any request with no `Authorization` header at all — which
//! is what keeps the cookie fallback from ever applying to it.

mod audit;
mod ocsf;
mod policies;
mod scim_tokens;

pub(crate) use audit::audit_events;
pub(crate) use policies::validate_policy_api;
pub(crate) use scim_tokens::{create_scim_token, delete_scim_token, list_scim_tokens};
