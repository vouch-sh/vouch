// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A client that has passed the checks of the flow that loaded it.
//!
//! [`crate::db::OAuthClient`] is the registration row and says what the
//! client *may* do. [`ValidatedOAuthClient`] says the row was checked against
//! the operation about to be performed: the token endpoint's grant
//! (`for_grant`) or the authorization endpoint's `code` response type
//! (`for_authorize`). Token issuers take the validated type, so a path that
//! skips the check does not compile.
//!
//! The type records that *a* flow's validation ran, not which one. Nothing
//! today hands an authorize-validated client to a token issuer, since the two
//! flows live in different handlers, but that is a convention and not a
//! compiler guarantee.

use std::ops::Deref;

use crate::db::OAuthClient;
use crate::error::{OAuthErrorCode, ServiceError};
use crate::services::oidc::grant_type::OAuthGrantType;

/// An [`OAuthClient`] checked against the operation it is about to perform.
///
/// Dereferences to the row for reads; there is no way to get the row back
/// out, and no constructor outside this module and `for_test`.
#[derive(Debug)]
pub struct ValidatedOAuthClient {
    client: OAuthClient,
}

/// Why `for_authorize` refused a client, with the row handed back so the
/// caller can render the refusal against the client's registered
/// `redirect_uri` and, for a JARM client, sign it with the client's key.
#[derive(Debug)]
pub struct AuthorizeRejection {
    pub client: OAuthClient,
    pub error: ServiceError,
}

impl ValidatedOAuthClient {
    /// Token endpoint: the handler has authenticated `client`; this checks
    /// its registered `grant_types` (RFC 7591 §2) for `grant`.
    ///
    /// # Errors
    /// RFC 6749 §5.2 `unauthorized_client`: "The authenticated client is not
    /// authorized to use this authorization grant type."
    pub(crate) fn for_grant(
        client: OAuthClient,
        grant: OAuthGrantType,
    ) -> Result<Self, ServiceError> {
        if client.is_authorized_for_grant(grant.as_str()) {
            Ok(Self { client })
        } else {
            Err(ServiceError::oauth(
                OAuthErrorCode::UnauthorizedClient,
                format!("Client is not authorized for {} grant", grant.as_str()),
            ))
        }
    }

    /// Authorization endpoint: RFC 7591 §2 defines `response_types` as the
    /// "response type strings that the client can use at the authorization
    /// endpoint", and `/authorize` only issues `code`. An absent list means
    /// the defaults apply, as `is_authorized_for_grant` treats an absent
    /// `grant_types`.
    ///
    /// # Errors
    /// RFC 6749 §4.1.2.1 `unauthorized_client`: "The client is not authorized
    /// to request an authorization code using this method."
    pub(crate) fn for_authorize(client: OAuthClient) -> Result<Self, Box<AuthorizeRejection>> {
        let allowed = client.response_types.as_ref().is_none_or(|types| {
            types
                .iter()
                .any(|rt| rt == crate::services::oidc::RESPONSE_TYPE_CODE)
        });
        if allowed {
            Ok(Self { client })
        } else {
            Err(Box::new(AuthorizeRejection {
                client,
                error: ServiceError::oauth(
                    OAuthErrorCode::UnauthorizedClient,
                    "Client is not registered for the 'code' response type",
                ),
            }))
        }
    }

    /// Bypass for unit tests of code downstream of the check.
    #[cfg(test)]
    pub(crate) fn for_test(client: OAuthClient) -> Self {
        Self { client }
    }
}

impl Deref for ValidatedOAuthClient {
    type Target = OAuthClient;

    fn deref(&self) -> &OAuthClient {
        &self.client
    }
}
