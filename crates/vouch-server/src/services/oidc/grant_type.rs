// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OAuth 2.0 `grant_type` wire values — single source of truth.
//!
//! [`OAuthGrantType`] enumerates every grant the token endpoint dispatches.
//! The token handler (parsing and dispatch) and the discovery document
//! (`grant_types_supported`) both derive from it, so the advertised set can
//! never drift from the accepted set.

/// OAuth grant types supported by this server's token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OAuthGrantType {
    /// Standard OAuth 2.0 authorization code grant.
    AuthorizationCode,
    /// Client credentials grant (RFC 6749 Section 4.4).
    ClientCredentials,
    /// Device authorization grant (RFC 8628).
    DeviceCode,
    /// Token exchange grant (RFC 8693).
    TokenExchange,
    /// FIDO2 assertion grant (custom extension per RFC 6749 Section 4.5).
    Fido2Assertion,
}

/// Parse error for OAuth `grant_type` values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParseOAuthGrantTypeError {
    value: String,
}

impl ParseOAuthGrantTypeError {
    #[must_use]
    pub(crate) fn new(value: &str) -> Self {
        Self {
            value: value.to_string(),
        }
    }
}

impl std::fmt::Display for ParseOAuthGrantTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unsupported grant_type: {}", self.value)
    }
}

impl std::error::Error for ParseOAuthGrantTypeError {}

impl OAuthGrantType {
    const SUPPORTED: [Self; 5] = [
        Self::AuthorizationCode,
        Self::ClientCredentials,
        Self::DeviceCode,
        Self::TokenExchange,
        Self::Fido2Assertion,
    ];

    /// Wire-format `grant_type` value.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::ClientCredentials => "client_credentials",
            Self::DeviceCode => "urn:ietf:params:oauth:grant-type:device_code",
            Self::TokenExchange => "urn:ietf:params:oauth:grant-type:token-exchange",
            Self::Fido2Assertion => "urn:ietf:params:oauth:grant-type:fido2-assertion",
        }
    }

    /// All supported `grant_type` wire values.
    #[must_use]
    pub(crate) fn supported_wire_values() -> Vec<&'static str> {
        Self::SUPPORTED.iter().copied().map(Self::as_str).collect()
    }
}

impl std::str::FromStr for OAuthGrantType {
    type Err = ParseOAuthGrantTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::SUPPORTED
            .iter()
            .copied()
            .find(|grant_type| grant_type.as_str() == s)
            .ok_or_else(|| ParseOAuthGrantTypeError::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::OAuthGrantType;

    #[test]
    fn test_oauth_grant_type_from_str_authorization_code() {
        let result: Result<OAuthGrantType, _> = "authorization_code".parse();
        assert_eq!(result, Ok(OAuthGrantType::AuthorizationCode));
    }

    #[test]
    fn test_oauth_grant_type_from_str_device_code() {
        let result: Result<OAuthGrantType, _> =
            "urn:ietf:params:oauth:grant-type:device_code".parse();
        assert_eq!(result, Ok(OAuthGrantType::DeviceCode));
    }

    #[test]
    fn test_oauth_grant_type_from_str_token_exchange() {
        let result: Result<OAuthGrantType, _> =
            "urn:ietf:params:oauth:grant-type:token-exchange".parse();
        assert_eq!(result, Ok(OAuthGrantType::TokenExchange));
    }

    #[test]
    fn test_oauth_grant_type_from_str_fido2_assertion() {
        let result: Result<OAuthGrantType, _> =
            "urn:ietf:params:oauth:grant-type:fido2-assertion".parse();
        assert_eq!(result, Ok(OAuthGrantType::Fido2Assertion));
    }

    #[test]
    fn test_oauth_grant_type_from_str_client_credentials() {
        let result: Result<OAuthGrantType, _> = "client_credentials".parse();
        assert_eq!(result, Ok(OAuthGrantType::ClientCredentials));
    }

    #[test]
    fn test_oauth_grant_type_from_str_rejects_unknown() {
        let result: Result<OAuthGrantType, _> = "password".parse();
        assert!(result.is_err());

        let result2: Result<OAuthGrantType, _> = "".parse();
        assert!(result2.is_err());

        let result3: Result<OAuthGrantType, _> = "jwt-bearer".parse();
        assert!(result3.is_err());

        // Lock-in: §2.1 grant URN must be rejected (RFC 7523 §2.1 removed).
        let bearer: Result<OAuthGrantType, _> =
            "urn:ietf:params:oauth:grant-type:jwt-bearer".parse();
        assert!(bearer.is_err());
    }
}
