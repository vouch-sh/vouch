// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Test harness for integration testing.
//!
//! This module provides a unified test harness that combines all the test
//! utilities from different crates into a single, easy-to-use interface.

use std::sync::Arc;

use anyhow::Result;

use crate::clock::TestClock;
use vouch_cli::{HttpClient, TestHttpClient};
use vouch_server::{AppState, db, test_utils};

/// Unified test harness for integration tests.
///
/// This harness provides:
/// - In-memory SQLite database with migrations
/// - Test HTTP client that calls the router directly
/// - Controllable test clock for time-dependent tests
/// - Helper methods for creating test users and sessions
pub struct TestHarness {
    /// Server application state.
    pub state: Arc<AppState>,
    /// Test HTTP client that calls the router directly.
    pub http_client: TestHttpClient,
    /// Raw axum router for tests that need full response headers
    /// (e.g. Location, Set-Cookie) which `TestHttpClient` strips.
    pub router: axum::Router,
    /// Controllable test clock.
    pub clock: Arc<TestClock>,
}

impl TestHarness {
    /// Create a new test harness with default configuration.
    pub async fn new() -> Self {
        Self::from_state(test_utils::test_app_state().await)
    }

    /// Create a test harness over a pre-built `AppState`.
    ///
    /// Use with the `test_utils::test_app_state_*` variants when a test needs
    /// non-default state, e.g. `test_app_state_with_rsa_key()` for RS256
    /// endpoints.
    pub fn from_state(state: Arc<AppState>) -> Self {
        let config = state.config();
        let router = vouch_server::infra::router::build_app(state.clone(), &config)
            .expect("Failed to build test app router");
        let http_client = TestHttpClient::new(router.clone());
        let clock = Arc::new(TestClock::default());

        Self {
            state,
            http_client,
            router,
            clock,
        }
    }

    /// Get the base URL for API requests.
    #[must_use]
    pub fn base_url(&self) -> &str {
        "https://test.example.com"
    }

    /// Build a full URL for an API path.
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url(), path)
    }

    /// Create a test user in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if user creation fails.
    pub async fn create_user(&self, email: &str) -> Result<vouch_server::db::User> {
        let user = test_utils::create_test_user(&self.state.store, email).await;
        Ok(user)
    }

    /// Create a test authenticator for a user.
    ///
    /// # Errors
    ///
    /// Returns an error if authenticator creation fails.
    pub async fn create_authenticator(&self, user_id: &str) -> Result<String> {
        let auth_id = test_utils::create_test_authenticator(&self.state.store, user_id).await;
        Ok(auth_id)
    }

    /// Create a test session and return the JWT token.
    ///
    /// # Errors
    ///
    /// Returns an error if session creation fails.
    pub async fn create_session(
        &self,
        user_id: &str,
        email: &str,
        auth_id: &str,
    ) -> Result<String> {
        let token = test_utils::create_test_session(&self.state, user_id, email, auth_id).await;
        Ok(token)
    }

    /// Create a session bound to a specific OAuth client.
    ///
    /// # Errors
    ///
    /// Returns an error if session creation fails.
    pub async fn create_session_for_client(
        &self,
        user_id: &str,
        email: &str,
        auth_id: &str,
        client_id: &str,
    ) -> Result<String> {
        let token = test_utils::create_test_session_for_client(
            &self.state,
            user_id,
            email,
            auth_id,
            client_id,
        )
        .await;
        Ok(token)
    }

    /// Create a fully set up user with an authenticator and session.
    ///
    /// Returns (user, auth_id, token).
    ///
    /// # Errors
    ///
    /// Returns an error if setup fails.
    pub async fn create_authenticated_user(
        &self,
        email: &str,
    ) -> Result<(vouch_server::db::User, String, String)> {
        let user = self.create_user(email).await?;
        let auth_id = self.create_authenticator(&user.id).await?;
        let token = self.create_session(&user.id, email, &auth_id).await?;
        Ok((user, auth_id, token))
    }

    /// Create a test organization.
    ///
    /// # Errors
    ///
    /// Returns an error if org creation fails.
    pub async fn create_org(&self, domain: &str) -> Result<db::Organization> {
        let org = test_utils::create_test_org(&self.state.store, domain).await;
        Ok(org)
    }

    /// Create a test user with organization membership.
    ///
    /// # Errors
    ///
    /// Returns an error if user creation fails.
    pub async fn create_user_in_org(
        &self,
        email: &str,
        org_id: &str,
        is_admin: bool,
    ) -> Result<vouch_server::db::User> {
        let user =
            test_utils::create_test_user_in_org(&self.state.store, email, org_id, is_admin).await;
        Ok(user)
    }

    /// Create a fully set up org admin with an authenticator and session.
    ///
    /// Returns (user, org, auth_id, token).
    ///
    /// # Errors
    ///
    /// Returns an error if setup fails.
    pub async fn create_authenticated_org_admin(
        &self,
        email: &str,
        domain: &str,
    ) -> Result<(vouch_server::db::User, db::Organization, String, String)> {
        let org = self.create_org(domain).await?;
        let user = self.create_user_in_org(email, &org.id, true).await?;
        let auth_id = self.create_authenticator(&user.id).await?;
        let token = self.create_session(&user.id, email, &auth_id).await?;
        Ok((user, org, auth_id, token))
    }

    /// Create a fully set up org member (non-admin) with an authenticator and session.
    ///
    /// Returns (user, auth_id, token).
    ///
    /// # Errors
    ///
    /// Returns an error if setup fails.
    pub async fn create_authenticated_org_member(
        &self,
        email: &str,
        org_id: &str,
    ) -> Result<(vouch_server::db::User, String, String)> {
        let user = self.create_user_in_org(email, org_id, false).await?;
        let auth_id = self.create_authenticator(&user.id).await?;
        let token = self.create_session(&user.id, email, &auth_id).await?;
        Ok((user, auth_id, token))
    }

    /// RFC 9421 signature headers for an authenticated `/v1/*` request.
    ///
    /// The `/v1/*` routes require a valid signature; sessions created by this
    /// harness use the first-party test client whose JWKS holds the shared test
    /// signing key, so we sign with that same key here. Non-`/v1` paths and the
    /// soft `/v1/auth/status` probe return no headers.
    fn v1_sig_headers(
        &self,
        method: &str,
        url: &str,
        body: Option<&[u8]>,
    ) -> Vec<(String, String)> {
        let path = url.strip_prefix(self.base_url()).unwrap_or(url);
        let path_only = path.split('?').next().unwrap_or(path);
        if !path_only.starts_with("/v1/") || path_only == "/v1/auth/status" {
            return Vec::new();
        }
        test_utils::test_signature_headers(method, url, body)
    }

    /// Make a GET request.
    pub async fn get(&self, path: &str) -> Result<vouch_cli::HttpResponse> {
        let url = self.url(path);
        self.http_client
            .request("GET", &url, None, None, None, None)
            .await
    }

    /// Make a POST request with JSON body.
    pub async fn post_json<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<vouch_cli::HttpResponse> {
        let url = self.url(path);
        let json = serde_json::to_vec(body)?;
        self.http_client
            .request(
                "POST",
                &url,
                Some(&json),
                Some("application/json"),
                None,
                None,
            )
            .await
    }

    /// Make an authenticated GET request.
    pub async fn get_authenticated(
        &self,
        path: &str,
        token: &str,
    ) -> Result<vouch_cli::HttpResponse> {
        let url = self.url(path);
        let auth = format!("Bearer {}", token);
        let sig = self.v1_sig_headers("GET", &url, None);
        let sig_refs: Vec<(&str, &str)> =
            sig.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let extra = (!sig_refs.is_empty()).then_some(sig_refs.as_slice());
        self.http_client
            .request("GET", &url, None, None, Some(&auth), extra)
            .await
    }

    /// Make an authenticated POST request with JSON body.
    pub async fn post_json_authenticated<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
        token: &str,
    ) -> Result<vouch_cli::HttpResponse> {
        let url = self.url(path);
        let json = serde_json::to_vec(body)?;
        let auth = format!("Bearer {}", token);
        let sig = self.v1_sig_headers("POST", &url, Some(&json));
        let sig_refs: Vec<(&str, &str)> =
            sig.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let extra = (!sig_refs.is_empty()).then_some(sig_refs.as_slice());
        self.http_client
            .request(
                "POST",
                &url,
                Some(&json),
                Some("application/json"),
                Some(&auth),
                extra,
            )
            .await
    }

    /// Advance the test clock by a number of hours.
    ///
    /// # Errors
    ///
    /// Returns an error if time advancement fails.
    pub fn advance_clock_hours(&self, hours: i64) -> Result<()> {
        self.clock.advance_hours(hours)?;
        Ok(())
    }

    /// Make an authenticated DELETE request.
    pub async fn delete_authenticated(
        &self,
        path: &str,
        token: &str,
    ) -> Result<vouch_cli::HttpResponse> {
        let url = self.url(path);
        let auth = format!("Bearer {}", token);
        let sig = self.v1_sig_headers("DELETE", &url, None);
        let sig_refs: Vec<(&str, &str)> =
            sig.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let extra = (!sig_refs.is_empty()).then_some(sig_refs.as_slice());
        self.http_client
            .request("DELETE", &url, None, None, Some(&auth), extra)
            .await
    }

    /// Make an authenticated PATCH request with JSON body.
    pub async fn patch_json_authenticated<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
        token: &str,
    ) -> Result<vouch_cli::HttpResponse> {
        let url = self.url(path);
        let json = serde_json::to_vec(body)?;
        let auth = format!("Bearer {}", token);
        let sig = self.v1_sig_headers("PATCH", &url, Some(&json));
        let sig_refs: Vec<(&str, &str)> =
            sig.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let extra = (!sig_refs.is_empty()).then_some(sig_refs.as_slice());
        self.http_client
            .request(
                "PATCH",
                &url,
                Some(&json),
                Some("application/json"),
                Some(&auth),
                extra,
            )
            .await
    }

    /// Make an authenticated PUT request with JSON body.
    pub async fn put_json_authenticated<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
        token: &str,
    ) -> Result<vouch_cli::HttpResponse> {
        let url = self.url(path);
        let json = serde_json::to_vec(body)?;
        let auth = format!("Bearer {}", token);
        let sig = self.v1_sig_headers("PUT", &url, Some(&json));
        let sig_refs: Vec<(&str, &str)> =
            sig.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let extra = (!sig_refs.is_empty()).then_some(sig_refs.as_slice());
        self.http_client
            .request(
                "PUT",
                &url,
                Some(&json),
                Some("application/json"),
                Some(&auth),
                extra,
            )
            .await
    }

    /// Make a POST request with form-urlencoded body.
    pub async fn post_form(&self, path: &str, body: &str) -> Result<vouch_cli::HttpResponse> {
        let url = self.url(path);
        self.http_client
            .request(
                "POST",
                &url,
                Some(body.as_bytes()),
                Some("application/x-www-form-urlencoded"),
                None,
                None,
            )
            .await
    }

    /// Make an authenticated POST request with form-urlencoded body.
    pub async fn post_form_authenticated(
        &self,
        path: &str,
        body: &str,
        token: &str,
    ) -> Result<vouch_cli::HttpResponse> {
        let url = self.url(path);
        let auth = format!("Bearer {}", token);
        self.http_client
            .request(
                "POST",
                &url,
                Some(body.as_bytes()),
                Some("application/x-www-form-urlencoded"),
                Some(&auth),
                None,
            )
            .await
    }

    /// Make a POST request with form-urlencoded body and a custom Authorization header.
    pub async fn post_form_with_auth(
        &self,
        path: &str,
        body: &str,
        auth_header: &str,
    ) -> Result<vouch_cli::HttpResponse> {
        let url = self.url(path);
        self.http_client
            .request(
                "POST",
                &url,
                Some(body.as_bytes()),
                Some("application/x-www-form-urlencoded"),
                Some(auth_header),
                None,
            )
            .await
    }

    /// Create a test OAuth client with secret for use in introspection/revocation tests.
    ///
    /// # Errors
    ///
    /// Returns an error if client creation fails.
    pub async fn create_oauth_client(&self, user_id: &str) -> Result<test_utils::TestOAuthClient> {
        let client = test_utils::create_test_oauth_client(&self.state.store, user_id).await;
        Ok(client)
    }

    /// Create a SCIM bearer token for testing, bound to the given org.
    ///
    /// `authenticate_scim` rejects tokens that have no `org_id`, so an
    /// org_id is required for any test that authenticates against SCIM
    /// endpoints.
    ///
    /// # Errors
    ///
    /// Returns an error if token creation fails.
    pub async fn create_scim_token(&self, description: &str, org_id: &str) -> Result<String> {
        let token =
            test_utils::create_test_scim_token(&self.state.store, description, org_id).await;
        Ok(token)
    }

    /// Authorize a device code for a user.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization fails.
    pub async fn authorize_device_code(
        &self,
        user_code: &str,
        user_id: &str,
        email: &str,
        auth_id: &str,
    ) -> Result<()> {
        // Look up device auth request by user code
        let request = vouch_server::db::get_device_auth_by_user_code(&self.state.store, user_code)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Device auth request not found"))?;

        // Authorize it
        vouch_server::db::authorize_device_auth(
            &self.state.store,
            &request.id,
            user_id,
            email,
            auth_id,
        )
        .await?;

        Ok(())
    }

    /// Create a session token that is not in the database (simulates revocation/expiration).
    ///
    /// Returns a valid JWT that will be rejected by the status endpoint because
    /// the corresponding session does not exist in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if token creation fails.
    pub async fn create_expired_token(&self, user_id: &str, email: &str, auth_id: &str) -> String {
        // Create a real session, then immediately delete it from the database.
        // This simulates an expired/revoked session — the token is valid JWT
        // but has no matching session record, so status returns authenticated: false.
        use vouch_server::crypto::hash_token;

        let token = test_utils::create_test_session(&self.state, user_id, email, auth_id).await;

        // Delete the session from the database to make it appear revoked
        let token_hash = hash_token(&token);
        let _ = db::delete_session_by_token_hash(&self.state.store, &token_hash).await;

        token
    }
}

impl std::fmt::Debug for TestHarness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestHarness")
            .field("base_url", &self.base_url())
            .finish_non_exhaustive()
    }
}
