//! Test harness for integration testing.
//!
//! This module provides a unified test harness that combines all the test
//! utilities from different crates into a single, easy-to-use interface.

use std::sync::Arc;

use anyhow::Result;

use vouch_cli::{HttpClient, TestHttpClient};
use vouch_common::TestClock;
use vouch_server::{AppState, test_utils};

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
    /// Controllable test clock.
    pub clock: Arc<TestClock>,
}

impl TestHarness {
    /// Create a new test harness with default configuration.
    pub async fn new() -> Self {
        let state = test_utils::test_app_state().await;
        let router = test_utils::test_router(state.clone());
        let http_client = TestHttpClient::new(router);
        let clock = Arc::new(TestClock::default());

        Self {
            state,
            http_client,
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
    pub async fn create_user(&self, email: &str) -> Result<vouch_server::User> {
        let user = test_utils::create_test_user(&self.state.db, email).await;
        Ok(user)
    }

    /// Create a test authenticator for a user.
    ///
    /// # Errors
    ///
    /// Returns an error if authenticator creation fails.
    pub async fn create_authenticator(&self, user_id: &str) -> Result<String> {
        let auth_id = test_utils::create_test_authenticator(&self.state.db, user_id).await;
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
    ) -> Result<(vouch_server::User, String, String)> {
        let user = self.create_user(email).await?;
        let auth_id = self.create_authenticator(&user.id).await?;
        let token = self.create_session(&user.id, email, &auth_id).await?;
        Ok((user, auth_id, token))
    }

    /// Make a GET request.
    pub async fn get(&self, path: &str) -> Result<vouch_cli::HttpResponse> {
        let url = self.url(path);
        self.http_client
            .request("GET", &url, None, None, None)
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
            .request("POST", &url, Some(&json), Some("application/json"), None)
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
        self.http_client
            .request("GET", &url, None, None, Some(&auth))
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
        self.http_client
            .request(
                "POST",
                &url,
                Some(&json),
                Some("application/json"),
                Some(&auth),
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
}

impl std::fmt::Debug for TestHarness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestHarness")
            .field("base_url", &self.base_url())
            .finish_non_exhaustive()
    }
}
