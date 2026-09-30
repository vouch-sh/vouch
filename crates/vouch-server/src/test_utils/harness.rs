// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A test server with fixture and request helpers.
//!
//! [`TestHarness`] holds the application state and its router, and drives
//! requests through [`http_request_full`], which signs authenticated `/v1/*`
//! requests with the shared test key.

use std::sync::Arc;

use anyhow::Result;
use axum::Router;
use vouch_common::protocol;

use super::{
    HttpResponse, TestOAuthClient, TestSessionSpec, create_test_authenticator,
    create_test_oauth_client, create_test_org, create_test_scim_token, create_test_session_with,
    create_test_user, create_test_user_in_org, http_request_full, test_app_state,
};
use crate::AppState;
use crate::crypto::hash_token;
use crate::crypto::webauthn_verify::AuthTime;
use crate::db::{self, AuthorizeDeviceAuthParams, User};
use crate::infra::router;

/// A test server: in-memory SQLite state and the router built over it.
pub struct TestHarness {
    /// Server application state.
    pub state: Arc<AppState>,
    /// The application router.
    pub router: Router,
}

impl TestHarness {
    /// A harness over the default test state.
    pub async fn new() -> Self {
        Self::from_state(test_app_state().await)
    }

    /// A harness over a pre-built `AppState`, for a test that needs
    /// non-default state (e.g. `test_app_state_with_rsa_key()`).
    ///
    /// # Panics
    ///
    /// Panics if the router cannot be built.
    #[expect(
        clippy::expect_used,
        reason = "test fixture: a router that cannot be built fails the test"
    )]
    pub fn from_state(state: Arc<AppState>) -> Self {
        let config = state.config();
        let router = router::build_app(state.clone(), &config).expect("build test app router");
        Self { state, router }
    }

    /// The base URL the test configuration serves.
    #[must_use]
    pub fn base_url(&self) -> &str {
        "https://test.example.com"
    }

    /// The full URL for an API path.
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url(), path)
    }

    /// Create a test user.
    ///
    /// # Errors
    ///
    /// Never; the `Result` keeps call sites uniform with the request helpers.
    pub async fn create_user(&self, email: &str) -> Result<User> {
        Ok(create_test_user(&self.state.store, email).await)
    }

    /// Create a test authenticator for a user and return its id.
    ///
    /// # Errors
    ///
    /// Never; see [`Self::create_user`].
    pub async fn create_authenticator(&self, user_id: &str) -> Result<String> {
        Ok(create_test_authenticator(&self.state.store, user_id).await)
    }

    /// Create a session and return its access token.
    ///
    /// # Errors
    ///
    /// Never; see [`Self::create_user`].
    pub async fn create_session(
        &self,
        user_id: &str,
        email: &str,
        auth_id: &str,
    ) -> Result<String> {
        Ok(create_test_session_with(
            &self.state,
            TestSessionSpec {
                user_id,
                email,
                auth_id: Some(auth_id),
                ..Default::default()
            },
        )
        .await)
    }

    /// Create a session bound to an OAuth client and return its access token.
    ///
    /// # Errors
    ///
    /// Never; see [`Self::create_user`].
    pub async fn create_session_for_client(
        &self,
        user_id: &str,
        email: &str,
        auth_id: &str,
        client_id: &str,
    ) -> Result<String> {
        Ok(create_test_session_with(
            &self.state,
            TestSessionSpec {
                user_id,
                email,
                auth_id: Some(auth_id),
                client_id: Some(client_id),
                ..Default::default()
            },
        )
        .await)
    }

    /// Create a user with an authenticator and a session.
    /// Returns `(user, auth_id, token)`.
    ///
    /// # Errors
    ///
    /// Never; see [`Self::create_user`].
    pub async fn create_authenticated_user(&self, email: &str) -> Result<(User, String, String)> {
        let user = self.create_user(email).await?;
        let auth_id = self.create_authenticator(&user.id).await?;
        let token = self.create_session(&user.id, email, &auth_id).await?;
        Ok((user, auth_id, token))
    }

    /// Create a test organization.
    ///
    /// # Errors
    ///
    /// Never; see [`Self::create_user`].
    pub async fn create_org(&self, domain: &str) -> Result<db::Organization> {
        Ok(create_test_org(&self.state.store, domain).await)
    }

    /// Create a test user in an organization.
    ///
    /// # Errors
    ///
    /// Never; see [`Self::create_user`].
    pub async fn create_user_in_org(
        &self,
        email: &str,
        org_id: &str,
        is_admin: bool,
    ) -> Result<User> {
        Ok(create_test_user_in_org(&self.state.store, email, org_id, is_admin).await)
    }

    /// Create an org admin with an authenticator and a session.
    /// Returns `(user, org, auth_id, token)`.
    ///
    /// # Errors
    ///
    /// Never; see [`Self::create_user`].
    pub async fn create_authenticated_org_admin(
        &self,
        email: &str,
        domain: &str,
    ) -> Result<(User, db::Organization, String, String)> {
        let org = self.create_org(domain).await?;
        let user = self.create_user_in_org(email, &org.id, true).await?;
        let auth_id = self.create_authenticator(&user.id).await?;
        let token = self.create_session(&user.id, email, &auth_id).await?;
        Ok((user, org, auth_id, token))
    }

    /// Create a non-admin org member with an authenticator and a session.
    /// Returns `(user, auth_id, token)`.
    ///
    /// # Errors
    ///
    /// Never; see [`Self::create_user`].
    pub async fn create_authenticated_org_member(
        &self,
        email: &str,
        org_id: &str,
    ) -> Result<(User, String, String)> {
        let user = self.create_user_in_org(email, org_id, false).await?;
        let auth_id = self.create_authenticator(&user.id).await?;
        let token = self.create_session(&user.id, email, &auth_id).await?;
        Ok((user, auth_id, token))
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<String>,
        content_type: Option<&str>,
        authorization: Option<&str>,
    ) -> Result<HttpResponse> {
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if let Some(content_type) = content_type {
            headers.push(("Content-Type", content_type));
        }
        if let Some(authorization) = authorization {
            headers.push(("Authorization", authorization));
        }
        Ok(http_request_full(&self.router, method, path, body, &headers).await)
    }

    fn bearer(token: &str) -> String {
        format!("{} {token}", protocol::AUTH_SCHEME_BEARER)
    }

    /// `GET path`.
    ///
    /// # Errors
    ///
    /// Never; a request failure panics inside [`http_request_full`].
    pub async fn get(&self, path: &str) -> Result<HttpResponse> {
        self.request("GET", path, None, None, None).await
    }

    /// `POST path` with a JSON body.
    ///
    /// # Errors
    ///
    /// Returns an error if `body` does not serialize.
    pub async fn post_json<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<HttpResponse> {
        let json = serde_json::to_string(body)?;
        self.request("POST", path, Some(json), Some("application/json"), None)
            .await
    }

    /// `GET path` with a Bearer token.
    ///
    /// # Errors
    ///
    /// Never; see [`Self::get`].
    pub async fn get_authenticated(&self, path: &str, token: &str) -> Result<HttpResponse> {
        self.request("GET", path, None, None, Some(&Self::bearer(token)))
            .await
    }

    /// `POST path` with a JSON body and a Bearer token.
    ///
    /// # Errors
    ///
    /// Returns an error if `body` does not serialize.
    pub async fn post_json_authenticated<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
        token: &str,
    ) -> Result<HttpResponse> {
        let json = serde_json::to_string(body)?;
        self.request(
            "POST",
            path,
            Some(json),
            Some("application/json"),
            Some(&Self::bearer(token)),
        )
        .await
    }

    /// `DELETE path` with a Bearer token.
    ///
    /// # Errors
    ///
    /// Never; see [`Self::get`].
    pub async fn delete_authenticated(&self, path: &str, token: &str) -> Result<HttpResponse> {
        self.request("DELETE", path, None, None, Some(&Self::bearer(token)))
            .await
    }

    /// `PATCH path` with a JSON body and a Bearer token.
    ///
    /// # Errors
    ///
    /// Returns an error if `body` does not serialize.
    pub async fn patch_json_authenticated<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
        token: &str,
    ) -> Result<HttpResponse> {
        let json = serde_json::to_string(body)?;
        self.request(
            "PATCH",
            path,
            Some(json),
            Some("application/json"),
            Some(&Self::bearer(token)),
        )
        .await
    }

    /// `PUT path` with a JSON body and a Bearer token.
    ///
    /// # Errors
    ///
    /// Returns an error if `body` does not serialize.
    pub async fn put_json_authenticated<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
        token: &str,
    ) -> Result<HttpResponse> {
        let json = serde_json::to_string(body)?;
        self.request(
            "PUT",
            path,
            Some(json),
            Some("application/json"),
            Some(&Self::bearer(token)),
        )
        .await
    }

    /// `POST path` with a form-urlencoded body.
    ///
    /// # Errors
    ///
    /// Never; see [`Self::get`].
    pub async fn post_form(&self, path: &str, body: &str) -> Result<HttpResponse> {
        self.request(
            "POST",
            path,
            Some(body.to_string()),
            Some(protocol::CONTENT_TYPE_FORM_URLENCODED),
            None,
        )
        .await
    }

    /// `POST path` with a form-urlencoded body and a Bearer token.
    ///
    /// # Errors
    ///
    /// Never; see [`Self::get`].
    pub async fn post_form_authenticated(
        &self,
        path: &str,
        body: &str,
        token: &str,
    ) -> Result<HttpResponse> {
        self.post_form_with_auth(path, body, &Self::bearer(token))
            .await
    }

    /// `POST path` with a form-urlencoded body and an `Authorization` value.
    ///
    /// # Errors
    ///
    /// Never; see [`Self::get`].
    pub async fn post_form_with_auth(
        &self,
        path: &str,
        body: &str,
        authorization: &str,
    ) -> Result<HttpResponse> {
        self.request(
            "POST",
            path,
            Some(body.to_string()),
            Some(protocol::CONTENT_TYPE_FORM_URLENCODED),
            Some(authorization),
        )
        .await
    }

    /// Create an OAuth client with a secret.
    ///
    /// # Errors
    ///
    /// Never; see [`Self::create_user`].
    pub async fn create_oauth_client(&self, user_id: &str) -> Result<TestOAuthClient> {
        Ok(create_test_oauth_client(&self.state.store, user_id).await)
    }

    /// Create a SCIM bearer token bound to an organization.
    ///
    /// # Errors
    ///
    /// Never; see [`Self::create_user`].
    pub async fn create_scim_token(&self, description: &str, org_id: &str) -> Result<String> {
        Ok(create_test_scim_token(&self.state.store, description, org_id).await)
    }

    /// Approve a pending device authorization for a user, as the browser
    /// assertion flow does.
    ///
    /// # Errors
    ///
    /// Returns an error if no request has `user_code`, or the store fails.
    #[expect(
        clippy::disallowed_methods,
        reason = "test fixtures construct their own instants"
    )]
    pub async fn authorize_device_code(
        &self,
        user_code: &str,
        user_id: &str,
        email: &str,
        auth_id: &str,
    ) -> Result<()> {
        let request = db::get_device_auth_by_user_code(&self.state.store, user_code)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Device auth request not found"))?;
        db::authorize_device_auth(
            &self.state.store,
            AuthorizeDeviceAuthParams {
                id: &request.id,
                user_id,
                user_email: email,
                authenticator_id: auth_id,
                verification: db::DeviceApproval::Observed(AuthTime::for_test(
                    jiff::Timestamp::now().as_second(),
                )),
            },
        )
        .await?;
        Ok(())
    }

    /// A signed access token whose session row is gone, as after revocation.
    ///
    /// # Panics
    ///
    /// Panics if the session cannot be deleted: the token would stay live and
    /// a caller asserting rejection would pass or fail for the wrong reason.
    #[expect(
        clippy::expect_used,
        reason = "test fixture: a session that survives would invalidate the caller's assertion"
    )]
    pub async fn create_expired_token(&self, user_id: &str, email: &str, auth_id: &str) -> String {
        let token = create_test_session_with(
            &self.state,
            TestSessionSpec {
                user_id,
                email,
                auth_id: Some(auth_id),
                ..Default::default()
            },
        )
        .await;
        self.state
            .session_cache
            .delete_by_token_hash(&self.state.store, &hash_token(&token))
            .await
            .expect("delete session to simulate revocation");
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
