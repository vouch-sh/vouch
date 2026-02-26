// SPDX-License-Identifier: BUSL-1.1
//! Session database operations.

use super::document_type::{Document, DocumentType};
use super::documents::session::SessionDoc;
use super::store::DocumentStore;
use anyhow::Result;
use jiff::Timestamp;

// Re-export SessionPurpose from documents module
pub use super::documents::session::SessionPurpose;

/// Session record.
#[derive(Debug)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub authenticator_id: Option<String>,
    pub expires_at: Timestamp,
    pub created_at: Timestamp,
    pub session_type: SessionPurpose,
}

impl From<Document<SessionDoc>> for Session {
    fn from(doc: Document<SessionDoc>) -> Self {
        Self {
            id: doc.id,
            user_id: doc.data.user_id,
            token_hash: doc.data.token_hash,
            authenticator_id: doc.data.authenticator_id,
            expires_at: doc.data.expires_at,
            created_at: doc.created_at,
            session_type: doc.data.session_type,
        }
    }
}

/// Create a new session.
///
/// `authenticator_id` is optional for OIDC-authenticated users who haven't
/// registered a security key yet.
/// `user_email` is denormalized into the session document.
pub async fn create_session(
    store: &DocumentStore,
    user_id: &str,
    user_email: &str,
    token_hash: &str,
    authenticator_id: Option<&str>,
    expires_at: Timestamp,
    session_type: SessionPurpose,
) -> Result<String> {
    let doc = SessionDoc {
        user_id: user_id.to_string(),
        user_email: user_email.to_string(),
        token_hash: token_hash.to_string(),
        authenticator_id: authenticator_id.map(String::from),
        session_type,
        expires_at,
    };
    let result = store.insert(&doc).await?;
    Ok(result.id)
}

/// Get a session by token hash.
///
/// Only returns sessions that have not yet expired.
pub async fn get_session_by_token_hash(
    store: &DocumentStore,
    token_hash: &str,
) -> Result<Option<Session>> {
    let doc = store
        .find_one::<SessionDoc>("token_hash", token_hash)
        .await?;
    let now = Timestamp::now();
    match doc {
        Some(d) if d.data.expires_at > now => Ok(Some(Session::from(d))),
        _ => Ok(None),
    }
}

/// Delete a session by token hash.
pub async fn delete_session_by_token_hash(store: &DocumentStore, token_hash: &str) -> Result<bool> {
    let count = store
        .delete_by_index::<SessionDoc>("token_hash", token_hash)
        .await?;
    Ok(count > 0)
}

/// Delete expired sessions.
pub async fn delete_expired_sessions(store: &DocumentStore, _now: &str) -> Result<u64> {
    store.delete_expired(SessionDoc::DOC_TYPE).await
}

/// Delete OAuth access token sessions for a user.
///
/// Used by authorization code replay detection (RFC 6749 Section 10.5) to
/// revoke all access tokens that may have been issued from a compromised code.
pub async fn delete_oauth_sessions_for_user(store: &DocumentStore, user_id: &str) -> Result<u64> {
    // Find all sessions for this user, filter for OAuth access tokens, delete
    let sessions = store.find_all::<SessionDoc>("user_id", user_id).await?;
    let mut count: u64 = 0;
    for session in &sessions {
        if session.data.session_type == SessionPurpose::OAuthAccessToken {
            store.delete(&session.id).await?;
            count += 1;
        }
    }
    Ok(count)
}

/// Delete all sessions for a user (for immediate session invalidation).
pub async fn delete_sessions_for_user(store: &DocumentStore, user_id: &str) -> Result<u64> {
    store
        .delete_by_index::<SessionDoc>("user_id", user_id)
        .await
}
