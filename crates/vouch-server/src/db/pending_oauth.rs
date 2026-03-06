// SPDX-License-Identifier: BUSL-1.1
//! Pending OAuth authorization database operations.

use super::document_type::{Document, DocumentType};
use super::documents::pending_oauth::PendingOAuthAuthDoc;
use super::store::DocumentStore;
use anyhow::Result;
use jiff::{Span, Timestamp};

/// Pending OAuth authorization record.
#[derive(Debug)]
pub struct PendingOAuthAuthorization {
    pub id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub state: Option<String>,
    pub scope: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub consumed_at: Option<Timestamp>,
    /// RFC 8707: Resource indicator.
    pub resource: Option<String>,
    /// RFC 9470: ACR values.
    pub acr_values: Option<String>,
    /// RFC 9470: Max age.
    pub max_age: Option<i64>,
    /// RFC 9470: Prompt.
    pub prompt: Option<String>,
    /// RFC 9449 / FAPI 2.0: DPoP key thumbprint.
    pub dpop_jkt: Option<String>,
    /// RFC 9396: Rich authorization details (JSON string).
    pub authorization_details: Option<String>,
}

impl From<Document<PendingOAuthAuthDoc>> for PendingOAuthAuthorization {
    fn from(doc: Document<PendingOAuthAuthDoc>) -> Self {
        Self {
            id: doc.id,
            client_id: doc.data.client_id,
            redirect_uri: doc.data.redirect_uri,
            response_type: doc.data.response_type,
            state: doc.data.state,
            scope: doc.data.scope,
            nonce: doc.data.nonce,
            code_challenge: doc.data.code_challenge,
            code_challenge_method: doc.data.code_challenge_method,
            created_at: doc.created_at,
            expires_at: doc.data.expires_at,
            consumed_at: doc.data.consumed_at,
            resource: doc.data.resource,
            acr_values: doc.data.acr_values,
            max_age: doc.data.max_age,
            prompt: doc.data.prompt,
            dpop_jkt: doc.data.dpop_jkt,
            authorization_details: doc.data.authorization_details,
        }
    }
}

/// Parameters for creating a pending OAuth authorization.
#[derive(Debug)]
pub struct CreatePendingOAuthParams<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub response_type: &'a str,
    pub state: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub nonce: Option<&'a str>,
    pub code_challenge: Option<&'a str>,
    pub code_challenge_method: Option<&'a str>,
    pub resource: Option<&'a str>,
    pub acr_values: Option<&'a str>,
    pub max_age: Option<i64>,
    pub prompt: Option<&'a str>,
    pub dpop_jkt: Option<&'a str>,
    /// RFC 9396: Rich authorization details (JSON string).
    pub authorization_details: Option<&'a str>,
}

/// Create a pending OAuth authorization.
pub async fn create_pending_oauth_authorization(
    store: &DocumentStore,
    params: CreatePendingOAuthParams<'_>,
) -> Result<String> {
    let now = Timestamp::now();
    let expires_at = now
        .checked_add(Span::new().minutes(10))
        .map_err(|_| anyhow::anyhow!("Time calculation overflow computing expiration"))?;

    let doc = PendingOAuthAuthDoc {
        client_id: params.client_id.to_string(),
        redirect_uri: params.redirect_uri.to_string(),
        response_type: params.response_type.to_string(),
        state: params.state.map(String::from),
        scope: params.scope.map(String::from),
        nonce: params.nonce.map(String::from),
        code_challenge: params.code_challenge.map(String::from),
        code_challenge_method: params.code_challenge_method.map(String::from),
        expires_at,
        consumed_at: None,
        resource: params.resource.map(String::from),
        acr_values: params.acr_values.map(String::from),
        max_age: params.max_age,
        prompt: params.prompt.map(String::from),
        dpop_jkt: params.dpop_jkt.map(String::from),
        authorization_details: params.authorization_details.map(String::from),
    };
    let result = store.insert(&doc).await?;
    Ok(result.id)
}

/// Get a pending OAuth authorization by ID.
///
/// Returns None if not found, expired, or already consumed.
pub async fn get_pending_oauth_authorization(
    store: &DocumentStore,
    id: &str,
) -> Result<Option<PendingOAuthAuthorization>> {
    let now = Timestamp::now();

    let doc = store.get::<PendingOAuthAuthDoc>(id).await?;
    match doc {
        Some(d) if d.data.consumed_at.is_none() && d.data.expires_at > now => {
            Ok(Some(PendingOAuthAuthorization::from(d)))
        }
        _ => Ok(None),
    }
}

/// Consume a pending OAuth authorization (single-use).
///
/// The read and mark-as-consumed execute within a single transaction
/// to prevent a double-spend race between concurrent requests.
///
/// Returns None if not found, expired, or already consumed.
pub async fn consume_pending_oauth_authorization(
    store: &DocumentStore,
    id: &str,
) -> Result<Option<PendingOAuthAuthorization>> {
    let now = Timestamp::now();

    let mut tx = store.begin().await?;

    let doc = tx.get::<PendingOAuthAuthDoc>(id).await?;
    let Some(doc) = doc else {
        return Ok(None);
    };

    // Check conditions
    if doc.data.consumed_at.is_some() || doc.data.expires_at <= now {
        return Ok(None);
    }

    // Mark as consumed
    let mut data = doc.data;
    data.consumed_at = Some(now);
    tx.update(id, &data).await?;

    // Snapshot the consumed record before committing
    let updated = tx.get::<PendingOAuthAuthDoc>(id).await?;
    tx.commit().await?;

    Ok(updated.map(PendingOAuthAuthorization::from))
}

/// Delete expired pending OAuth authorizations.
pub async fn delete_expired_pending_oauth_authorizations(
    store: &DocumentStore,
    _now: &str,
) -> Result<u64> {
    store.delete_expired(PendingOAuthAuthDoc::DOC_TYPE).await
}
