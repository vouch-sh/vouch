// SPDX-License-Identifier: BUSL-1.1
//! Authorization code single-use enforcement (RFC 6749 Section 10.5).

use super::document_type::DocumentType;
use super::documents::authorization_code::AuthorizationCodeDoc;
use super::store::DocumentStore;
use anyhow::Result;
use jiff::Timestamp;

/// Record an issued authorization code.
pub async fn store_authorization_code(
    store: &DocumentStore,
    code_hash: &str,
    client_id: &str,
    user_id: &str,
    expires_at: Timestamp,
    authorization_details: Option<&serde_json::Value>,
) -> Result<()> {
    let doc = AuthorizationCodeDoc {
        code_hash: code_hash.to_string(),
        client_id: client_id.to_string(),
        user_id: user_id.to_string(),
        expires_at,
        consumed_at: None,
        authorization_details: authorization_details.cloned(),
    };
    store.insert(&doc).await?;
    Ok(())
}

/// Try to consume an authorization code.
///
/// Returns `true` if the code was successfully consumed (first use).
/// Returns `false` if already consumed, does not exist, or was
/// concurrently consumed by another request (optimistic lock).
pub async fn try_consume_authorization_code(
    store: &DocumentStore,
    code_hash: &str,
) -> Result<bool> {
    let now = Timestamp::now();

    let doc = store
        .find_one::<AuthorizationCodeDoc>("code_hash", code_hash)
        .await?;
    let Some(doc) = doc else {
        return Ok(false);
    };

    // Check: not consumed and not expired
    if doc.data.consumed_at.is_some() || doc.data.expires_at <= now {
        return Ok(false);
    }

    // Consume with optimistic concurrency — if another request already
    // consumed this code between our read and write, compare_and_update
    // returns false (version mismatch).
    let mut data = doc.data;
    data.consumed_at = Some(now);
    store.compare_and_update(&doc.id, doc.version, &data).await
}

/// Check if an authorization code has already been consumed.
pub async fn is_authorization_code_consumed(
    store: &DocumentStore,
    code_hash: &str,
) -> Result<bool> {
    let doc = store
        .find_one::<AuthorizationCodeDoc>("code_hash", code_hash)
        .await?;
    match doc {
        Some(d) => Ok(d.data.consumed_at.is_some()),
        None => Ok(false),
    }
}

/// Get user_id and client_id for a consumed authorization code.
///
/// Used during replay detection (RFC 6749 Section 10.5).
pub async fn get_authorization_code_owner(
    store: &DocumentStore,
    code_hash: &str,
) -> Result<Option<(String, String)>> {
    let doc = store
        .find_one::<AuthorizationCodeDoc>("code_hash", code_hash)
        .await?;
    Ok(doc.map(|d| (d.data.user_id, d.data.client_id)))
}

/// Check if consumed and return owner info for revocation.
pub async fn get_consumed_code_owner(
    store: &DocumentStore,
    code_hash: &str,
) -> Result<Option<(String, String)>> {
    let doc = store
        .find_one::<AuthorizationCodeDoc>("code_hash", code_hash)
        .await?;
    match doc {
        Some(d) if d.data.consumed_at.is_some() => Ok(Some((d.data.user_id, d.data.client_id))),
        _ => Ok(None),
    }
}

/// Get the authorization_details for an authorization code (RFC 9396).
///
/// Used after consuming the code to retrieve server-side stored
/// authorization details for the token response.
pub async fn get_authorization_code_details(
    store: &DocumentStore,
    code_hash: &str,
) -> Result<Option<serde_json::Value>> {
    let doc = store
        .find_one::<AuthorizationCodeDoc>("code_hash", code_hash)
        .await?;
    Ok(doc.and_then(|d| d.data.authorization_details))
}

/// Delete expired authorization codes.
pub async fn delete_expired_authorization_codes(store: &DocumentStore) -> Result<u64> {
    store.delete_expired(AuthorizationCodeDoc::DOC_TYPE).await
}
