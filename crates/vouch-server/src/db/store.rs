// SPDX-License-Identifier: BUSL-1.1
//! Encrypted document store backed by 3 tables.
//!
//! [`DocumentStore`] provides typed CRUD operations over the `documents` and
//! `document_indexes` tables. All data is encrypted/decrypted transparently
//! via the [`DocumentCrypto`] trait, and index values are HMAC-hashed in
//! production for blind equality lookups.
//!
//! # Transactions
//!
//! Use [`DocumentStore::begin`] to obtain a [`StoreTransaction`] when multiple
//! operations must execute atomically. All write methods on `DocumentStore`
//! are single-operation wrappers that open, execute, and commit a transaction
//! internally.

use std::sync::Arc;

use anyhow::{Context, Result};
use jiff::Timestamp;
use sea_query::{Cond, Expr, Iden, Order, Query};

use super::document_type::{Document, DocumentType};
use super::pool::Pool;
use crate::crypto::document_crypto::{DocumentCrypto, EncryptedDocument};

// ============================================================================
// Schema Iden Enums (local to store — used by sea-query)
// ============================================================================

#[derive(Iden)]
enum Documents {
    Table,
    Id,
    DocType,
    SchemaVersion,
    EncappedKey,
    Data,
    ExpiresAt,
    CreatedAt,
    UpdatedAt,
    Version,
    LastUsedAt,
}

/// All document columns (unqualified) for `SELECT` statements on a
/// single table.
const DOC_COLUMNS: [Documents; 10] = [
    Documents::Id,
    Documents::DocType,
    Documents::SchemaVersion,
    Documents::EncappedKey,
    Documents::Data,
    Documents::ExpiresAt,
    Documents::CreatedAt,
    Documents::UpdatedAt,
    Documents::Version,
    Documents::LastUsedAt,
];

/// All document columns qualified with the table name, for `SELECT`
/// statements involving joins.
const DOC_TABLE_COLUMNS: [(Documents, Documents); 10] = [
    (Documents::Table, Documents::Id),
    (Documents::Table, Documents::DocType),
    (Documents::Table, Documents::SchemaVersion),
    (Documents::Table, Documents::EncappedKey),
    (Documents::Table, Documents::Data),
    (Documents::Table, Documents::ExpiresAt),
    (Documents::Table, Documents::CreatedAt),
    (Documents::Table, Documents::UpdatedAt),
    (Documents::Table, Documents::Version),
    (Documents::Table, Documents::LastUsedAt),
];

#[derive(Iden)]
enum DocumentIndexes {
    Table,
    Id,
    DocumentId,
    IndexField,
    IndexValue,
}

/// Build an INSERT statement for a single document index entry.
///
/// Used by both `DocumentStore` and `StoreTransaction` write paths to avoid
/// duplicating the index insertion logic.
fn build_index_insert(
    crypto: &dyn DocumentCrypto,
    doc_id: &str,
    entry: &super::document_type::IndexEntry,
) -> Result<sea_query::InsertStatement> {
    let index_id = uuid::Uuid::now_v7().to_string();
    let hashed_value = crypto.hmac_index(&entry.value);
    let stmt = Query::insert()
        .into_table(DocumentIndexes::Table)
        .columns([
            DocumentIndexes::Id,
            DocumentIndexes::DocumentId,
            DocumentIndexes::IndexField,
            DocumentIndexes::IndexValue,
        ])
        .values([
            index_id.as_str().into(),
            doc_id.into(),
            entry.field.into(),
            hashed_value.as_str().into(),
        ])?
        .to_owned();
    Ok(stmt)
}

// ============================================================================
// Raw Row Types (for sqlx FromRow)
// ============================================================================

/// Raw row from the `documents` table.
#[derive(sqlx::FromRow)]
struct RawDocumentRow {
    id: String,
    #[allow(dead_code)]
    doc_type: String,
    schema_version: i32,
    encapped_key: Option<String>,
    data: String,
    expires_at: Option<String>,
    created_at: String,
    updated_at: String,
    version: i32,
    last_used_at: Option<String>,
    /// Window-function total count, present only in paginated queries.
    #[sqlx(default)]
    total_count: Option<i64>,
}

/// Raw row with just an id column (for expired doc lookups).
#[derive(sqlx::FromRow)]
struct IdRow {
    id: String,
}

// ============================================================================
// Shared Pure Helpers
// ============================================================================

/// Output of serializing and encrypting a document for storage.
struct SerializedDoc {
    /// Raw JSON bytes (used to deserialize back after insert).
    json: Vec<u8>,
    /// Encrypted payload.
    encrypted: EncryptedDocument,
    /// ISO 8601 expiration timestamp string, if the document expires.
    expires_str: Option<String>,
    /// Index entries to write to `document_indexes`.
    indexes: Vec<super::document_type::IndexEntry>,
}

/// Serialize and encrypt a document, returning everything needed for storage.
///
/// # Errors
///
/// Returns an error if serialization or encryption fails.
fn serialize_and_encrypt<T: DocumentType>(
    crypto: &Arc<dyn DocumentCrypto>,
    id: &str,
    doc: &T,
) -> Result<SerializedDoc> {
    let json = serde_json::to_vec(doc).context("failed to serialize document")?;
    let encrypted = crypto.seal(T::DOC_TYPE.as_bytes(), id.as_bytes(), &json)?;
    let expires_str = doc.expires_at().map(|ts| ts.to_string());
    let indexes = doc.index_entries();
    Ok(SerializedDoc {
        json,
        encrypted,
        expires_str,
        indexes,
    })
}

/// Decrypt and deserialize a raw row into a typed document.
///
/// # Errors
///
/// Returns an error if decryption or deserialization fails.
fn raw_to_document<T: DocumentType>(
    crypto: &Arc<dyn DocumentCrypto>,
    row: RawDocumentRow,
) -> Result<Document<T>> {
    let encrypted_doc = EncryptedDocument {
        encapped_key: row.encapped_key,
        data: row.data,
    };

    let json_bytes = crypto.open(T::DOC_TYPE.as_bytes(), row.id.as_bytes(), &encrypted_doc)?;

    #[allow(clippy::cast_sign_loss)]
    let version = row.schema_version as u32;
    let typed_data = if version < T::CURRENT_VERSION {
        let value: serde_json::Value =
            serde_json::from_slice(&json_bytes).context("failed to parse document JSON")?;
        T::migrate(version, value)?
    } else if version > T::CURRENT_VERSION {
        tracing::warn!(
            doc_type = T::DOC_TYPE,
            stored_version = version,
            current_version = T::CURRENT_VERSION,
            "document has newer schema version than current code"
        );
        serde_json::from_slice(&json_bytes).context("failed to deserialize document")?
    } else {
        serde_json::from_slice(&json_bytes).context("failed to deserialize document")?
    };

    let created_at: Timestamp = row
        .created_at
        .parse()
        .context("failed to parse created_at timestamp")?;
    let updated_at: Timestamp = row
        .updated_at
        .parse()
        .context("failed to parse updated_at timestamp")?;
    let expires_at = row
        .expires_at
        .map(|s| s.parse::<Timestamp>())
        .transpose()
        .context("failed to parse expires_at timestamp")?;
    let last_used_at = row
        .last_used_at
        .map(|s| s.parse::<Timestamp>())
        .transpose()
        .context("failed to parse last_used_at timestamp")?;

    Ok(Document {
        id: row.id,
        data: typed_data,
        created_at,
        updated_at,
        expires_at,
        version: row.version,
        last_used_at,
    })
}

/// Build an index-value match expression.
///
/// In HPKE mode, matches both the HMAC-hashed value (new rows) and
/// the plaintext value (pre-encryption rows) using `IN`. In plaintext
/// mode, the hash equals the value so this reduces to a single `=`.
///
/// This is a temporary migration bridge. Once all rows have been
/// re-encrypted and their indexes HMAC-hashed (via update-on-read or
/// background job), this can revert to a simple equality check.
fn index_value_condition(crypto: &dyn DocumentCrypto, value: &str) -> sea_query::SimpleExpr {
    let hashed = crypto.hmac_index(value);
    let col = Expr::col((DocumentIndexes::Table, DocumentIndexes::IndexValue));
    if hashed == value {
        col.eq(value.to_string())
    } else {
        col.is_in([hashed, value.to_string()])
    }
}

/// Like [`index_value_condition`] but references `index_value` through a
/// join alias instead of the canonical `DocumentIndexes` table name.
///
/// Used by `find_by_indexes` to build self-join conditions for each
/// additional criterion without aliasing conflicts.
fn index_value_condition_aliased(
    crypto: &dyn DocumentCrypto,
    value: &str,
    alias: &sea_query::Alias,
) -> sea_query::SimpleExpr {
    let hashed = crypto.hmac_index(value);
    let col = Expr::col((alias.clone(), DocumentIndexes::IndexValue));
    if hashed == value {
        col.eq(value.to_string())
    } else {
        col.is_in([hashed, value.to_string()])
    }
}

// ============================================================================
// DocumentStore
// ============================================================================

/// Core abstraction for the encrypted document store.
///
/// Wraps a database pool and a crypto implementation. All serialization,
/// encryption, index hashing, and query building happen here.
#[derive(Clone)]
pub struct DocumentStore {
    pool: Pool,
    crypto: Arc<dyn DocumentCrypto>,
}

impl DocumentStore {
    /// Create a new document store.
    #[must_use]
    pub fn new(pool: Pool, crypto: Arc<dyn DocumentCrypto>) -> Self {
        Self { pool, crypto }
    }

    /// Access the underlying pool (for migrations and raw queries).
    #[must_use]
    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    /// Access the crypto implementation.
    #[must_use]
    pub fn crypto(&self) -> &Arc<dyn DocumentCrypto> {
        &self.crypto
    }

    /// Begin a new store transaction.
    ///
    /// All operations on the returned [`StoreTransaction`] execute within a
    /// single database transaction. Call [`StoreTransaction::commit`] to
    /// persist changes, or let it drop to roll back.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying database transaction cannot be
    /// started.
    pub async fn begin(&self) -> Result<StoreTransaction<'_>> {
        let tx = self.pool.begin().await?;
        Ok(StoreTransaction {
            tx,
            crypto: &self.crypto,
        })
    }

    // ========================================================================
    // Insert
    // ========================================================================

    /// Insert a new document with an auto-generated UUID v7 ID.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization, encryption, or the database write
    /// fails.
    pub async fn insert<T: DocumentType>(&self, doc: &T) -> Result<Document<T>> {
        crate::with_dsql_retry!(async {
            let id = uuid::Uuid::now_v7().to_string();
            let mut tx = self.begin().await?;
            let result = tx.insert_with_id(&id, doc).await?;
            tx.commit().await?;
            Ok(result)
        })
    }

    /// Insert a new document with a caller-specified ID.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization, encryption, or the database write
    /// fails.
    pub async fn insert_with_id<T: DocumentType>(&self, id: &str, doc: &T) -> Result<Document<T>> {
        crate::with_dsql_retry!(async {
            let mut tx = self.begin().await?;
            let result = tx.insert_with_id(id, doc).await?;
            tx.commit().await?;
            Ok(result)
        })
    }

    // ========================================================================
    // Get by ID
    // ========================================================================

    /// Get a single document by ID.
    ///
    /// Returns `None` if the document doesn't exist.
    /// Callers must check `expires_at` if the document type
    /// supports expiration.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption or deserialization fails.
    pub async fn get<T: DocumentType>(&self, id: &str) -> Result<Option<Document<T>>> {
        let stmt = Query::select()
            .columns(DOC_COLUMNS)
            .from(Documents::Table)
            .and_where(Expr::col(Documents::Id).eq(id))
            .and_where(Expr::col(Documents::DocType).eq(T::DOC_TYPE))
            .to_owned();

        let row: Option<RawDocumentRow> =
            crate::db_fetch_optional!(&self.pool, stmt, RawDocumentRow)?;

        match row {
            Some(row) => raw_to_document::<T>(&self.crypto, row).map(Some),
            None => Ok(None),
        }
    }

    /// Get multiple documents by their IDs.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption or deserialization fails.
    pub async fn get_many<T: DocumentType>(&self, ids: &[&str]) -> Result<Vec<Document<T>>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        let stmt = Query::select()
            .columns(DOC_COLUMNS)
            .from(Documents::Table)
            .and_where(Expr::col(Documents::Id).is_in(ids.iter().copied()))
            .and_where(Expr::col(Documents::DocType).eq(T::DOC_TYPE))
            .to_owned();

        let rows: Vec<RawDocumentRow> = crate::db_fetch_all!(&self.pool, stmt, RawDocumentRow)?;

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            results.push(raw_to_document::<T>(&self.crypto, row)?);
        }
        Ok(results)
    }

    // ========================================================================
    // Find by Index
    // ========================================================================

    /// Find a single document by an indexed field.
    ///
    /// Returns `None` if no matching, non-expired document exists.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption or deserialization fails.
    pub async fn find_one<T: DocumentType>(
        &self,
        field: &str,
        value: &str,
    ) -> Result<Option<Document<T>>> {
        let index_cond = index_value_condition(&*self.crypto, value);

        let stmt = Query::select()
            .columns(DOC_TABLE_COLUMNS)
            .from(Documents::Table)
            .inner_join(
                DocumentIndexes::Table,
                Expr::col((Documents::Table, Documents::Id))
                    .equals((DocumentIndexes::Table, DocumentIndexes::DocumentId)),
            )
            .and_where(Expr::col((Documents::Table, Documents::DocType)).eq(T::DOC_TYPE))
            .and_where(Expr::col((DocumentIndexes::Table, DocumentIndexes::IndexField)).eq(field))
            .and_where(index_cond)
            .order_by((Documents::Table, Documents::CreatedAt), Order::Desc)
            .limit(1)
            .to_owned();

        let row: Option<RawDocumentRow> =
            crate::db_fetch_optional!(&self.pool, stmt, RawDocumentRow)?;

        row.map(|r| raw_to_document::<T>(&self.crypto, r))
            .transpose()
    }

    /// Find all documents matching an indexed field.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption or deserialization fails.
    pub async fn find_all<T: DocumentType>(
        &self,
        field: &str,
        value: &str,
    ) -> Result<Vec<Document<T>>> {
        let index_cond = index_value_condition(&*self.crypto, value);

        let stmt = Query::select()
            .columns(DOC_TABLE_COLUMNS)
            .from(Documents::Table)
            .inner_join(
                DocumentIndexes::Table,
                Expr::col((Documents::Table, Documents::Id))
                    .equals((DocumentIndexes::Table, DocumentIndexes::DocumentId)),
            )
            .and_where(Expr::col((Documents::Table, Documents::DocType)).eq(T::DOC_TYPE))
            .and_where(Expr::col((DocumentIndexes::Table, DocumentIndexes::IndexField)).eq(field))
            .and_where(index_cond)
            .to_owned();

        let rows: Vec<RawDocumentRow> = crate::db_fetch_all!(&self.pool, stmt, RawDocumentRow)?;

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            results.push(raw_to_document::<T>(&self.crypto, row)?);
        }
        Ok(results)
    }

    /// Find documents matching an indexed field with cursor-based pagination.
    ///
    /// Returns up to `limit` documents ordered by ID (UUID v7, time-ordered).
    /// If `after_id` is `Some`, only returns documents with IDs greater than the cursor.
    /// The boolean indicates whether more results exist beyond this page.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption or deserialization fails.
    pub async fn find_paginated<T: DocumentType>(
        &self,
        field: &str,
        value: &str,
        after_id: Option<&str>,
        limit: u64,
    ) -> Result<(Vec<Document<T>>, bool)> {
        let index_cond = index_value_condition(&*self.crypto, value);

        let mut query = Query::select();
        query
            .columns(DOC_TABLE_COLUMNS)
            .from(Documents::Table)
            .inner_join(
                DocumentIndexes::Table,
                Expr::col((Documents::Table, Documents::Id))
                    .equals((DocumentIndexes::Table, DocumentIndexes::DocumentId)),
            )
            .and_where(Expr::col((Documents::Table, Documents::DocType)).eq(T::DOC_TYPE))
            .and_where(Expr::col((DocumentIndexes::Table, DocumentIndexes::IndexField)).eq(field))
            .and_where(index_cond);

        if let Some(cursor) = after_id {
            query.and_where(Expr::col((Documents::Table, Documents::Id)).gt(cursor));
        }

        // Fetch one extra to detect whether there are more pages.
        let stmt = query
            .order_by((Documents::Table, Documents::Id), Order::Asc)
            .limit(limit + 1)
            .to_owned();

        let rows: Vec<RawDocumentRow> = crate::db_fetch_all!(&self.pool, stmt, RawDocumentRow)?;

        let has_more = rows.len() as u64 > limit;
        let take = if has_more { limit as usize } else { rows.len() };

        let mut results = Vec::with_capacity(take);
        for row in rows.into_iter().take(take) {
            results.push(raw_to_document::<T>(&self.crypto, row)?);
        }
        Ok((results, has_more))
    }

    /// Find documents matching multiple index criteria (AND).
    ///
    /// Each criterion is pushed into SQL as an INNER JOIN on `document_indexes`,
    /// one join per criterion. This avoids loading all candidates for the first
    /// criterion into memory when many rows match.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption or deserialization fails.
    pub async fn find_by_indexes<T: DocumentType>(
        &self,
        criteria: &[(&str, &str)],
    ) -> Result<Vec<Document<T>>> {
        if criteria.is_empty() {
            return Ok(Vec::new());
        }

        let mut query = Query::select();
        query
            .columns(DOC_TABLE_COLUMNS)
            .from(Documents::Table)
            .and_where(Expr::col((Documents::Table, Documents::DocType)).eq(T::DOC_TYPE));

        for (i, (field, value)) in criteria.iter().enumerate() {
            let alias = sea_query::Alias::new(format!("i{i}"));
            let join_cond = Cond::all()
                .add(
                    Expr::col((Documents::Table, Documents::Id))
                        .equals((alias.clone(), DocumentIndexes::DocumentId)),
                )
                .add(Expr::col((alias.clone(), DocumentIndexes::IndexField)).eq(*field))
                .add(index_value_condition_aliased(&*self.crypto, value, &alias));
            query.join_as(
                sea_query::JoinType::InnerJoin,
                DocumentIndexes::Table,
                alias,
                join_cond,
            );
        }

        let stmt = query.to_owned();
        let rows: Vec<RawDocumentRow> = crate::db_fetch_all!(&self.pool, stmt, RawDocumentRow)?;

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            results.push(raw_to_document::<T>(&self.crypto, row)?);
        }
        Ok(results)
    }

    // ========================================================================
    // Update
    // ========================================================================

    /// Update a document's data by ID.
    ///
    /// Re-encrypts the data and rebuilds all index entries.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization, encryption, or the database write
    /// fails.
    pub async fn update<T: DocumentType>(&self, id: &str, doc: &T) -> Result<()> {
        crate::with_dsql_retry!(async {
            let mut tx = self.begin().await?;
            tx.update(id, doc).await?;
            tx.commit().await
        })
    }

    /// Update only the `last_used_at` column for a document.
    ///
    /// This is a lightweight operation that does not touch the encrypted
    /// data, version, or `updated_at` columns — no decrypt/encrypt cycle.
    ///
    /// # Errors
    ///
    /// Returns an error if the database write fails.
    pub async fn update_last_used_at(&self, id: &str) -> Result<()> {
        crate::with_dsql_retry!(async {
            let now_str = Timestamp::now().to_string();
            let stmt = {
                let mut q = Query::update();
                q.table(Documents::Table)
                    .value(Documents::LastUsedAt, Expr::val(now_str.as_str()))
                    .and_where(Expr::col(Documents::Id).eq(id));
                q.to_owned()
            };
            crate::db_execute!(&self.pool, stmt)?;
            Ok(())
        })
    }

    /// Read a document, apply a modifier, and write it back.
    ///
    /// On version conflict the document is re-read and the modifier is
    /// re-applied, up to [`MAX_DSQL_RETRIES`](super::pool::MAX_DSQL_RETRIES)
    /// times.  Transient DSQL errors are handled by `compare_and_update`
    /// internally.
    ///
    /// Returns `false` if the document does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails after retries.
    pub async fn modify<T, F>(&self, id: &str, modifier: F) -> Result<bool>
    where
        T: DocumentType,
        F: Fn(&mut T),
    {
        for attempt in 0..=super::pool::MAX_DSQL_RETRIES {
            let Some(doc) = self.get::<T>(id).await? else {
                return Ok(false);
            };
            let version = doc.version;
            let mut data = doc.data;
            modifier(&mut data);
            if self.compare_and_update(id, version, &data).await? {
                return Ok(true);
            }
            if attempt < super::pool::MAX_DSQL_RETRIES {
                tracing::debug!(doc_id = id, attempt, "version conflict in modify, retrying");
                tokio::time::sleep(super::pool::retry_backoff(attempt)).await;
            }
        }
        anyhow::bail!("version conflict after retries for document {id}")
    }

    /// Conditionally update a document only if its version matches.
    ///
    /// Returns `true` if the update succeeded, `false` if the document
    /// was modified by another request since it was read (optimistic
    /// concurrency control).
    ///
    /// # Errors
    ///
    /// Returns an error if serialization, encryption, or the database
    /// write fails.
    pub async fn compare_and_update<T: DocumentType>(
        &self,
        id: &str,
        expected_version: i32,
        doc: &T,
    ) -> Result<bool> {
        crate::with_dsql_retry!(async {
            let json = serde_json::to_vec(doc).context("failed to serialize document")?;
            let encrypted = self
                .crypto
                .seal(T::DOC_TYPE.as_bytes(), id.as_bytes(), &json)?;

            let now_str = Timestamp::now().to_string();
            let expires = doc.expires_at();
            let indexes = doc.index_entries();

            let encapped: Option<&str> = encrypted.encapped_key.as_deref();
            let expires_str = expires.map(|ts| ts.to_string());
            let expires_ref: Option<&str> = expires_str.as_deref();

            let mut tx = self.pool.begin().await?;

            // UPDATE with version guard (optimistic concurrency)
            let update_stmt = {
                let mut q = Query::update();
                q.table(Documents::Table)
                    .value(Documents::Data, Expr::val(encrypted.data.as_str()))
                    .value(Documents::EncappedKey, Expr::val(encapped))
                    .value(Documents::ExpiresAt, Expr::val(expires_ref))
                    .value(
                        Documents::SchemaVersion,
                        Expr::val(T::CURRENT_VERSION as i32),
                    )
                    .value(Documents::UpdatedAt, Expr::val(now_str.as_str()))
                    .value(Documents::Version, Expr::val(expected_version + 1))
                    .and_where(Expr::col(Documents::Id).eq(id))
                    .and_where(Expr::col(Documents::Version).eq(expected_version));
                q.to_owned()
            };

            let result = crate::tx_execute!(tx, update_stmt)?;

            if result.rows_affected() == 0 {
                // Version mismatch — concurrent modification detected
                return Ok(false);
            }

            // DELETE old indexes
            let delete_idx_stmt = Query::delete()
                .from_table(DocumentIndexes::Table)
                .and_where(Expr::col(DocumentIndexes::DocumentId).eq(id))
                .to_owned();

            crate::tx_execute!(tx, delete_idx_stmt)?;

            // INSERT new indexes
            for entry in &indexes {
                let idx_stmt = build_index_insert(self.crypto.as_ref(), id, entry)?;
                crate::tx_execute!(tx, idx_stmt)?;
            }

            tx.commit().await?;
            Ok(true)
        })
    }

    /// Update all documents matching an index, applying a modifier function.
    ///
    /// Decrypts each matching document, applies the modifier, re-encrypts,
    /// and updates within batched transactions. Each batch processes up to
    /// 500 documents (~3 statements per doc) to stay within DSQL's
    /// 3,000-statement transaction limit.
    ///
    /// Returns the number of documents updated.
    ///
    /// # Errors
    ///
    /// Returns an error if any read/write operation fails.
    pub async fn update_by_index<T, F>(&self, field: &str, value: &str, modifier: F) -> Result<u64>
    where
        T: DocumentType,
        F: Fn(&mut T),
    {
        crate::with_dsql_retry!(async {
            let mut docs = self.find_all::<T>(field, value).await?;
            let count = docs.len() as u64;
            for batch in docs.chunks_mut(500) {
                let mut tx = self.begin().await?;
                for doc in batch.iter_mut() {
                    modifier(&mut doc.data);
                    tx.update(&doc.id, &doc.data).await?;
                }
                tx.commit().await?;
            }
            Ok(count)
        })
    }

    // ========================================================================
    // Delete
    // ========================================================================

    /// Delete a document by ID (and its index entries).
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub async fn delete(&self, id: &str) -> Result<()> {
        crate::with_dsql_retry!(async {
            let mut tx = self.begin().await?;
            tx.delete(id).await?;
            tx.commit().await
        })
    }

    /// Delete all documents matching an index entry.
    ///
    /// Returns the number of documents deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub async fn delete_by_index<T: DocumentType>(&self, field: &str, value: &str) -> Result<u64> {
        crate::with_dsql_retry!(async {
            let mut tx = self.begin().await?;
            let total = tx.delete_by_index::<T>(field, value).await?;
            tx.commit().await?;
            Ok(total)
        })
    }

    /// Delete all expired documents of a given type.
    ///
    /// Batches deletes into transactions of up to 1,000 documents
    /// each (2 statements per batch) to stay within DSQL's
    /// 3,000-statement transaction limit.
    ///
    /// Returns the number of documents deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub async fn delete_expired(&self, doc_type: &str) -> Result<u64> {
        crate::with_dsql_retry!(async {
            let now = jiff::Timestamp::now().to_string();

            // Find expired document IDs
            let select_stmt = Query::select()
                .column(Documents::Id)
                .from(Documents::Table)
                .and_where(Expr::col(Documents::DocType).eq(doc_type))
                .and_where(Expr::col(Documents::ExpiresAt).is_not_null())
                .and_where(Expr::col(Documents::ExpiresAt).lt(now.as_str()))
                .to_owned();

            let rows: Vec<IdRow> = crate::db_fetch_all!(&self.pool, select_stmt, IdRow)?;

            let total = rows.len() as u64;
            // Batch deletes: 1,000 docs per tx (2 DELETE statements each)
            for batch in rows.chunks(1000) {
                let ids: Vec<sea_query::Value> =
                    batch.iter().map(|r| r.id.as_str().into()).collect();

                let mut tx = self.pool.begin().await?;

                let del_idx = Query::delete()
                    .from_table(DocumentIndexes::Table)
                    .and_where(Expr::col(DocumentIndexes::DocumentId).is_in(ids.clone()))
                    .to_owned();
                crate::tx_execute!(tx, del_idx)?;

                let del_doc = Query::delete()
                    .from_table(Documents::Table)
                    .and_where(Expr::col(Documents::Id).is_in(ids))
                    .to_owned();
                crate::tx_execute!(tx, del_doc)?;

                tx.commit().await?;
            }
            Ok(total)
        })
    }

    // ========================================================================
    // Count
    // ========================================================================

    /// Count documents matching an indexed field.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn count<T: DocumentType>(&self, field: &str, value: &str) -> Result<i64> {
        let index_cond = index_value_condition(&*self.crypto, value);

        let stmt = Query::select()
            .expr_as(
                Expr::col((Documents::Table, Documents::Id)).count(),
                sea_query::Alias::new("count"),
            )
            .from(Documents::Table)
            .inner_join(
                DocumentIndexes::Table,
                Expr::col((Documents::Table, Documents::Id))
                    .equals((DocumentIndexes::Table, DocumentIndexes::DocumentId)),
            )
            .and_where(Expr::col((Documents::Table, Documents::DocType)).eq(T::DOC_TYPE))
            .and_where(Expr::col((DocumentIndexes::Table, DocumentIndexes::IndexField)).eq(field))
            .and_where(index_cond)
            .to_owned();

        // Use a simple FromRow struct for the count result
        #[derive(sqlx::FromRow)]
        struct CountRow {
            #[sqlx(default)]
            count: i64,
        }

        let row: CountRow = crate::db_fetch_one!(&self.pool, stmt, CountRow)?;
        Ok(row.count)
    }

    /// Count all documents of a given type (no index join needed).
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn count_all<T: DocumentType>(&self) -> Result<i64> {
        let stmt = Query::select()
            .expr_as(
                Expr::col(Documents::Id).count(),
                sea_query::Alias::new("count"),
            )
            .from(Documents::Table)
            .and_where(Expr::col(Documents::DocType).eq(T::DOC_TYPE))
            .to_owned();

        #[derive(sqlx::FromRow)]
        struct CountRow {
            #[sqlx(default)]
            count: i64,
        }

        let row: CountRow = crate::db_fetch_one!(&self.pool, stmt, CountRow)?;
        Ok(row.count)
    }

    // ========================================================================
    // List all of a type
    // ========================================================================

    /// List all documents of a given type, ordered by creation time
    /// descending.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption or deserialization fails.
    pub async fn list_all<T: DocumentType>(&self) -> Result<Vec<Document<T>>> {
        let stmt = Query::select()
            .columns(DOC_COLUMNS)
            .from(Documents::Table)
            .and_where(Expr::col(Documents::DocType).eq(T::DOC_TYPE))
            .order_by(Documents::CreatedAt, Order::Desc)
            .to_owned();

        let rows: Vec<RawDocumentRow> = crate::db_fetch_all!(&self.pool, stmt, RawDocumentRow)?;

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            results.push(raw_to_document::<T>(&self.crypto, row)?);
        }
        Ok(results)
    }

    /// List documents of a given type with cursor-based pagination.
    ///
    /// Document IDs are UUIDv7s, so they are time-ordered and monotonically
    /// increasing. The cursor is simply the last `id` from the previous page;
    /// `WHERE id > $cursor` with `ORDER BY id ASC` gives stable pagination
    /// without needing a composite key.
    ///
    /// Fetches `limit + 1` rows; the extra row detects whether more pages
    /// exist without a separate COUNT query.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption or deserialization fails.
    pub async fn list_all_paginated<T: DocumentType>(
        &self,
        after_id: Option<&str>,
        limit: u64,
    ) -> Result<(Vec<Document<T>>, bool)> {
        let mut query = Query::select();
        query
            .columns(DOC_COLUMNS)
            .from(Documents::Table)
            .and_where(Expr::col(Documents::DocType).eq(T::DOC_TYPE));

        if let Some(cursor) = after_id {
            query.and_where(Expr::col(Documents::Id).gt(cursor));
        }

        let stmt = query
            .order_by(Documents::Id, Order::Asc)
            .limit(limit + 1)
            .to_owned();

        let rows: Vec<RawDocumentRow> = crate::db_fetch_all!(&self.pool, stmt, RawDocumentRow)?;

        let has_more = rows.len() as u64 > limit;
        let take = if has_more { limit as usize } else { rows.len() };

        let mut results = Vec::with_capacity(take);
        for row in rows.into_iter().take(take) {
            results.push(raw_to_document::<T>(&self.crypto, row)?);
        }
        Ok((results, has_more))
    }

    /// List documents with OFFSET pagination and a total count in one query.
    ///
    /// Uses `COUNT(*) OVER()` window function to return the total matching row
    /// count alongside the page results. Offset is capped at 10,000; requests
    /// beyond that return an error.
    ///
    /// Results are ordered by `id ASC` (UUIDv7 = insertion order).
    ///
    /// # Errors
    ///
    /// Returns an error if decryption or deserialization fails.
    ///
    /// # Panics safety
    ///
    /// Callers must validate `offset` before calling; large offsets
    /// will degrade performance on big tables.
    pub async fn list_all_paginated_with_count<T: DocumentType>(
        &self,
        offset: u64,
        limit: u64,
    ) -> Result<(Vec<Document<T>>, i64)> {
        let stmt = Query::select()
            .columns(DOC_COLUMNS)
            .expr_as(
                Expr::cust("COUNT(*) OVER()"),
                sea_query::Alias::new("total_count"),
            )
            .from(Documents::Table)
            .and_where(Expr::col(Documents::DocType).eq(T::DOC_TYPE))
            .order_by(Documents::Id, Order::Asc)
            .offset(offset)
            .limit(limit)
            .to_owned();

        let rows: Vec<RawDocumentRow> = crate::db_fetch_all!(&self.pool, stmt, RawDocumentRow)?;

        let total_count = rows.first().and_then(|r| r.total_count).unwrap_or_default();

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            results.push(raw_to_document::<T>(&self.crypto, row)?);
        }
        Ok((results, total_count))
    }
}

// Implement Debug manually to avoid exposing crypto internals.
impl std::fmt::Debug for DocumentStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DocumentStore")
            .field("pool", &self.pool)
            .field("crypto", &"<DocumentCrypto>")
            .finish()
    }
}

// ============================================================================
// StoreTransaction
// ============================================================================

/// A transactional document store session.
///
/// Created via [`DocumentStore::begin`]. All operations execute within a
/// single database transaction that is committed explicitly via
/// [`commit`](Self::commit) or rolled back on drop.
pub struct StoreTransaction<'a> {
    tx: super::pool::Transaction<'a>,
    crypto: &'a Arc<dyn DocumentCrypto>,
}

impl<'a> StoreTransaction<'a> {
    /// Commit the transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the commit fails.
    pub async fn commit(self) -> Result<()> {
        self.tx.commit().await
    }

    // ========================================================================
    // Insert
    // ========================================================================

    /// Insert a new document with an auto-generated UUID v7 ID.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization, encryption, or the database write
    /// fails.
    pub async fn insert<T: DocumentType>(&mut self, doc: &T) -> Result<Document<T>> {
        let id = uuid::Uuid::now_v7().to_string();
        self.insert_with_id(&id, doc).await
    }

    /// Insert a new document with a caller-specified ID.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization, encryption, or the database write
    /// fails.
    pub async fn insert_with_id<T: DocumentType>(
        &mut self,
        id: &str,
        doc: &T,
    ) -> Result<Document<T>> {
        let SerializedDoc {
            json,
            encrypted,
            expires_str,
            indexes,
        } = serialize_and_encrypt(self.crypto, id, doc)?;

        let now = Timestamp::now();
        let now_str = now.to_string();

        let encapped: Option<&str> = encrypted.encapped_key.as_deref();
        let expires_ref: Option<&str> = expires_str.as_deref();

        // INSERT document
        let insert_stmt = Query::insert()
            .into_table(Documents::Table)
            .columns(DOC_COLUMNS)
            .values([
                id.into(),
                T::DOC_TYPE.into(),
                (T::CURRENT_VERSION as i32).into(),
                encapped.into(),
                encrypted.data.as_str().into(),
                expires_ref.into(),
                now_str.as_str().into(),
                now_str.as_str().into(),
                1_i32.into(),
                Option::<&str>::None.into(),
            ])?
            .to_owned();

        crate::tx_execute!(self.tx, insert_stmt)?;

        // INSERT index entries
        for entry in &indexes {
            let idx_stmt = build_index_insert(self.crypto.as_ref(), id, entry)?;
            crate::tx_execute!(self.tx, idx_stmt)?;
        }

        let expires_at = expires_str
            .map(|s| s.parse::<Timestamp>())
            .transpose()
            .context("failed to parse expires_at timestamp")?;

        Ok(Document {
            id: id.to_string(),
            data: serde_json::from_slice(&json)
                .context("failed to deserialize inserted document")?,
            created_at: now,
            updated_at: now,
            expires_at,
            version: 1,
            last_used_at: None,
        })
    }

    // ========================================================================
    // Get by ID
    // ========================================================================

    /// Get a single document by ID within this transaction.
    ///
    /// Returns `None` if the document doesn't exist.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption or deserialization fails.
    pub async fn get<T: DocumentType>(&mut self, id: &str) -> Result<Option<Document<T>>> {
        let stmt = Query::select()
            .columns(DOC_COLUMNS)
            .from(Documents::Table)
            .and_where(Expr::col(Documents::Id).eq(id))
            .and_where(Expr::col(Documents::DocType).eq(T::DOC_TYPE))
            .to_owned();

        let row: Option<RawDocumentRow> = crate::tx_fetch_optional!(self.tx, stmt, RawDocumentRow)?;

        match row {
            Some(row) => raw_to_document::<T>(self.crypto, row).map(Some),
            None => Ok(None),
        }
    }

    // ========================================================================
    // Find by Index
    // ========================================================================

    /// Find a single document by an indexed field within this transaction.
    ///
    /// Returns `None` if no matching document exists.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption or deserialization fails.
    pub async fn find_one<T: DocumentType>(
        &mut self,
        field: &str,
        value: &str,
    ) -> Result<Option<Document<T>>> {
        let index_cond = index_value_condition(&**self.crypto, value);

        let stmt = Query::select()
            .columns(DOC_TABLE_COLUMNS)
            .from(Documents::Table)
            .inner_join(
                DocumentIndexes::Table,
                Expr::col((Documents::Table, Documents::Id))
                    .equals((DocumentIndexes::Table, DocumentIndexes::DocumentId)),
            )
            .and_where(Expr::col((Documents::Table, Documents::DocType)).eq(T::DOC_TYPE))
            .and_where(Expr::col((DocumentIndexes::Table, DocumentIndexes::IndexField)).eq(field))
            .and_where(index_cond)
            .order_by((Documents::Table, Documents::CreatedAt), Order::Desc)
            .limit(1)
            .to_owned();

        let row: Option<RawDocumentRow> = crate::tx_fetch_optional!(self.tx, stmt, RawDocumentRow)?;

        row.map(|r| raw_to_document::<T>(self.crypto, r))
            .transpose()
    }

    /// Find all documents matching an indexed field within this transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption or deserialization fails.
    pub async fn find_all<T: DocumentType>(
        &mut self,
        field: &str,
        value: &str,
    ) -> Result<Vec<Document<T>>> {
        let index_cond = index_value_condition(&**self.crypto, value);

        let stmt = Query::select()
            .columns(DOC_TABLE_COLUMNS)
            .from(Documents::Table)
            .inner_join(
                DocumentIndexes::Table,
                Expr::col((Documents::Table, Documents::Id))
                    .equals((DocumentIndexes::Table, DocumentIndexes::DocumentId)),
            )
            .and_where(Expr::col((Documents::Table, Documents::DocType)).eq(T::DOC_TYPE))
            .and_where(Expr::col((DocumentIndexes::Table, DocumentIndexes::IndexField)).eq(field))
            .and_where(index_cond)
            .to_owned();

        let rows: Vec<RawDocumentRow> = crate::tx_fetch_all!(self.tx, stmt, RawDocumentRow)?;

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            results.push(raw_to_document::<T>(self.crypto, row)?);
        }
        Ok(results)
    }

    // ========================================================================
    // Update
    // ========================================================================

    /// Update a document's data by ID within this transaction.
    ///
    /// Re-encrypts the data and rebuilds all index entries.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization, encryption, or the database write
    /// fails.
    pub async fn update<T: DocumentType>(&mut self, id: &str, doc: &T) -> Result<()> {
        let SerializedDoc {
            encrypted,
            expires_str,
            indexes,
            ..
        } = serialize_and_encrypt(self.crypto, id, doc)?;

        let now_str = Timestamp::now().to_string();

        let encapped: Option<&str> = encrypted.encapped_key.as_deref();
        let expires_ref: Option<&str> = expires_str.as_deref();

        // UPDATE document — scope the query builder so it drops before await
        let update_stmt = {
            let mut q = Query::update();
            q.table(Documents::Table)
                .value(Documents::Data, Expr::val(encrypted.data.as_str()))
                .value(Documents::EncappedKey, Expr::val(encapped))
                .value(Documents::ExpiresAt, Expr::val(expires_ref))
                .value(
                    Documents::SchemaVersion,
                    Expr::val(T::CURRENT_VERSION as i32),
                )
                .value(Documents::UpdatedAt, Expr::val(now_str.as_str()))
                .value(Documents::Version, Expr::col(Documents::Version).add(1))
                .and_where(Expr::col(Documents::Id).eq(id));
            q.to_owned()
        };

        crate::tx_execute!(self.tx, update_stmt)?;

        // DELETE old indexes
        let delete_idx_stmt = Query::delete()
            .from_table(DocumentIndexes::Table)
            .and_where(Expr::col(DocumentIndexes::DocumentId).eq(id))
            .to_owned();

        crate::tx_execute!(self.tx, delete_idx_stmt)?;

        // INSERT new indexes
        for entry in &indexes {
            let idx_stmt = build_index_insert(self.crypto.as_ref(), id, entry)?;
            crate::tx_execute!(self.tx, idx_stmt)?;
        }

        Ok(())
    }

    // ========================================================================
    // Delete
    // ========================================================================

    /// Delete a document by ID (and its index entries) within this
    /// transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub async fn delete(&mut self, id: &str) -> Result<()> {
        let delete_idx_stmt = Query::delete()
            .from_table(DocumentIndexes::Table)
            .and_where(Expr::col(DocumentIndexes::DocumentId).eq(id))
            .to_owned();

        crate::tx_execute!(self.tx, delete_idx_stmt)?;

        let delete_doc_stmt = Query::delete()
            .from_table(Documents::Table)
            .and_where(Expr::col(Documents::Id).eq(id))
            .to_owned();

        crate::tx_execute!(self.tx, delete_doc_stmt)?;

        Ok(())
    }

    /// Delete all documents matching an index entry within this transaction.
    ///
    /// Returns the number of documents deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub async fn delete_by_index<T: DocumentType>(
        &mut self,
        field: &str,
        value: &str,
    ) -> Result<u64> {
        let docs = self.find_all::<T>(field, value).await?;
        let total = docs.len() as u64;

        if docs.is_empty() {
            return Ok(0);
        }

        // Batch deletes in chunks of 1,000 to stay within DSQL statement
        // limits
        for batch in docs.chunks(1000) {
            let ids: Vec<sea_query::Value> = batch.iter().map(|d| d.id.as_str().into()).collect();

            let del_idx = Query::delete()
                .from_table(DocumentIndexes::Table)
                .and_where(Expr::col(DocumentIndexes::DocumentId).is_in(ids.clone()))
                .to_owned();
            crate::tx_execute!(self.tx, del_idx)?;

            let del_doc = Query::delete()
                .from_table(Documents::Table)
                .and_where(Expr::col(Documents::Id).is_in(ids))
                .to_owned();
            crate::tx_execute!(self.tx, del_doc)?;
        }

        Ok(total)
    }

    // ========================================================================
    // Count
    // ========================================================================

    /// Count documents matching an indexed field within this transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn count<T: DocumentType>(&mut self, field: &str, value: &str) -> Result<i64> {
        let index_cond = index_value_condition(&**self.crypto, value);

        let stmt = Query::select()
            .expr_as(
                Expr::col((Documents::Table, Documents::Id)).count(),
                sea_query::Alias::new("count"),
            )
            .from(Documents::Table)
            .inner_join(
                DocumentIndexes::Table,
                Expr::col((Documents::Table, Documents::Id))
                    .equals((DocumentIndexes::Table, DocumentIndexes::DocumentId)),
            )
            .and_where(Expr::col((Documents::Table, Documents::DocType)).eq(T::DOC_TYPE))
            .and_where(Expr::col((DocumentIndexes::Table, DocumentIndexes::IndexField)).eq(field))
            .and_where(index_cond)
            .to_owned();

        #[derive(sqlx::FromRow)]
        struct CountRow {
            #[sqlx(default)]
            count: i64,
        }

        let row: CountRow = crate::tx_fetch_one!(self.tx, stmt, CountRow)?;
        Ok(row.count)
    }

    // ========================================================================
    // Update by Index
    // ========================================================================

    /// Update all documents matching an index within this transaction.
    ///
    /// Decrypts each matching document, applies the modifier, re-encrypts,
    /// and updates. Returns the number of documents updated.
    ///
    /// # Errors
    ///
    /// Returns an error if any read/write operation fails.
    pub async fn update_by_index<T, F>(
        &mut self,
        field: &str,
        value: &str,
        modifier: F,
    ) -> Result<u64>
    where
        T: DocumentType,
        F: Fn(&mut T),
    {
        let docs = self.find_all::<T>(field, value).await?;
        let count = docs.len() as u64;
        for mut doc in docs {
            modifier(&mut doc.data);
            self.update(&doc.id, &doc.data).await?;
        }
        Ok(count)
    }

    // ========================================================================
    // Compare-and-Update
    // ========================================================================

    /// Conditionally update a document only if its version matches within
    /// this transaction.
    ///
    /// Returns `true` if the update succeeded, `false` if the document
    /// was modified by another request since it was read (optimistic
    /// concurrency control).
    ///
    /// # Errors
    ///
    /// Returns an error if serialization, encryption, or the database
    /// write fails.
    pub async fn compare_and_update<T: DocumentType>(
        &mut self,
        id: &str,
        expected_version: i32,
        doc: &T,
    ) -> Result<bool> {
        let json = serde_json::to_vec(doc).context("failed to serialize document")?;
        let encrypted = self
            .crypto
            .seal(T::DOC_TYPE.as_bytes(), id.as_bytes(), &json)?;

        let now_str = Timestamp::now().to_string();
        let expires = doc.expires_at();
        let indexes = doc.index_entries();

        let encapped: Option<&str> = encrypted.encapped_key.as_deref();
        let expires_str = expires.map(|ts| ts.to_string());
        let expires_ref: Option<&str> = expires_str.as_deref();

        let update_stmt = {
            let mut q = Query::update();
            q.table(Documents::Table)
                .value(Documents::Data, Expr::val(encrypted.data.as_str()))
                .value(Documents::EncappedKey, Expr::val(encapped))
                .value(Documents::ExpiresAt, Expr::val(expires_ref))
                .value(
                    Documents::SchemaVersion,
                    Expr::val(T::CURRENT_VERSION as i32),
                )
                .value(Documents::UpdatedAt, Expr::val(now_str.as_str()))
                .value(Documents::Version, Expr::val(expected_version + 1))
                .and_where(Expr::col(Documents::Id).eq(id))
                .and_where(Expr::col(Documents::Version).eq(expected_version));
            q.to_owned()
        };

        let result = crate::tx_execute!(self.tx, update_stmt)?;

        if result.rows_affected() == 0 {
            return Ok(false);
        }

        let delete_idx_stmt = Query::delete()
            .from_table(DocumentIndexes::Table)
            .and_where(Expr::col(DocumentIndexes::DocumentId).eq(id))
            .to_owned();
        crate::tx_execute!(self.tx, delete_idx_stmt)?;

        for entry in &indexes {
            let index_id = uuid::Uuid::now_v7().to_string();
            let hashed_value = self.crypto.hmac_index(&entry.value);
            let idx_stmt = Query::insert()
                .into_table(DocumentIndexes::Table)
                .columns([
                    DocumentIndexes::Id,
                    DocumentIndexes::DocumentId,
                    DocumentIndexes::IndexField,
                    DocumentIndexes::IndexValue,
                ])
                .values([
                    index_id.as_str().into(),
                    id.into(),
                    entry.field.into(),
                    hashed_value.as_str().into(),
                ])?
                .to_owned();
            crate::tx_execute!(self.tx, idx_stmt)?;
        }

        Ok(true)
    }
}

impl std::fmt::Debug for StoreTransaction<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreTransaction")
            .field("crypto", &"<DocumentCrypto>")
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::crypto::document_crypto::PlaintextDocumentCrypto;
    use crate::db::document_type::IndexEntry;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
    struct TestDoc {
        name: String,
        value: i32,
    }

    impl DocumentType for TestDoc {
        const DOC_TYPE: &'static str = "test";

        fn index_entries(&self) -> Vec<IndexEntry> {
            vec![IndexEntry {
                field: "name",
                value: self.name.clone(),
            }]
        }
    }

    #[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
    struct ExpiringDoc {
        token: String,
        expires: Timestamp,
    }

    impl DocumentType for ExpiringDoc {
        const DOC_TYPE: &'static str = "expiring";

        fn index_entries(&self) -> Vec<IndexEntry> {
            vec![IndexEntry {
                field: "token",
                value: self.token.clone(),
            }]
        }

        fn expires_at(&self) -> Option<Timestamp> {
            Some(self.expires)
        }
    }

    async fn test_store() -> DocumentStore {
        let pool = Pool::connect("sqlite::memory:", &crate::db::pool::PoolConfig::default())
            .await
            .unwrap();

        // Tests always use SQLite — execute raw DDL directly
        let Pool::Sqlite(ref p) = pool else {
            unreachable!()
        };
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS documents (
                id TEXT PRIMARY KEY,
                doc_type TEXT NOT NULL,
                schema_version INTEGER NOT NULL DEFAULT 1,
                encapped_key TEXT,
                data TEXT NOT NULL,
                expires_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                last_used_at TEXT
            )",
        )
        .execute(p)
        .await
        .unwrap();

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS document_indexes (
                id TEXT PRIMARY KEY,
                document_id TEXT NOT NULL,
                index_field TEXT NOT NULL,
                index_value TEXT NOT NULL,
                UNIQUE(document_id, index_field, index_value)
            )",
        )
        .execute(p)
        .await
        .unwrap();

        let crypto = Arc::new(PlaintextDocumentCrypto);
        DocumentStore::new(pool, crypto)
    }

    #[tokio::test]
    async fn insert_and_get() {
        let store = test_store().await;
        let doc = TestDoc {
            name: "alice".to_string(),
            value: 42,
        };

        let result = store.insert(&doc).await.unwrap();
        assert_eq!(result.data, doc);
        assert!(!result.id.is_empty());

        let fetched = store.get::<TestDoc>(&result.id).await.unwrap().unwrap();
        assert_eq!(fetched.data, doc);
        assert_eq!(fetched.id, result.id);
    }

    #[tokio::test]
    async fn insert_with_id() {
        let store = test_store().await;
        let doc = TestDoc {
            name: "bob".to_string(),
            value: 99,
        };

        let result = store.insert_with_id("custom-id", &doc).await.unwrap();
        assert_eq!(result.id, "custom-id");

        let fetched = store.get::<TestDoc>("custom-id").await.unwrap().unwrap();
        assert_eq!(fetched.data, doc);
    }

    #[tokio::test]
    async fn find_one_by_index() {
        let store = test_store().await;
        let doc = TestDoc {
            name: "carol".to_string(),
            value: 7,
        };
        store.insert(&doc).await.unwrap();

        let found = store
            .find_one::<TestDoc>("name", "carol")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.data, doc);

        let not_found = store
            .find_one::<TestDoc>("name", "nonexistent")
            .await
            .unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn find_all_by_index() {
        let store = test_store().await;

        for i in 0..3 {
            let doc = TestDoc {
                name: "shared".to_string(),
                value: i,
            };
            store.insert(&doc).await.unwrap();
        }

        let found = store.find_all::<TestDoc>("name", "shared").await.unwrap();
        assert_eq!(found.len(), 3);
    }

    #[tokio::test]
    async fn update_document() {
        let store = test_store().await;
        let doc = TestDoc {
            name: "dave".to_string(),
            value: 1,
        };
        let result = store.insert(&doc).await.unwrap();

        let updated = TestDoc {
            name: "dave-updated".to_string(),
            value: 2,
        };
        store.update(&result.id, &updated).await.unwrap();

        let fetched = store.get::<TestDoc>(&result.id).await.unwrap().unwrap();
        assert_eq!(fetched.data, updated);

        // Old index should be gone, new index should work
        let old = store.find_one::<TestDoc>("name", "dave").await.unwrap();
        assert!(old.is_none());

        let new = store
            .find_one::<TestDoc>("name", "dave-updated")
            .await
            .unwrap();
        assert!(new.is_some());
    }

    #[tokio::test]
    async fn delete_document() {
        let store = test_store().await;
        let doc = TestDoc {
            name: "eve".to_string(),
            value: 3,
        };
        let result = store.insert(&doc).await.unwrap();

        store.delete(&result.id).await.unwrap();

        let fetched = store.get::<TestDoc>(&result.id).await.unwrap();
        assert!(fetched.is_none());

        let found = store.find_one::<TestDoc>("name", "eve").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn delete_by_index() {
        let store = test_store().await;

        for i in 0..3 {
            let doc = TestDoc {
                name: "group".to_string(),
                value: i,
            };
            store.insert(&doc).await.unwrap();
        }

        let deleted = store
            .delete_by_index::<TestDoc>("name", "group")
            .await
            .unwrap();
        assert_eq!(deleted, 3);

        let remaining = store.find_all::<TestDoc>("name", "group").await.unwrap();
        assert!(remaining.is_empty());
    }

    #[tokio::test]
    async fn delete_expired() {
        let store = test_store().await;

        // Insert an already-expired document
        let doc = ExpiringDoc {
            token: "expired-token".to_string(),
            expires: "2020-01-01T00:00:00Z".parse().unwrap(),
        };
        store.insert(&doc).await.unwrap();

        // Insert a future-expiring document
        let doc2 = ExpiringDoc {
            token: "future-token".to_string(),
            expires: "2099-01-01T00:00:00Z".parse().unwrap(),
        };
        store.insert(&doc2).await.unwrap();

        let deleted = store.delete_expired("expiring").await.unwrap();
        assert_eq!(deleted, 1);

        // Future doc should still exist
        let found = store
            .find_one::<ExpiringDoc>("token", "future-token")
            .await
            .unwrap();
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn count_by_index() {
        let store = test_store().await;

        for i in 0..5 {
            let doc = TestDoc {
                name: "counted".to_string(),
                value: i,
            };
            store.insert(&doc).await.unwrap();
        }

        let count = store.count::<TestDoc>("name", "counted").await.unwrap();
        assert_eq!(count, 5);
    }

    #[tokio::test]
    async fn get_many() {
        let store = test_store().await;

        let mut ids = Vec::new();
        for i in 0..3 {
            let doc = TestDoc {
                name: format!("batch-{i}"),
                value: i,
            };
            let result = store.insert(&doc).await.unwrap();
            ids.push(result.id);
        }

        let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let fetched = store.get_many::<TestDoc>(&id_refs).await.unwrap();
        assert_eq!(fetched.len(), 3);
    }

    #[tokio::test]
    async fn update_by_index() {
        let store = test_store().await;

        for i in 0..3 {
            let doc = TestDoc {
                name: "updatable".to_string(),
                value: i,
            };
            store.insert(&doc).await.unwrap();
        }

        let updated = store
            .update_by_index::<TestDoc, _>("name", "updatable", |doc| {
                doc.value += 100;
            })
            .await
            .unwrap();
        assert_eq!(updated, 3);

        let docs = store
            .find_all::<TestDoc>("name", "updatable")
            .await
            .unwrap();
        for doc in &docs {
            assert!(doc.data.value >= 100);
        }
    }

    #[tokio::test]
    async fn list_all() {
        let store = test_store().await;

        for i in 0..3 {
            let doc = TestDoc {
                name: format!("list-{i}"),
                value: i,
            };
            store.insert(&doc).await.unwrap();
        }

        let all = store.list_all::<TestDoc>().await.unwrap();
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn get_nonexistent_returns_none() {
        let store = test_store().await;
        let result = store.get::<TestDoc>("nonexistent-id").await.unwrap();
        assert!(result.is_none());
    }

    // Document with two index fields for multi-criteria tests
    #[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
    struct MultiIndexDoc {
        org_id: String,
        role: String,
    }

    impl DocumentType for MultiIndexDoc {
        const DOC_TYPE: &'static str = "multi_idx";

        fn index_entries(&self) -> Vec<IndexEntry> {
            vec![
                IndexEntry {
                    field: "org_id",
                    value: self.org_id.clone(),
                },
                IndexEntry {
                    field: "role",
                    value: self.role.clone(),
                },
            ]
        }
    }

    #[tokio::test]
    async fn find_by_indexes_and_semantics() {
        let store = test_store().await;

        // Insert docs: org-A/admin, org-A/member, org-B/admin
        let a_admin = MultiIndexDoc {
            org_id: "org-A".into(),
            role: "admin".into(),
        };
        let a_member = MultiIndexDoc {
            org_id: "org-A".into(),
            role: "member".into(),
        };
        let b_admin = MultiIndexDoc {
            org_id: "org-B".into(),
            role: "admin".into(),
        };
        store.insert(&a_admin).await.unwrap();
        store.insert(&a_member).await.unwrap();
        store.insert(&b_admin).await.unwrap();

        // Single criterion: org_id = org-A → 2 results
        let results = store
            .find_by_indexes::<MultiIndexDoc>(&[("org_id", "org-A")])
            .await
            .unwrap();
        assert_eq!(results.len(), 2);

        // Two criteria: org_id = org-A AND role = admin → 1 result
        let results = store
            .find_by_indexes::<MultiIndexDoc>(&[("org_id", "org-A"), ("role", "admin")])
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].data, a_admin);

        // No match
        let results = store
            .find_by_indexes::<MultiIndexDoc>(&[("org_id", "org-B"), ("role", "member")])
            .await
            .unwrap();
        assert!(results.is_empty());

        // Empty criteria
        let results = store.find_by_indexes::<MultiIndexDoc>(&[]).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn compare_and_update_version_mismatch() {
        let store = test_store().await;
        let doc = TestDoc {
            name: "cas".to_string(),
            value: 1,
        };
        let inserted = store.insert(&doc).await.unwrap();

        // Update with wrong version should fail
        let updated_doc = TestDoc {
            name: "cas".to_string(),
            value: 2,
        };
        let result = store
            .compare_and_update(&inserted.id, 999, &updated_doc)
            .await
            .unwrap();
        assert!(!result, "CAS with wrong version should return false");

        // Update with correct version should succeed
        let result = store
            .compare_and_update(&inserted.id, inserted.version, &updated_doc)
            .await
            .unwrap();
        assert!(result, "CAS with correct version should return true");

        let fetched = store.get::<TestDoc>(&inserted.id).await.unwrap().unwrap();
        assert_eq!(fetched.data.value, 2);
        assert_eq!(fetched.version, 2);
    }

    #[tokio::test]
    async fn count_all_documents() {
        let store = test_store().await;

        for i in 0..4 {
            let doc = TestDoc {
                name: format!("count-all-{i}"),
                value: i,
            };
            store.insert(&doc).await.unwrap();
        }

        let count = store.count_all::<TestDoc>().await.unwrap();
        assert_eq!(count, 4);
    }

    #[tokio::test]
    async fn list_all_paginated() {
        let store = test_store().await;

        for i in 0..5 {
            let doc = TestDoc {
                name: format!("page-{i}"),
                value: i,
            };
            store.insert(&doc).await.unwrap();
        }

        // First page — no cursor
        let (page1, has_more1) = store.list_all_paginated::<TestDoc>(None, 2).await.unwrap();
        assert_eq!(page1.len(), 2);
        assert!(has_more1);

        // Second page — cursor is the last id from page 1
        let cursor1 = page1.last().unwrap().id.clone();
        let (page2, has_more2) = store
            .list_all_paginated::<TestDoc>(Some(cursor1.as_str()), 2)
            .await
            .unwrap();
        assert_eq!(page2.len(), 2);
        assert!(has_more2);

        // Third page — cursor is the last id from page 2
        let cursor2 = page2.last().unwrap().id.clone();
        let (page3, has_more3) = store
            .list_all_paginated::<TestDoc>(Some(cursor2.as_str()), 2)
            .await
            .unwrap();
        assert_eq!(page3.len(), 1);
        assert!(!has_more3);
    }

    #[tokio::test]
    async fn update_last_used_at() {
        let store = test_store().await;
        let doc = TestDoc {
            name: "last-used".to_string(),
            value: 1,
        };
        let inserted = store.insert(&doc).await.unwrap();
        assert!(inserted.last_used_at.is_none());

        store.update_last_used_at(&inserted.id).await.unwrap();

        let fetched = store.get::<TestDoc>(&inserted.id).await.unwrap().unwrap();
        assert!(fetched.last_used_at.is_some());
    }

    #[tokio::test]
    async fn modify_applies_fn() {
        let store = test_store().await;
        let doc = TestDoc {
            name: "modify-me".to_string(),
            value: 10,
        };
        let inserted = store.insert(&doc).await.unwrap();

        let found = store
            .modify::<TestDoc, _>(&inserted.id, |d| {
                d.value += 5;
            })
            .await
            .unwrap();
        assert!(found);

        let fetched = store.get::<TestDoc>(&inserted.id).await.unwrap().unwrap();
        assert_eq!(fetched.data.value, 15);
    }

    // ========================================================================
    // index_value_condition tests
    // ========================================================================

    /// Test-only crypto that returns a different hash than the input,
    /// simulating HPKE mode where `hmac_index` produces an opaque hash.
    #[derive(Debug)]
    struct HashingTestCrypto;

    impl DocumentCrypto for HashingTestCrypto {
        fn seal(
            &self,
            _info: &[u8],
            _aad: &[u8],
            plaintext: &[u8],
        ) -> anyhow::Result<EncryptedDocument> {
            let data =
                String::from_utf8(plaintext.to_vec()).context("plaintext is not valid UTF-8")?;
            Ok(EncryptedDocument {
                encapped_key: None,
                data,
            })
        }

        fn open(
            &self,
            _info: &[u8],
            _aad: &[u8],
            doc: &EncryptedDocument,
        ) -> anyhow::Result<Vec<u8>> {
            Ok(doc.data.as_bytes().to_vec())
        }

        fn hmac_index(&self, value: &str) -> String {
            format!("hashed:{value}")
        }
    }

    #[test]
    fn index_value_condition_plaintext_emits_eq() {
        use sea_query::SqliteQueryBuilder;

        let crypto = PlaintextDocumentCrypto;
        let expr = index_value_condition(&crypto, "alice@example.com");

        let (sql, _) = Query::select()
            .column(DocumentIndexes::IndexValue)
            .from(DocumentIndexes::Table)
            .and_where(expr)
            .build(SqliteQueryBuilder);

        assert!(
            sql.contains("= ?") || sql.contains("= 'alice@example.com'"),
            "expected simple equality, got: {sql}"
        );
        assert!(
            !sql.contains("IN"),
            "plaintext mode should not use IN, got: {sql}"
        );
    }

    #[test]
    fn index_value_condition_hpke_emits_in() {
        use sea_query::SqliteQueryBuilder;

        let crypto = HashingTestCrypto;
        let expr = index_value_condition(&crypto, "alice@example.com");

        let (sql, _) = Query::select()
            .column(DocumentIndexes::IndexValue)
            .from(DocumentIndexes::Table)
            .and_where(expr)
            .build(SqliteQueryBuilder);

        assert!(
            sql.contains("IN"),
            "HPKE mode should use IN clause, got: {sql}"
        );
    }
}
