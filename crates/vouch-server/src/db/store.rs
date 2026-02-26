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
use sea_query::{Expr, Iden, Order, Query};

use super::document_type::{Document, DocumentType};
use super::pool::Pool;
use super::types::BuildSql;
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

#[derive(Iden)]
enum DocumentIndexes {
    Table,
    Id,
    DocumentId,
    IndexField,
    IndexValue,
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
    version: i64,
    last_used_at: Option<String>,
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
        let db_type = self.pool.db_type();

        let sql = Query::select()
            .columns([
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
            ])
            .from(Documents::Table)
            .and_where(Expr::col(Documents::Id).eq(id))
            .and_where(Expr::col(Documents::DocType).eq(T::DOC_TYPE))
            .build_sql(db_type);

        let row: Option<RawDocumentRow> =
            crate::db_fetch_optional!(&self.pool, sqlx::query_as(&sql))?;

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

        let db_type = self.pool.db_type();
        let sql = Query::select()
            .columns([
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
            ])
            .from(Documents::Table)
            .and_where(Expr::col(Documents::Id).is_in(ids.iter().copied()))
            .and_where(Expr::col(Documents::DocType).eq(T::DOC_TYPE))
            .build_sql(db_type);

        let rows: Vec<RawDocumentRow> = crate::db_fetch_all!(&self.pool, sqlx::query_as(&sql))?;

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
        let results = self.find_all::<T>(field, value).await?;
        Ok(results.into_iter().next())
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
        let hashed = self.crypto.hmac_index(value);
        let db_type = self.pool.db_type();

        let sql = Query::select()
            .columns([
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
            ])
            .from(Documents::Table)
            .inner_join(
                DocumentIndexes::Table,
                Expr::col((Documents::Table, Documents::Id))
                    .equals((DocumentIndexes::Table, DocumentIndexes::DocumentId)),
            )
            .and_where(Expr::col((Documents::Table, Documents::DocType)).eq(T::DOC_TYPE))
            .and_where(Expr::col((DocumentIndexes::Table, DocumentIndexes::IndexField)).eq(field))
            .and_where(
                Expr::col((DocumentIndexes::Table, DocumentIndexes::IndexValue))
                    .eq(hashed.as_str()),
            )
            .build_sql(db_type);

        let rows: Vec<RawDocumentRow> = crate::db_fetch_all!(&self.pool, sqlx::query_as(&sql))?;

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            results.push(raw_to_document::<T>(&self.crypto, row)?);
        }
        Ok(results)
    }

    /// Find documents matching multiple index criteria (AND).
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

        // Strategy: find by first criterion, then filter in-memory
        let (first_field, first_value) = criteria.first().copied().context("empty criteria")?;
        let candidates = self.find_all::<T>(first_field, first_value).await?;

        if criteria.len() == 1 {
            return Ok(candidates);
        }

        // For additional criteria, re-compute indexes and filter
        let mut filtered = Vec::new();
        for doc in candidates {
            let entries = doc.data.index_entries();
            let matches_all = criteria.iter().skip(1).all(|(f, v)| {
                let target_hash = self.crypto.hmac_index(v);
                entries
                    .iter()
                    .any(|e| e.field == *f && self.crypto.hmac_index(&e.value) == target_hash)
            });
            if matches_all {
                filtered.push(doc);
            }
        }
        Ok(filtered)
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
            let db_type = self.pool.db_type();
            let sql = {
                let mut q = Query::update();
                q.table(Documents::Table)
                    .value(Documents::LastUsedAt, Expr::val(now_str.as_str()))
                    .and_where(Expr::col(Documents::Id).eq(id));
                q.build_sql(db_type)
            };
            crate::db_execute!(&self.pool, sqlx::query(&sql))?;
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
        expected_version: i64,
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
            let db_type = self.pool.db_type();

            let encapped: Option<&str> = encrypted.encapped_key.as_deref();
            let expires_str = expires.map(|ts| ts.to_string());
            let expires_ref: Option<&str> = expires_str.as_deref();

            let mut tx = self.pool.begin().await?;

            // UPDATE with version guard (optimistic concurrency)
            let update_sql = {
                let mut q = Query::update();
                q.table(Documents::Table)
                    .value(Documents::Data, Expr::val(encrypted.data.as_str()))
                    .value(Documents::EncappedKey, Expr::val(encapped))
                    .value(Documents::ExpiresAt, Expr::val(expires_ref))
                    .value(
                        Documents::SchemaVersion,
                        Expr::val(i64::from(T::CURRENT_VERSION)),
                    )
                    .value(Documents::UpdatedAt, Expr::val(now_str.as_str()))
                    .value(Documents::Version, Expr::val(expected_version + 1))
                    .and_where(Expr::col(Documents::Id).eq(id))
                    .and_where(Expr::col(Documents::Version).eq(expected_version));
                q.build_sql(db_type)
            };

            let result = crate::tx_execute!(tx, sqlx::query(&update_sql))?;

            if result.rows_affected() == 0 {
                // Version mismatch — concurrent modification detected
                return Ok(false);
            }

            // DELETE old indexes
            let delete_idx_sql = Query::delete()
                .from_table(DocumentIndexes::Table)
                .and_where(Expr::col(DocumentIndexes::DocumentId).eq(id))
                .build_sql(db_type);

            crate::tx_execute!(tx, sqlx::query(&delete_idx_sql))?;

            // INSERT new indexes
            for entry in &indexes {
                let index_id = uuid::Uuid::now_v7().to_string();
                let hashed_value = self.crypto.hmac_index(&entry.value);
                let idx_sql = Query::insert()
                    .into_table(DocumentIndexes::Table)
                    .columns([
                        DocumentIndexes::Id,
                        DocumentIndexes::DocumentId,
                        DocumentIndexes::IndexField,
                        DocumentIndexes::IndexValue,
                    ])
                    .values_panic([
                        index_id.as_str().into(),
                        id.into(),
                        entry.field.into(),
                        hashed_value.as_str().into(),
                    ])
                    .build_sql(db_type);

                crate::tx_execute!(tx, sqlx::query(&idx_sql))?;
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
            let db_type = self.pool.db_type();
            let now = jiff::Timestamp::now().to_string();

            // Find expired document IDs
            let select_sql = Query::select()
                .column(Documents::Id)
                .from(Documents::Table)
                .and_where(Expr::col(Documents::DocType).eq(doc_type))
                .and_where(Expr::col(Documents::ExpiresAt).is_not_null())
                .and_where(Expr::col(Documents::ExpiresAt).lt(now.as_str()))
                .build_sql(db_type);

            let rows: Vec<IdRow> = crate::db_fetch_all!(&self.pool, sqlx::query_as(&select_sql))?;

            let total = rows.len() as u64;
            // Batch deletes: 1,000 docs per tx (2 DELETE statements each)
            for batch in rows.chunks(1000) {
                let ids: Vec<sea_query::Value> =
                    batch.iter().map(|r| r.id.as_str().into()).collect();

                let mut tx = self.pool.begin().await?;

                let del_idx = Query::delete()
                    .from_table(DocumentIndexes::Table)
                    .and_where(Expr::col(DocumentIndexes::DocumentId).is_in(ids.clone()))
                    .build_sql(db_type);
                crate::tx_execute!(tx, sqlx::query(&del_idx))?;

                let del_doc = Query::delete()
                    .from_table(Documents::Table)
                    .and_where(Expr::col(Documents::Id).is_in(ids))
                    .build_sql(db_type);
                crate::tx_execute!(tx, sqlx::query(&del_doc))?;

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
        let hashed = self.crypto.hmac_index(value);
        let db_type = self.pool.db_type();

        let sql = Query::select()
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
            .and_where(
                Expr::col((DocumentIndexes::Table, DocumentIndexes::IndexValue))
                    .eq(hashed.as_str()),
            )
            .build_sql(db_type);

        // Use a simple FromRow struct for the count result
        #[derive(sqlx::FromRow)]
        struct CountRow {
            #[sqlx(default)]
            count: i64,
        }

        let row: CountRow = crate::db_fetch_one!(&self.pool, sqlx::query_as(&sql))?;
        Ok(row.count)
    }

    /// Count all documents of a given type (no index join needed).
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn count_all<T: DocumentType>(&self) -> Result<i64> {
        let db_type = self.pool.db_type();

        let sql = Query::select()
            .expr_as(
                Expr::col(Documents::Id).count(),
                sea_query::Alias::new("count"),
            )
            .from(Documents::Table)
            .and_where(Expr::col(Documents::DocType).eq(T::DOC_TYPE))
            .build_sql(db_type);

        #[derive(sqlx::FromRow)]
        struct CountRow {
            #[sqlx(default)]
            count: i64,
        }

        let row: CountRow = crate::db_fetch_one!(&self.pool, sqlx::query_as(&sql))?;
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
        let db_type = self.pool.db_type();

        let sql = Query::select()
            .columns([
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
            ])
            .from(Documents::Table)
            .and_where(Expr::col(Documents::DocType).eq(T::DOC_TYPE))
            .order_by(Documents::CreatedAt, Order::Desc)
            .build_sql(db_type);

        let rows: Vec<RawDocumentRow> = crate::db_fetch_all!(&self.pool, sqlx::query_as(&sql))?;

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            results.push(raw_to_document::<T>(&self.crypto, row)?);
        }
        Ok(results)
    }

    /// List documents of a given type with DB-level pagination.
    ///
    /// `offset` is 0-based. Results are ordered by `created_at` ascending
    /// (oldest first) for stable pagination.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption or deserialization fails.
    pub async fn list_all_paginated<T: DocumentType>(
        &self,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<Document<T>>> {
        let db_type = self.pool.db_type();

        let sql = Query::select()
            .columns([
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
            ])
            .from(Documents::Table)
            .and_where(Expr::col(Documents::DocType).eq(T::DOC_TYPE))
            .order_by(Documents::CreatedAt, Order::Asc)
            .offset(offset)
            .limit(limit)
            .build_sql(db_type);

        let rows: Vec<RawDocumentRow> = crate::db_fetch_all!(&self.pool, sqlx::query_as(&sql))?;

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            results.push(raw_to_document::<T>(&self.crypto, row)?);
        }
        Ok(results)
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
        let db_type = self.tx.db_type();

        let encapped: Option<&str> = encrypted.encapped_key.as_deref();
        let expires_ref: Option<&str> = expires_str.as_deref();

        // INSERT document
        let insert_sql = Query::insert()
            .into_table(Documents::Table)
            .columns([
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
            ])
            .values_panic([
                id.into(),
                T::DOC_TYPE.into(),
                i64::from(T::CURRENT_VERSION).into(),
                encapped.into(),
                encrypted.data.as_str().into(),
                expires_ref.into(),
                now_str.as_str().into(),
                now_str.as_str().into(),
                1_i64.into(),
                Option::<&str>::None.into(),
            ])
            .build_sql(db_type);

        crate::tx_execute!(self.tx, sqlx::query(&insert_sql))?;

        // INSERT index entries
        for entry in &indexes {
            let index_id = uuid::Uuid::now_v7().to_string();
            let hashed_value = self.crypto.hmac_index(&entry.value);
            let idx_sql = Query::insert()
                .into_table(DocumentIndexes::Table)
                .columns([
                    DocumentIndexes::Id,
                    DocumentIndexes::DocumentId,
                    DocumentIndexes::IndexField,
                    DocumentIndexes::IndexValue,
                ])
                .values_panic([
                    index_id.as_str().into(),
                    id.into(),
                    entry.field.into(),
                    hashed_value.as_str().into(),
                ])
                .build_sql(db_type);

            crate::tx_execute!(self.tx, sqlx::query(&idx_sql))?;
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
        let db_type = self.tx.db_type();

        let sql = Query::select()
            .columns([
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
            ])
            .from(Documents::Table)
            .and_where(Expr::col(Documents::Id).eq(id))
            .and_where(Expr::col(Documents::DocType).eq(T::DOC_TYPE))
            .build_sql(db_type);

        let row: Option<RawDocumentRow> = crate::tx_fetch_optional!(self.tx, sqlx::query_as(&sql))?;

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
        let mut results = self.find_all::<T>(field, value).await?;
        Ok(results.drain(..).next())
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
        let hashed = self.crypto.hmac_index(value);
        let db_type = self.tx.db_type();

        let sql = Query::select()
            .columns([
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
            ])
            .from(Documents::Table)
            .inner_join(
                DocumentIndexes::Table,
                Expr::col((Documents::Table, Documents::Id))
                    .equals((DocumentIndexes::Table, DocumentIndexes::DocumentId)),
            )
            .and_where(Expr::col((Documents::Table, Documents::DocType)).eq(T::DOC_TYPE))
            .and_where(Expr::col((DocumentIndexes::Table, DocumentIndexes::IndexField)).eq(field))
            .and_where(
                Expr::col((DocumentIndexes::Table, DocumentIndexes::IndexValue))
                    .eq(hashed.as_str()),
            )
            .build_sql(db_type);

        let rows: Vec<RawDocumentRow> = crate::tx_fetch_all!(self.tx, sqlx::query_as(&sql))?;

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
        let db_type = self.tx.db_type();

        let encapped: Option<&str> = encrypted.encapped_key.as_deref();
        let expires_ref: Option<&str> = expires_str.as_deref();

        // UPDATE document — scope the query builder so it drops before await
        let update_sql = {
            let mut q = Query::update();
            q.table(Documents::Table)
                .value(Documents::Data, Expr::val(encrypted.data.as_str()))
                .value(Documents::EncappedKey, Expr::val(encapped))
                .value(Documents::ExpiresAt, Expr::val(expires_ref))
                .value(
                    Documents::SchemaVersion,
                    Expr::val(i64::from(T::CURRENT_VERSION)),
                )
                .value(Documents::UpdatedAt, Expr::val(now_str.as_str()))
                .value(Documents::Version, Expr::col(Documents::Version).add(1))
                .and_where(Expr::col(Documents::Id).eq(id));
            q.build_sql(db_type)
        };

        crate::tx_execute!(self.tx, sqlx::query(&update_sql))?;

        // DELETE old indexes
        let delete_idx_sql = Query::delete()
            .from_table(DocumentIndexes::Table)
            .and_where(Expr::col(DocumentIndexes::DocumentId).eq(id))
            .build_sql(db_type);

        crate::tx_execute!(self.tx, sqlx::query(&delete_idx_sql))?;

        // INSERT new indexes
        for entry in &indexes {
            let index_id = uuid::Uuid::now_v7().to_string();
            let hashed_value = self.crypto.hmac_index(&entry.value);
            let idx_sql = Query::insert()
                .into_table(DocumentIndexes::Table)
                .columns([
                    DocumentIndexes::Id,
                    DocumentIndexes::DocumentId,
                    DocumentIndexes::IndexField,
                    DocumentIndexes::IndexValue,
                ])
                .values_panic([
                    index_id.as_str().into(),
                    id.into(),
                    entry.field.into(),
                    hashed_value.as_str().into(),
                ])
                .build_sql(db_type);

            crate::tx_execute!(self.tx, sqlx::query(&idx_sql))?;
        }

        Ok(())
    }

    // ========================================================================
    // Delete
    // ========================================================================

    /// Delete a document by ID (and its index entries) within this transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub async fn delete(&mut self, id: &str) -> Result<()> {
        let db_type = self.tx.db_type();

        let delete_idx_sql = Query::delete()
            .from_table(DocumentIndexes::Table)
            .and_where(Expr::col(DocumentIndexes::DocumentId).eq(id))
            .build_sql(db_type);

        crate::tx_execute!(self.tx, sqlx::query(&delete_idx_sql))?;

        let delete_doc_sql = Query::delete()
            .from_table(Documents::Table)
            .and_where(Expr::col(Documents::Id).eq(id))
            .build_sql(db_type);

        crate::tx_execute!(self.tx, sqlx::query(&delete_doc_sql))?;

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

        let db_type = self.tx.db_type();

        // Batch deletes in chunks of 1,000 to stay within DSQL statement limits
        for batch in docs.chunks(1000) {
            let ids: Vec<sea_query::Value> = batch.iter().map(|d| d.id.as_str().into()).collect();

            let del_idx = Query::delete()
                .from_table(DocumentIndexes::Table)
                .and_where(Expr::col(DocumentIndexes::DocumentId).is_in(ids.clone()))
                .build_sql(db_type);
            crate::tx_execute!(self.tx, sqlx::query(&del_idx))?;

            let del_doc = Query::delete()
                .from_table(Documents::Table)
                .and_where(Expr::col(Documents::Id).is_in(ids))
                .build_sql(db_type);
            crate::tx_execute!(self.tx, sqlx::query(&del_doc))?;
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
        let hashed = self.crypto.hmac_index(value);
        let db_type = self.tx.db_type();

        let sql = Query::select()
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
            .and_where(
                Expr::col((DocumentIndexes::Table, DocumentIndexes::IndexValue))
                    .eq(hashed.as_str()),
            )
            .build_sql(db_type);

        #[derive(sqlx::FromRow)]
        struct CountRow {
            #[sqlx(default)]
            count: i64,
        }

        let row: CountRow = crate::tx_fetch_one!(self.tx, sqlx::query_as(&sql))?;
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
        expected_version: i64,
        doc: &T,
    ) -> Result<bool> {
        let json = serde_json::to_vec(doc).context("failed to serialize document")?;
        let encrypted = self
            .crypto
            .seal(T::DOC_TYPE.as_bytes(), id.as_bytes(), &json)?;

        let now_str = Timestamp::now().to_string();
        let expires = doc.expires_at();
        let indexes = doc.index_entries();
        let db_type = self.tx.db_type();

        let encapped: Option<&str> = encrypted.encapped_key.as_deref();
        let expires_str = expires.map(|ts| ts.to_string());
        let expires_ref: Option<&str> = expires_str.as_deref();

        let update_sql = {
            let mut q = Query::update();
            q.table(Documents::Table)
                .value(Documents::Data, Expr::val(encrypted.data.as_str()))
                .value(Documents::EncappedKey, Expr::val(encapped))
                .value(Documents::ExpiresAt, Expr::val(expires_ref))
                .value(
                    Documents::SchemaVersion,
                    Expr::val(i64::from(T::CURRENT_VERSION)),
                )
                .value(Documents::UpdatedAt, Expr::val(now_str.as_str()))
                .value(Documents::Version, Expr::val(expected_version + 1))
                .and_where(Expr::col(Documents::Id).eq(id))
                .and_where(Expr::col(Documents::Version).eq(expected_version));
            q.build_sql(db_type)
        };

        let result = crate::tx_execute!(self.tx, sqlx::query(&update_sql))?;

        if result.rows_affected() == 0 {
            return Ok(false);
        }

        let delete_idx_sql = Query::delete()
            .from_table(DocumentIndexes::Table)
            .and_where(Expr::col(DocumentIndexes::DocumentId).eq(id))
            .build_sql(db_type);
        crate::tx_execute!(self.tx, sqlx::query(&delete_idx_sql))?;

        for entry in &indexes {
            let index_id = uuid::Uuid::now_v7().to_string();
            let hashed_value = self.crypto.hmac_index(&entry.value);
            let idx_sql = Query::insert()
                .into_table(DocumentIndexes::Table)
                .columns([
                    DocumentIndexes::Id,
                    DocumentIndexes::DocumentId,
                    DocumentIndexes::IndexField,
                    DocumentIndexes::IndexValue,
                ])
                .values_panic([
                    index_id.as_str().into(),
                    id.into(),
                    entry.field.into(),
                    hashed_value.as_str().into(),
                ])
                .build_sql(db_type);
            crate::tx_execute!(self.tx, sqlx::query(&idx_sql))?;
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
        let pool = Pool::connect("sqlite::memory:").await.unwrap();

        // Create tables inline for test isolation
        crate::db_execute!(
            &pool,
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
                )"
            )
        )
        .unwrap();

        crate::db_execute!(
            &pool,
            sqlx::query(
                "CREATE TABLE IF NOT EXISTS document_indexes (
                    id TEXT PRIMARY KEY,
                    document_id TEXT NOT NULL,
                    index_field TEXT NOT NULL,
                    index_value TEXT NOT NULL,
                    UNIQUE(document_id, index_field, index_value)
                )"
            )
        )
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

        // AND: org_id = org-A AND role = admin → 1 result
        let results = store
            .find_by_indexes::<MultiIndexDoc>(&[("org_id", "org-A"), ("role", "admin")])
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].data.org_id, "org-A");
        assert_eq!(results[0].data.role, "admin");

        // AND with no match: org_id = org-B AND role = member → 0
        let results = store
            .find_by_indexes::<MultiIndexDoc>(&[("org_id", "org-B"), ("role", "member")])
            .await
            .unwrap();
        assert!(results.is_empty());

        // Empty criteria → empty results
        let results = store.find_by_indexes::<MultiIndexDoc>(&[]).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn count_all_and_list_all_paginated() {
        let store = test_store().await;

        for i in 0..5 {
            let doc = TestDoc {
                name: format!("page-{i}"),
                value: i,
            };
            store.insert(&doc).await.unwrap();
        }

        // count_all
        let count = store.count_all::<TestDoc>().await.unwrap();
        assert_eq!(count, 5);

        // Paginated: first 2
        let page1 = store.list_all_paginated::<TestDoc>(0, 2).await.unwrap();
        assert_eq!(page1.len(), 2);

        // Paginated: skip 2, take 2
        let page2 = store.list_all_paginated::<TestDoc>(2, 2).await.unwrap();
        assert_eq!(page2.len(), 2);

        // Pages don't overlap
        assert_ne!(page1[0].id, page2[0].id);

        // Paginated: beyond end
        let page_end = store.list_all_paginated::<TestDoc>(10, 5).await.unwrap();
        assert!(page_end.is_empty());
    }

    #[tokio::test]
    async fn compare_and_update_version_conflict() {
        let store = test_store().await;

        let doc = TestDoc {
            name: "versioned".into(),
            value: 1,
        };
        let inserted = store.insert(&doc).await.unwrap();
        assert_eq!(inserted.version, 1);

        // Update with correct version succeeds
        let mut updated_data = inserted.data.clone();
        updated_data.value = 2;
        let won = store
            .compare_and_update(&inserted.id, 1, &updated_data)
            .await
            .unwrap();
        assert!(won);

        // Same version again (stale) fails
        updated_data.value = 3;
        let won = store
            .compare_and_update(&inserted.id, 1, &updated_data)
            .await
            .unwrap();
        assert!(!won);

        // Verify the value stayed at 2
        let fetched = store.get::<TestDoc>(&inserted.id).await.unwrap().unwrap();
        assert_eq!(fetched.data.value, 2);
        assert_eq!(fetched.version, 2);
    }

    // ====================================================================
    // StoreTransaction tests
    // ====================================================================

    #[tokio::test]
    async fn transaction_insert_and_get() {
        let store = test_store().await;

        let mut tx = store.begin().await.unwrap();
        let doc = TestDoc {
            name: "tx-test".to_string(),
            value: 42,
        };
        let inserted = tx.insert(&doc).await.unwrap();
        assert_eq!(inserted.data.name, "tx-test");

        // Visible within the transaction
        let found = tx.get::<TestDoc>(&inserted.id).await.unwrap();
        assert!(found.is_some());

        tx.commit().await.unwrap();

        // Visible after commit via the store
        let found = store.get::<TestDoc>(&inserted.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().data.value, 42);
    }

    #[tokio::test]
    async fn transaction_rollback_on_drop() {
        let store = test_store().await;

        let id = {
            let mut tx = store.begin().await.unwrap();
            let doc = TestDoc {
                name: "rollback-test".to_string(),
                value: 99,
            };
            let inserted = tx.insert(&doc).await.unwrap();

            // Visible within tx
            assert!(tx.get::<TestDoc>(&inserted.id).await.unwrap().is_some());

            // Drop tx without commit — rolls back
            inserted.id
        };

        // Not visible after rollback
        let found = store.get::<TestDoc>(&id).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn transaction_multi_op_commit() {
        let store = test_store().await;

        let mut tx = store.begin().await.unwrap();

        // Insert two docs
        let doc1 = TestDoc {
            name: "multi-1".to_string(),
            value: 1,
        };
        let doc2 = TestDoc {
            name: "multi-2".to_string(),
            value: 2,
        };
        let ins1 = tx.insert(&doc1).await.unwrap();
        let ins2 = tx.insert(&doc2).await.unwrap();

        // Update the first
        let mut updated = doc1.clone();
        updated.value = 10;
        tx.update(&ins1.id, &updated).await.unwrap();

        // Delete the second
        tx.delete(&ins2.id).await.unwrap();

        tx.commit().await.unwrap();

        // Verify via store
        let found1 = store.get::<TestDoc>(&ins1.id).await.unwrap().unwrap();
        assert_eq!(found1.data.value, 10);

        let found2 = store.get::<TestDoc>(&ins2.id).await.unwrap();
        assert!(found2.is_none());
    }

    #[tokio::test]
    async fn transaction_find_one_and_find_all() {
        let store = test_store().await;

        let mut tx = store.begin().await.unwrap();
        let doc = TestDoc {
            name: "findable".to_string(),
            value: 7,
        };
        tx.insert(&doc).await.unwrap();

        // find_one within tx
        let found = tx.find_one::<TestDoc>("name", "findable").await.unwrap();
        assert!(found.is_some());

        // find_all within tx
        let all = tx.find_all::<TestDoc>("name", "findable").await.unwrap();
        assert_eq!(all.len(), 1);

        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn transaction_delete_by_index() {
        let store = test_store().await;

        // Pre-populate
        store
            .insert(&TestDoc {
                name: "batch".to_string(),
                value: 1,
            })
            .await
            .unwrap();
        store
            .insert(&TestDoc {
                name: "batch".to_string(),
                value: 2,
            })
            .await
            .unwrap();
        store
            .insert(&TestDoc {
                name: "keep".to_string(),
                value: 3,
            })
            .await
            .unwrap();

        let mut tx = store.begin().await.unwrap();
        let deleted = tx
            .delete_by_index::<TestDoc>("name", "batch")
            .await
            .unwrap();
        assert_eq!(deleted, 2);
        tx.commit().await.unwrap();

        // "batch" docs gone, "keep" remains
        let remaining = store.find_all::<TestDoc>("name", "batch").await.unwrap();
        assert!(remaining.is_empty());

        let kept = store.find_one::<TestDoc>("name", "keep").await.unwrap();
        assert!(kept.is_some());
    }

    #[tokio::test]
    async fn transaction_compare_and_update() {
        let store = test_store().await;

        // Pre-populate
        let doc = TestDoc {
            name: "cas-test".to_string(),
            value: 1,
        };
        let inserted = store.insert(&doc).await.unwrap();

        let mut tx = store.begin().await.unwrap();
        let mut updated = doc.clone();
        updated.value = 2;
        let won = tx
            .compare_and_update(&inserted.id, 1, &updated)
            .await
            .unwrap();
        assert!(won);

        // Stale version fails within same tx
        updated.value = 3;
        let won = tx
            .compare_and_update(&inserted.id, 1, &updated)
            .await
            .unwrap();
        assert!(!won);

        tx.commit().await.unwrap();

        let fetched = store.get::<TestDoc>(&inserted.id).await.unwrap().unwrap();
        assert_eq!(fetched.data.value, 2);
    }

    #[tokio::test]
    async fn transaction_count() {
        let store = test_store().await;

        let mut tx = store.begin().await.unwrap();
        tx.insert(&TestDoc {
            name: "counted".to_string(),
            value: 1,
        })
        .await
        .unwrap();
        tx.insert(&TestDoc {
            name: "counted".to_string(),
            value: 2,
        })
        .await
        .unwrap();

        let count = tx.count::<TestDoc>("name", "counted").await.unwrap();
        assert_eq!(count, 2);

        tx.commit().await.unwrap();
    }
}
