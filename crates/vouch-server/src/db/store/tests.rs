// SPDX-License-Identifier: Apache-2.0 OR MIT
#![expect(
    clippy::unwrap_used,
    clippy::unreachable,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]

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

/// A conflicting write on every attempt must exhaust the retry budget and
/// surface the version-conflict error rather than spinning or reporting
/// success. Uses the modify test seam to conflict deterministically.
#[tokio::test]
async fn modify_version_conflict_on_every_attempt_exhausts_retries() {
    let mut store = test_store().await;
    let doc = TestDoc {
        name: "conflict-me".to_string(),
        value: 1,
    };
    let inserted = store.insert(&doc).await.unwrap();
    let doc_id = inserted.id.clone();

    let writer = store.clone();
    store.set_modify_test_hook(Arc::new(move |id: &str, _attempt: u32| {
        let writer = writer.clone();
        let id = id.to_string();
        Box::pin(async move {
            // Conflict on every attempt: any write bumps the version, so
            // the in-flight compare_and_update always loses.
            let current = writer.get::<TestDoc>(&id).await.unwrap().unwrap();
            writer.update(&id, &current.data).await.unwrap();
        })
    }));

    let err = store
        .modify::<TestDoc, _>(&doc_id, |d| {
            d.value += 1;
        })
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("version conflict after retries"),
        "exhausted retries must surface the version-conflict error, got: {err}"
    );
}

/// A document deleted between `modify`'s read and its compare-and-update
/// is gone on the retry's re-read: `modify` must return `Ok(false)` rather
/// than erroring or resurrecting the document. The existing
/// deleted-between-resolve-and-modify coverage only deletes before the
/// first read; this exercises deletion mid-loop.
#[tokio::test]
async fn modify_doc_deleted_mid_loop_returns_false() {
    let mut store = test_store().await;
    let doc = TestDoc {
        name: "delete-me".to_string(),
        value: 1,
    };
    let inserted = store.insert(&doc).await.unwrap();
    let doc_id = inserted.id.clone();

    let writer = store.clone();
    store.set_modify_test_hook(Arc::new(move |id: &str, attempt: u32| {
        let writer = writer.clone();
        let id = id.to_string();
        Box::pin(async move {
            if attempt != 0 {
                return;
            }
            writer.delete(&id).await.unwrap();
        })
    }));

    let found = store
        .modify::<TestDoc, _>(&doc_id, |d| {
            d.value += 1;
        })
        .await
        .unwrap();
    assert!(!found, "doc deleted mid-loop must yield Ok(false)");
    assert!(
        store.get::<TestDoc>(&doc_id).await.unwrap().is_none(),
        "the deletion must not be undone by the failed modify"
    );
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
        let data = String::from_utf8(plaintext.to_vec()).context("plaintext is not valid UTF-8")?;
        Ok(EncryptedDocument {
            encapped_key: None,
            data,
        })
    }

    fn open(&self, _info: &[u8], _aad: &[u8], doc: &EncryptedDocument) -> anyhow::Result<Vec<u8>> {
        Ok(doc.data.as_bytes().to_vec())
    }

    fn hmac_index(&self, value: &str) -> String {
        format!("hashed:{value}")
    }

    fn is_encrypted(&self) -> bool {
        // Simulates HPKE mode (opaque hashed indexes) without encrypting.
        false
    }
}

#[test]
fn index_value_condition_plaintext_emits_eq() {
    use sea_query::SqliteQueryBuilder;

    let crypto = PlaintextDocumentCrypto;
    let expr = index_value_condition(&crypto, DocumentIndexes::Table, "alice@example.com");

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
    let expr = index_value_condition(&crypto, DocumentIndexes::Table, "alice@example.com");

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

#[tokio::test]
async fn insert_rejects_nul_in_index_value() {
    let store = test_store().await;
    let doc = TestDoc {
        name: "ali\0ce".to_string(),
        value: 1,
    };

    let err = store.insert_with_id("nul-doc", &doc).await.unwrap_err();
    let invalid = err.downcast_ref::<InvalidIndexValue>().unwrap();
    assert_eq!(invalid.field, "name");

    // The transaction rolled back: no document row either.
    assert!(store.get::<TestDoc>("nul-doc").await.unwrap().is_none());
}

#[tokio::test]
async fn update_rejects_nul_in_index_value() {
    let store = test_store().await;
    let doc = TestDoc {
        name: "frank".to_string(),
        value: 1,
    };
    let inserted = store.insert(&doc).await.unwrap();

    let bad = TestDoc {
        name: "fra\0nk".to_string(),
        value: 2,
    };
    let err = store.update(&inserted.id, &bad).await.unwrap_err();
    assert!(err.downcast_ref::<InvalidIndexValue>().is_some());

    // Rolled back: the original document and its index row survive.
    let found = store.find_one::<TestDoc>("name", "frank").await.unwrap();
    assert_eq!(found.unwrap().data, doc);
}

#[tokio::test]
async fn compare_and_update_rejects_nul_in_index_value() {
    let store = test_store().await;
    let doc = TestDoc {
        name: "grace".to_string(),
        value: 1,
    };
    let inserted = store.insert(&doc).await.unwrap();

    let bad = TestDoc {
        name: "gra\0ce".to_string(),
        value: 2,
    };
    let err = store
        .compare_and_update(&inserted.id, inserted.version, &bad)
        .await
        .unwrap_err();
    assert!(err.downcast_ref::<InvalidIndexValue>().is_some());

    let found = store.find_one::<TestDoc>("name", "grace").await.unwrap();
    assert_eq!(found.unwrap().data, doc);
}

#[tokio::test]
async fn find_with_nul_lookup_matches_nothing() {
    let store = test_store().await;
    store
        .insert(&TestDoc {
            name: "heidi".to_string(),
            value: 1,
        })
        .await
        .unwrap();

    // Must degrade to not-found — binding 0x00 as a text parameter is a
    // hard error on Postgres/DSQL.
    let found = store.find_one::<TestDoc>("name", "hei\0di").await.unwrap();
    assert!(found.is_none());

    let all = store.find_all::<TestDoc>("name", "hei\0di").await.unwrap();
    assert!(all.is_empty());
}

#[test]
fn index_value_condition_nul_never_binds_raw_value() {
    use sea_query::SqliteQueryBuilder;

    // HPKE mode is where the IN bridge would otherwise bind the raw value.
    let crypto = HashingTestCrypto;
    let expr = index_value_condition(&crypto, DocumentIndexes::Table, "ali\0ce");

    let (sql, values) = Query::select()
        .column(DocumentIndexes::IndexValue)
        .from(DocumentIndexes::Table)
        .and_where(expr)
        .build(SqliteQueryBuilder);

    assert!(
        !sql.contains("IN"),
        "NUL lookup must not use IN, got: {sql}"
    );
    for value in &values.0 {
        let rendered = format!("{value:?}");
        assert!(
            !rendered.contains('\0'),
            "NUL must never be bound as a parameter, got: {rendered}"
        );
    }
}

// ========================================================================
// StoreTransaction::update_by_index — batched set-based index maintenance.
//
// The transactional form powers the credential-revocation cascade
// (`delete_authenticator` → detach device-auth approvals). It keeps every
// matching document's update inside the caller's single transaction
// (atomicity) but rebuilds index entries once per 500-doc batch with
// set-based SQL (one `DELETE … IN (…)` plus one multi-row `INSERT`) so the
// transaction's statement count tracks the document count rather than ~5×
// it — keeping the cascade within DSQL's 3,000-statement-per-transaction
// budget. These tests pin the functional, atomicity, index-rebuild, and
// statement-budget properties of that path; there was previously no direct
// coverage of `StoreTransaction::update_by_index` at all.
// ========================================================================

#[tokio::test]
async fn tx_update_by_index_updates_every_document_across_batch_boundary() {
    // More than one 500-doc batch so the second batch's documents are also
    // updated, not silently dropped at the batch boundary.
    let store = test_store().await;
    let n: usize = 600;
    for _ in 0..n {
        let doc = TestDoc {
            name: "shared".to_string(),
            value: 0,
        };
        store.insert(&doc).await.unwrap();
    }

    let mut tx = store.begin().await.unwrap();
    let updated = tx
        .update_by_index::<TestDoc, _>("name", "shared", |d| {
            d.value += 100;
        })
        .await
        .unwrap();
    assert_eq!(updated, n as u64);
    tx.commit().await.unwrap();

    let docs = store.find_all::<TestDoc>("name", "shared").await.unwrap();
    assert_eq!(
        docs.len(),
        n,
        "every document must remain reachable by its (unchanged) index"
    );
    for doc in &docs {
        assert_eq!(
            doc.data.value, 100,
            "every document across both batches must be updated exactly once"
        );
    }
}

#[tokio::test]
async fn tx_update_by_index_rebuilds_changed_and_unchanged_indexes() {
    // `MultiIndexDoc` emits two index entries (`org_id`, `role`). The
    // modifier changes only `role`, so the batched index rebuild must drop
    // the old `role` rows, insert the new `role` rows, AND re-insert the
    // unchanged `org_id` rows — otherwise `find_all` by `org_id` would lose
    // every document.
    let store = test_store().await;
    for _ in 0..3 {
        let doc = MultiIndexDoc {
            org_id: "org-A".into(),
            role: "member".into(),
        };
        store.insert(&doc).await.unwrap();
    }

    let mut tx = store.begin().await.unwrap();
    let updated = tx
        .update_by_index::<MultiIndexDoc, _>("org_id", "org-A", |d| {
            d.role = "senior".to_string();
        })
        .await
        .unwrap();
    assert_eq!(updated, 3);
    tx.commit().await.unwrap();

    // Old `role` index is gone; new `role` index is present.
    assert!(
        store
            .find_all::<MultiIndexDoc>("role", "member")
            .await
            .unwrap()
            .is_empty()
    );
    let seniors = store
        .find_all::<MultiIndexDoc>("role", "senior")
        .await
        .unwrap();
    assert_eq!(seniors.len(), 3);

    // Unchanged `org_id` index was re-inserted and still resolves every doc.
    let org_docs = store
        .find_all::<MultiIndexDoc>("org_id", "org-A")
        .await
        .unwrap();
    assert_eq!(
        org_docs.len(),
        3,
        "unchanged index entries must be rebuilt, not dropped"
    );
}

#[tokio::test]
async fn tx_update_by_index_is_atomic_on_nul_index_value() {
    // A modifier that emits a NUL index value must abort the caller's
    // transaction and persist nothing — no half-updated documents, no
    // partially-rewritten index rows.
    let store = test_store().await;
    for i in 0..5 {
        let doc = TestDoc {
            name: "shared".to_string(),
            value: i,
        };
        store.insert(&doc).await.unwrap();
    }

    let mut tx = store.begin().await.unwrap();
    let err = tx
        .update_by_index::<TestDoc, _>("name", "shared", |d| {
            d.name = "bad\0name".to_string();
        })
        .await
        .unwrap_err();
    // Dropping `tx` here rolls the transaction back.
    drop(tx);

    assert!(
        err.downcast_ref::<InvalidIndexValue>().is_some(),
        "error must be InvalidIndexValue, got: {err:?}"
    );

    // Every document must be untouched: original name and value.
    let docs = store.find_all::<TestDoc>("name", "shared").await.unwrap();
    assert_eq!(
        docs.len(),
        5,
        "no document may have its index rewritten to the NUL value"
    );
    let mut values: Vec<i32> = docs.iter().map(|d| d.data.value).collect();
    values.sort();
    assert_eq!(
        values,
        vec![0, 1, 2, 3, 4],
        "no document's data may be modified"
    );
}

#[tokio::test]
async fn tx_update_by_index_statement_count_scales_with_doc_count_not_per_index_entry() {
    // The budget-regression test for the revocation cascade. The prior
    // implementation issued one `UPDATE` plus a per-row index `DELETE` and
    // one `INSERT` per index entry for every document — ~4 statements/doc for
    // a 2-index doc, ~5 for a device-auth row — all inside the caller's one
    // transaction. At 800 matching rows that is ~3,200 statements, already
    // over DSQL's 3,000-statement-per-transaction budget. The set-based
    // batched rebuild issues one `UPDATE` per doc plus one `DELETE` and one
    // multi-row `INSERT` per 500-doc batch, so the count tracks the number
    // of documents.
    let store = test_store().await;
    let n: usize = 800;
    for _ in 0..n {
        let doc = MultiIndexDoc {
            org_id: "org-A".into(),
            role: "member".into(),
        };
        store.insert(&doc).await.unwrap();
    }

    let mut tx = store.begin().await.unwrap();
    let updated = tx
        .update_by_index::<MultiIndexDoc, _>("org_id", "org-A", |d| {
            d.role = "senior".to_string();
        })
        .await
        .unwrap();
    assert_eq!(updated, n as u64);
    let stmts = tx.update_by_index_statement_count();
    tx.commit().await.unwrap();

    let batches = n.div_ceil(UPDATE_BY_INDEX_BATCH);
    // Per batch: B `UPDATE`s + 1 set-based `DELETE` + 1 multi-row `INSERT`.
    let expected = (n + batches * 2) as u64;
    assert_eq!(
        stmts, expected,
        "set-based index maintenance must issue ~1 statement per doc (n + 2 per batch), got {stmts}"
    );
    // The prior per-row implementation would have issued ~4 * n = 3,200 at
    // this scale, exceeding the 3,000-statement budget; the fix keeps the
    // single transaction well within it.
    assert!(
        stmts < 3_000,
        "transaction must stay within DSQL's 3,000-statement-per-transaction budget, got {stmts}"
    );

    // And the result is still correct end-to-end.
    assert!(
        store
            .find_all::<MultiIndexDoc>("role", "member")
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .find_all::<MultiIndexDoc>("role", "senior")
            .await
            .unwrap()
            .len(),
        n
    );
    assert_eq!(
        store
            .find_all::<MultiIndexDoc>("org_id", "org-A")
            .await
            .unwrap()
            .len(),
        n,
        "unchanged index entries must be rebuilt, not dropped"
    );
}

#[tokio::test]
async fn tx_update_by_index_with_no_matches_issues_no_writes() {
    let store = test_store().await;
    store
        .insert(&TestDoc {
            name: "only".to_string(),
            value: 1,
        })
        .await
        .unwrap();

    let mut tx = store.begin().await.unwrap();
    let updated = tx
        .update_by_index::<TestDoc, _>("name", "nonexistent", |d| {
            d.value += 1;
        })
        .await
        .unwrap();
    assert_eq!(updated, 0);
    assert_eq!(
        tx.update_by_index_statement_count(),
        0,
        "no matching documents must issue zero write statements"
    );
    tx.commit().await.unwrap();

    // The one existing document is untouched.
    let doc = store
        .find_one::<TestDoc>("name", "only")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(doc.data.value, 1);
}
