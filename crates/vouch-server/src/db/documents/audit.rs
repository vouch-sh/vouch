// SPDX-License-Identifier: BUSL-1.1
//! Audit event data payloads for the `audit_events.data` JSON column.
//!
//! These are serialized to JSON and stored in the unencrypted audit table.
//! They are NOT `DocumentType` implementations — they're the payload
//! inside `AuditStore::insert_event(data_json)`.
//!
//! Typed audit structs will be added when callers migrate from raw JSON
//! strings to structured payloads.
