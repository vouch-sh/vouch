// SPDX-License-Identifier: BUSL-1.1
//! Database schema definitions.
//!
//! The document store uses 3 tables: `documents`, `document_indexes`, and
//! `audit_events`. Sea-query Iden enums for these tables are defined locally
//! in [`super::store`] and [`super::audit`] where they are used.
//!
//! This module is intentionally empty — the old per-table Iden enums were
//! removed as part of the document store migration.
