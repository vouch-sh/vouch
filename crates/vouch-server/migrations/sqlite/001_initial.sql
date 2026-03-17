-- Encrypted document store: 3-table schema
-- documents: encrypted JSON blobs with metadata
-- document_indexes: HMAC-hashed index values for blind equality lookups
-- audit_events: unencrypted write-once security event log

CREATE TABLE IF NOT EXISTS documents (
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
);

CREATE INDEX IF NOT EXISTS idx_documents_doc_type ON documents(doc_type);
CREATE INDEX IF NOT EXISTS idx_documents_expires_at ON documents(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_documents_doc_type_created ON documents(doc_type, created_at);

CREATE TABLE IF NOT EXISTS document_indexes (
    id TEXT PRIMARY KEY,
    document_id TEXT NOT NULL,
    index_field TEXT NOT NULL,
    index_value TEXT NOT NULL,
    UNIQUE(document_id, index_field, index_value)
);

CREATE INDEX IF NOT EXISTS idx_document_indexes_lookup ON document_indexes(index_field, index_value);
CREATE INDEX IF NOT EXISTS idx_document_indexes_document_id ON document_indexes(document_id);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    user_id TEXT,
    email_domain TEXT,
    email_hmac TEXT,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_user_created ON audit_events(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_domain_created ON audit_events(email_domain, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_user_id ON audit_events(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_email_hmac ON audit_events(email_hmac);
CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_type_created ON audit_events(event_type, created_at);
