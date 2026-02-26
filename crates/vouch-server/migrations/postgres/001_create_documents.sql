CREATE TABLE documents (
    id TEXT PRIMARY KEY,
    doc_type TEXT NOT NULL,
    schema_version INTEGER NOT NULL DEFAULT 1,
    encapped_key TEXT,
    data TEXT NOT NULL,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);
