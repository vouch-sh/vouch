CREATE TABLE document_indexes (
    id TEXT PRIMARY KEY,
    document_id TEXT NOT NULL,
    index_field TEXT NOT NULL,
    index_value TEXT NOT NULL,
    UNIQUE(document_id, index_field, index_value)
);
