CREATE INDEX ASYNC idx_document_indexes_covering ON document_indexes(index_field, index_value) INCLUDE (document_id);
