-- RFC 8707: Add resource_uris column to oauth_clients (DSQL-safe: name and type only).
ALTER TABLE oauth_clients ADD COLUMN resource_uris TEXT;
