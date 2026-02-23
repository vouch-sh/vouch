-- RFC 8707: Set default for new rows.
ALTER TABLE oauth_clients ALTER COLUMN resource_uris SET DEFAULT '[]';
