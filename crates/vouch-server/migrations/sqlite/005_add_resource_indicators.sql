-- RFC 8707: Resource Indicators for OAuth 2.0.
ALTER TABLE oauth_clients ADD COLUMN resource_uris TEXT NOT NULL DEFAULT '[]';
ALTER TABLE pending_oauth_authorizations ADD COLUMN resource TEXT;
