-- RFC 7591: OAuth 2.0 Dynamic Client Registration metadata columns.
ALTER TABLE oauth_clients ADD COLUMN grant_types TEXT;
ALTER TABLE oauth_clients ADD COLUMN response_types TEXT;
ALTER TABLE oauth_clients ADD COLUMN software_id TEXT;
ALTER TABLE oauth_clients ADD COLUMN software_version TEXT;
ALTER TABLE oauth_clients ADD COLUMN registration_source TEXT;
ALTER TABLE oauth_clients ADD COLUMN registration_access_token_hash TEXT;
ALTER TABLE oauth_clients ADD COLUMN registration_metadata TEXT;
