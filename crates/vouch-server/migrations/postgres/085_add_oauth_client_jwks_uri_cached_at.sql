-- RFC 7523: Timestamp of last JWKS URI fetch (DSQL-safe: name and type only).
ALTER TABLE oauth_clients ADD COLUMN jwks_uri_cached_at TIMESTAMPTZ;
