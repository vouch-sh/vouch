-- RFC 7523: Cached JWKS content fetched from jwks_uri (DSQL-safe: name and type only).
ALTER TABLE oauth_clients ADD COLUMN jwks_uri_cache TEXT;
