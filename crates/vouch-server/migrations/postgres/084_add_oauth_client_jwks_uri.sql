-- RFC 7523: Remote JWKS URI for private_key_jwt client authentication (DSQL-safe: name and type only).
ALTER TABLE oauth_clients ADD COLUMN jwks_uri TEXT;
