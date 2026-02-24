-- RFC 7523: Inline JWKS for private_key_jwt client authentication (DSQL-safe: name and type only).
ALTER TABLE oauth_clients ADD COLUMN jwks TEXT;
