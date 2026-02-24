-- RFC 9470: Step Up Authentication - store requested prompt value (DSQL-safe: name and type only).
ALTER TABLE pending_oauth_authorizations ADD COLUMN prompt TEXT;
