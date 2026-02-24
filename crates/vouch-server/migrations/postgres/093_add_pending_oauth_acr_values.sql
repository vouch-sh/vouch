-- RFC 9470: Step Up Authentication - store requested acr_values (DSQL-safe: name and type only).
ALTER TABLE pending_oauth_authorizations ADD COLUMN acr_values TEXT;
