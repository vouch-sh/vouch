-- RFC 9470: Step Up Authentication - store requested max_age (DSQL-safe: name and type only).
ALTER TABLE pending_oauth_authorizations ADD COLUMN max_age INTEGER;
