-- RFC 9470: Step Up Authentication Challenge Protocol.
ALTER TABLE pending_oauth_authorizations ADD COLUMN acr_values TEXT;
ALTER TABLE pending_oauth_authorizations ADD COLUMN max_age INTEGER;
ALTER TABLE pending_oauth_authorizations ADD COLUMN prompt TEXT;
