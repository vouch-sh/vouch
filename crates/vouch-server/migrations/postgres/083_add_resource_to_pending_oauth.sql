-- RFC 8707: Store resource parameter during authorization flow.
ALTER TABLE pending_oauth_authorizations ADD COLUMN resource TEXT;
