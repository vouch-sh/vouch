-- RFC 7523: Apply NOT NULL constraint after populating existing rows.
ALTER TABLE oauth_clients ALTER COLUMN token_endpoint_auth_method SET NOT NULL;
