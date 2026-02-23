-- RFC 8707: Apply NOT NULL constraint after populating existing rows.
ALTER TABLE oauth_clients ALTER COLUMN resource_uris SET NOT NULL;
