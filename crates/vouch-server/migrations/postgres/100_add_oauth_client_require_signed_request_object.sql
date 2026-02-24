-- RFC 9101: Whether this client MUST use JAR for authorization requests.
ALTER TABLE oauth_clients ADD COLUMN require_signed_request_object BOOLEAN;
