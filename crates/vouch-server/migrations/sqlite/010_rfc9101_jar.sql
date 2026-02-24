-- RFC 9101: JWT-Secured Authorization Request (JAR) client metadata.
ALTER TABLE oauth_clients ADD COLUMN request_object_signing_alg TEXT;
ALTER TABLE oauth_clients ADD COLUMN require_signed_request_object BOOLEAN DEFAULT FALSE;
