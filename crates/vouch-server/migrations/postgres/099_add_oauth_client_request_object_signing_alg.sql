-- RFC 9101: Client's preferred signing algorithm for Request Objects.
ALTER TABLE oauth_clients ADD COLUMN request_object_signing_alg TEXT;
