-- RFC 9101: Default existing clients to not require signed request objects.
UPDATE oauth_clients SET require_signed_request_object = FALSE WHERE require_signed_request_object IS NULL;
