-- Index for expired device auth request cleanup
CREATE INDEX ASYNC idx_device_auth_expires ON device_auth_requests(expires_at);
