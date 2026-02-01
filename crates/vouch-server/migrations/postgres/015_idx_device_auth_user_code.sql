-- Index for user code lookups during device authorization
CREATE INDEX ASYNC idx_device_auth_user_code ON device_auth_requests(user_code);
