-- Index for expired DPoP nonce cleanup
CREATE INDEX ASYNC idx_dpop_nonces_expires ON dpop_nonces(expires_at);
