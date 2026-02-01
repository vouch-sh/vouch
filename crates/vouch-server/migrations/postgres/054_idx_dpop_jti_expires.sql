-- Index for expired DPoP JTI cleanup
CREATE INDEX ASYNC idx_dpop_jti_expires ON dpop_jti_cache(expires_at);
