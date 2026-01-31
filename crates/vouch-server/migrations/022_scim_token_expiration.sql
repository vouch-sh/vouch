-- Set expiration for existing SCIM tokens that don't have one
UPDATE scim_tokens
SET expires_at = datetime('now', '+365 days')
WHERE expires_at IS NULL;
