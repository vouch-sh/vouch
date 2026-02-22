-- Add scope granularity to SCIM tokens
ALTER TABLE scim_tokens ADD COLUMN scope TEXT NOT NULL DEFAULT 'users:read,users:write,groups:read,groups:write';
