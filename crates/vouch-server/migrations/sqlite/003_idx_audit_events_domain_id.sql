CREATE INDEX IF NOT EXISTS idx_audit_events_domain_id ON audit_events(email_domain, id);
