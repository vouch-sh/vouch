CREATE INDEX ASYNC idx_audit_events_domain_created ON audit_events(email_domain, created_at);
