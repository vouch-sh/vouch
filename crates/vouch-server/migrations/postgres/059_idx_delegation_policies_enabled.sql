-- Index for filtering enabled delegation policies
CREATE INDEX ASYNC idx_delegation_policies_enabled ON delegation_policies(enabled);
