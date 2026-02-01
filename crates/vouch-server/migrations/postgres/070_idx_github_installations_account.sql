-- Index for GitHub installation lookups by account login
CREATE INDEX ASYNC idx_github_installations_account ON github_installations(github_account_login);
