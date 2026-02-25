# GitHub

This chapter describes how Vouch integrates with GitHub for short-lived Git credentials via a shared GitHub App.

## GitHub App Integration

Vouch integrates with GitHub via a shared GitHub App to provide short-lived Git credentials:

- **Installation tokens** — 15-minute TTL, scoped to specific repositories
- **Minimal permissions** — `contents:write`, `metadata:read` only
- **Multi-org support** — Organizations can connect multiple GitHub accounts
- **Automatic selection** — Vouch determines the correct installation from the repo URL

**Flow:**
1. Org admin connects GitHub at `/github/connect`
2. User runs `vouch setup github --configure` to set up git credential helper
3. Git operations automatically request tokens via `vouch credential github`
4. Tokens are scoped to the specific GitHub organization being accessed

## Configuration

```
~/.gitconfig:
  [credential "https://github.com"]
    helper = vouch credential github

How it works:
1. Git calls credential helper for github.com
2. vouch requests GitHub App installation token
3. Server uses GitHub App private key to generate token
4. Token scoped to repositories org has granted access to
5. Short-lived (default 1 hour)
```
