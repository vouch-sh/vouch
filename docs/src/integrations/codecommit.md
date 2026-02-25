# CodeCommit

This chapter describes how Vouch integrates with AWS CodeCommit for Git authentication over HTTPS.

## Configuration

```
~/.gitconfig:
  [credential "https://git-codecommit.us-east-1.amazonaws.com"]
    helper = vouch credential codecommit

How it works:
1. Git calls vouch as a credential helper for CodeCommit HTTPS URLs
2. vouch exchanges access token for AWS credentials via credential_process
3. Uses AWS credentials to generate CodeCommit Git credentials
4. Returns username/password for HTTPS Git authentication
```

## Setup

**`vouch setup codecommit` creates:**
- Git credential helper configuration in `~/.gitconfig` for CodeCommit URLs
- Chains through `vouch credential aws` for IAM authentication

## Usage

```bash
# Configure git for CodeCommit
vouch setup codecommit --region us-east-1

# Then use git normally
git clone https://git-codecommit.us-east-1.amazonaws.com/v1/repos/my-repo
git push origin main
```
