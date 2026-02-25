# CodeArtifact

This chapter describes how Vouch integrates with AWS CodeArtifact for authenticating to private package repositories.

## Configuration

```
~/.aws/config:
  [profile vouch-codeartifact]
    credential_process = vouch credential aws --role arn:aws:iam::123456789:role/developer

How it works:
1. vouch credential codeartifact calls vouch credential aws to get temporary AWS credentials
2. Uses those credentials to call CodeArtifact GetAuthorizationToken
3. Returns an authorization token for the CodeArtifact domain
4. Token is used by package managers (npm, pip, cargo, maven) for registry auth
```

## Setup

**`vouch setup codeartifact` creates:**
- Package manager configuration pointing to the CodeArtifact repository
- Credential provider configuration that chains through `vouch credential aws`

## Usage

```bash
# Configure npm for CodeArtifact
vouch setup codeartifact --domain my-domain --repository my-repo --tool npm

# Configure pip for CodeArtifact
vouch setup codeartifact --domain my-domain --repository my-repo --tool pip

# Then use package managers normally
npm install my-private-package
pip install my-private-package
```
