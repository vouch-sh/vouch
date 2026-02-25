# Docker / ECR

This chapter describes how Vouch integrates with Docker for authenticating to Amazon ECR container registries.

## Configuration

```
~/.docker/config.json:
  {
    "credHelpers": {
      "123456789.dkr.ecr.us-east-1.amazonaws.com": "vouch"
    }
  }

How it works:
1. Docker calls vouch as a credential helper (docker-credential-vouch)
2. vouch exchanges access token for AWS credentials via credential_process
3. vouch calls ECR GetAuthorizationToken with AWS credentials
4. Returns Docker credentials (username/password) for the ECR registry
5. Credentials auto-refresh within the session
```

## Setup

**`vouch setup docker` creates:**
- Docker credential helper configuration in `~/.docker/config.json`
- Maps ECR registry hosts to the vouch credential helper
