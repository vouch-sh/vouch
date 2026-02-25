# AWS Credentials

This chapter describes how Vouch integrates with the AWS CLI and SDKs to provide short-lived AWS credentials backed by hardware authentication.

## Configuration

```
~/.aws/config:
  [profile production]
    credential_process = vouch credential aws --role arn:aws:iam::123456789:role/developer

How it works:
1. AWS CLI/SDK calls credential_process
2. vouch gets OIDC token from server (exchanges access token)
3. vouch calls AWS STS AssumeRoleWithWebIdentity
4. Returns temporary credentials in credential_process format
5. Credentials expire in 1 hour, auto-refresh within session
```
