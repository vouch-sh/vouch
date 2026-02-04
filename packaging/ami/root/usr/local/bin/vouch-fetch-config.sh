#!/bin/bash
set -e

# Get IMDSv2 token
TOKEN=$(curl -sX PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 300")

# Get region from instance metadata
REGION=$(curl -sH "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/placement/region)

# Get secret name from instance tags via IMDS (default: vouch-server/config)
# Requires instance launched with: --metadata-options "InstanceMetadataTags=enabled"
SECRET_NAME=$(curl -sfH "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/tags/instance/VouchSecretName 2>/dev/null || echo "")

if [ -z "$SECRET_NAME" ]; then
    SECRET_NAME="vouch-server/config"
fi

# Create runtime directory
mkdir -p /run/vouch-server

# Fetch secrets and write env file
# The secret should contain KEY=value pairs, one per line
aws secretsmanager get-secret-value \
    --region "$REGION" \
    --secret-id "$SECRET_NAME" \
    --query SecretString \
    --output text > /run/vouch-server/env

# Secure the env file
chmod 600 /run/vouch-server/env
chown vouch:vouch /run/vouch-server/env

echo "Configuration loaded from Secrets Manager: $SECRET_NAME"
