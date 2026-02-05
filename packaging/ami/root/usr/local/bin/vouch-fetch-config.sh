#!/bin/bash
set -e

# Get IMDSv2 token
TOKEN=$(curl -sX PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 300")

# Get region from instance metadata
REGION=$(curl -sH "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/placement/region)

# Get parameter name from instance tags via IMDS (default: /vouch-server/config)
# Requires instance launched with: --metadata-options "InstanceMetadataTags=enabled"
PARAM_NAME=$(curl -sfH "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/tags/instance/VouchConfigParameter 2>/dev/null || echo "")

if [ -z "$PARAM_NAME" ]; then
    PARAM_NAME="/vouch-server/config"
fi

# Create runtime directory
mkdir -p /run/vouch-server

# Fetch parameter and write directly to env file
# Parameter value should be KEY=VALUE pairs, one per line
aws ssm get-parameter \
    --region "$REGION" \
    --name "$PARAM_NAME" \
    --query Parameter.Value \
    --output text > /run/vouch-server/env

# Secure the env file
chmod 600 /run/vouch-server/env
chown vouch:vouch /run/vouch-server/env

echo "Configuration loaded from Parameter Store: $PARAM_NAME"
