#!/bin/bash
set -e

# Detect IMDS endpoint: prefer IPv6 (dualstack) to avoid timeout delays
# The probe omits -f intentionally — IMDSv2 returns HTTP 401 without a token,
# but curl exits 0 because the TCP connection succeeded, which is what we're testing
IMDS_IPV6="http://[fd00:ec2::254]:80"
IMDS_IPV4="http://169.254.169.254:80"
if curl -s --connect-timeout 1 -o /dev/null "${IMDS_IPV6}/latest/meta-data/"; then
    IMDS_ENDPOINT="${IMDS_IPV6}"
else
    IMDS_ENDPOINT="${IMDS_IPV4}"
fi

# Get IMDSv2 token
TOKEN=$(curl -sX PUT "${IMDS_ENDPOINT}/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 300")

# Get region and availability zone from instance metadata
REGION=$(curl -sH "X-aws-ec2-metadata-token: $TOKEN" \
    "${IMDS_ENDPOINT}/latest/meta-data/placement/region")
AZ=$(curl -sH "X-aws-ec2-metadata-token: $TOKEN" \
    "${IMDS_ENDPOINT}/latest/meta-data/placement/availability-zone")

# Get parameter name from instance tags via IMDS (default: /vouch-server/config)
# Requires instance launched with: --metadata-options "InstanceMetadataTags=enabled"
PARAM_NAME=$(curl -sfH "X-aws-ec2-metadata-token: $TOKEN" \
    "${IMDS_ENDPOINT}/latest/meta-data/tags/instance/VouchConfigParameter" 2>/dev/null || echo "")

if [ -z "$PARAM_NAME" ]; then
    PARAM_NAME="/vouch-server/config"
fi

# Create runtime directory
mkdir -p /run/vouch-server

# Fetch parameter and write directly to env file
# Parameter value should be KEY=VALUE pairs, one per line
# Use dualstack endpoints so the AWS CLI works in IPv6-only and dualstack subnets
AWS_USE_DUALSTACK_ENDPOINT=true aws ssm get-parameter \
    --region "$REGION" \
    --name "$PARAM_NAME" \
    --query Parameter.Value \
    --output text > /run/vouch-server/env

# Append AWS_AZ to the env file
# These are used by vouch-server for DSQL endpoint resolution
echo "AWS_AZ=$AZ" >> /run/vouch-server/env

# Secure the env file
chmod 600 /run/vouch-server/env
chown vouch:vouch /run/vouch-server/env

echo "Configuration loaded from Parameter Store: $PARAM_NAME (region: $REGION, az: $AZ)"
