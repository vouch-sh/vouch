#!/bin/bash -xe
# User-data template for AMI build instances
# Variables are substituted by envsubst before passing to EC2

exec > >(tee /var/log/user-data.log | logger -t user-data -s 2>/dev/console) 2>&1

# Set environment variables
export VERSION="${VERSION}"
export AWS_REGION="${AWS_REGION}"
export S3_BUCKET="${S3_BUCKET}"
export S3_PREFIX="${S3_PREFIX}"

echo "=== User-data script started ==="
echo "Downloading build script from S3..."

# Download and run the build script
aws s3 cp "s3://${S3_BUCKET}/${S3_PARENT_PREFIX}/build-ami.sh" /tmp/build-ami.sh
chmod +x /tmp/build-ami.sh
/tmp/build-ami.sh
