#!/bin/bash -xe
# User-data template for AMI build instances
# Variables are substituted by envsubst before passing to EC2

exec > >(tee /var/log/user-data.log | logger -t user-data -s 2>/dev/console) 2>&1

# Set environment variables
export VERSION="${VERSION}"
export AWS_REGION="${AWS_REGION}"
export S3_BUCKET="${S3_BUCKET}"
export S3_PREFIX="${S3_PREFIX}"

echo "=== AMI Build Script Started ==="
echo "Instance ID: $(ec2-metadata -i | cut -d' ' -f2)"
echo "Region: ${AWS_REGION}"
echo "Version: ${VERSION}"
echo "S3 Bucket: ${S3_BUCKET}"
echo "S3 Prefix: ${S3_PREFIX}"

# Function to upload logs and signal completion
cleanup() {
    local exit_code=$?
    echo "=== Build finished with exit code: ${exit_code} ==="

    # Upload log to S3
    aws s3 cp /var/log/user-data.log "s3://${S3_BUCKET}/${S3_PREFIX}/build.log" || true

    # Signal completion by uploading status file
    if [ "$exit_code" -eq 0 ]; then
        echo "SUCCESS" > /tmp/build-status.txt
    else
        echo "FAILED" > /tmp/build-status.txt
    fi
    aws s3 cp /tmp/build-status.txt "s3://${S3_BUCKET}/${S3_PREFIX}/build-status.txt" || true
}
trap cleanup EXIT

# Install build dependencies
echo "=== Installing build dependencies ==="
dnf install -y -q \
    kiwi-cli python3-kiwi kiwi-systemdeps-core \
    python3-poetry-core qemu-img veritysetup erofs-utils \
    cargo aws-nitro-tpm-tools
echo "Build dependencies installed"

# Download and extract AMI build files
echo "=== Downloading AMI build files ==="
aws s3 cp "s3://${S3_BUCKET}/${S3_PARENT_PREFIX}/ami-files.tar.gz" /tmp/ami-files.tar.gz
mkdir -p /tmp/ami-build
tar -xzf /tmp/ami-files.tar.gz -C /tmp/ami-build
cd /tmp/ami-build

# Update version in appliance.kiwi
echo "=== Updating version to ${VERSION} ==="
sed -i "s/<version>.*<\/version>/<version>${VERSION}<\/version>/" appliance.kiwi

# Show build configuration
echo "=== Build configuration ==="
ls -la /tmp/ami-build/
cat appliance.kiwi

# Build the image
echo "=== Starting kiwi-ng build ==="
kiwi-ng --color-output system build \
    --description /tmp/ami-build \
    --target-dir /tmp/image \
    --allow-existing-root
echo "=== kiwi-ng build completed ==="

# Find the raw image
echo "=== Looking for raw image ==="
ls -la /tmp/image/
RAW_IMAGE=$(find /tmp/image -name "*.raw" | head -1)

if [ -z "$RAW_IMAGE" ]; then
    echo "ERROR: No raw image found"
    exit 1
fi

echo "Built image: $RAW_IMAGE"
ls -lh "$RAW_IMAGE"

# Install coldsnap for EBS snapshot upload (after image build to fail fast)
echo "=== Installing coldsnap ==="
cargo install --locked --quiet coldsnap
export PATH="/root/.cargo/bin:$PATH"
echo "Coldsnap installed: $(which coldsnap)"

# Upload to EBS snapshot using coldsnap
echo "=== Uploading image to EBS snapshot ==="
SNAPSHOT_ID=$(coldsnap upload "$RAW_IMAGE" --region "${AWS_REGION}" --wait)
echo "=== Coldsnap upload completed ==="

echo "Created snapshot: $SNAPSHOT_ID"
echo "$SNAPSHOT_ID" > /tmp/snapshot-id.txt

# Upload snapshot ID to S3
echo "=== Uploading snapshot ID to S3 ==="
aws s3 cp /tmp/snapshot-id.txt "s3://${S3_BUCKET}/${S3_PREFIX}/snapshot-id.txt"

echo "=== Build script completed successfully ==="
