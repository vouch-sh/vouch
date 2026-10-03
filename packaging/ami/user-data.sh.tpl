#!/bin/bash -xe
# User-data template for AMI build instances
# Variables are substituted by envsubst before passing to EC2

exec > >(tee /var/log/user-data.log | logger -t user-data -s 2>/dev/console) 2>&1

# Set environment variables
export VERSION="${VERSION}"
export AWS_REGION="${AWS_REGION}"
export S3_BUCKET="${S3_BUCKET}"
export S3_PREFIX="${S3_PREFIX}"
export SB_KEY_S3_PATH="${SB_KEY_S3_PATH}"

echo "=== AMI Build Script Started ==="
echo "Instance ID: $(ec2-metadata -i | cut -d' ' -f2)"
echo "Region: ${AWS_REGION}"
echo "Version: ${VERSION}"
echo "S3 Bucket: ${S3_BUCKET}"
echo "S3 Prefix: ${S3_PREFIX}"
echo "SB Key S3 Path: ${SB_KEY_S3_PATH:-(not set)}"

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
    aws-nitro-tpm-tools sbsigntools
echo "Build dependencies installed"

# Download and extract AMI build files
echo "=== Downloading AMI build files ==="
aws s3 cp "s3://${S3_BUCKET}/${S3_PARENT_PREFIX}/ami-files.tar.gz" /tmp/ami-files.tar.gz
mkdir -p /tmp/ami-build
tar -xzf /tmp/ami-files.tar.gz -C /tmp/ami-build
cd /tmp/ami-build

# Download vouch-server binary from GitHub Releases
echo "=== Downloading vouch-server ${VERSION} from GitHub Releases ==="
ARCH=$(uname -m)
RPM_NAME="vouch-server-${VERSION}-1.${ARCH}.rpm"
RPM_URL="https://github.com/vouch-sh/vouch/releases/download/v${VERSION}/${RPM_NAME}"
curl -sfL "$RPM_URL" -o "/tmp/${RPM_NAME}"
echo "Downloaded ${RPM_NAME}"

# Verify the RPM is signed by the Vouch packages key before trusting its
# contents. This instance holds the Secure Boot signing key and the image it
# builds is what the PCR measurements attest, so an unverified download here
# would be the weakest link in that chain.
#
# The fingerprint is the trust anchor: the key is fetched over the network, so
# pinning the fingerprint is what makes a substituted key useless.
VOUCH_GPG_FPR="E43BAE80FF24FBA161CC580966761B8F3EC7055B"
curl -sfL "https://raw.githubusercontent.com/vouch-sh/packages/main/gpg/vouch.asc" \
  -o /tmp/vouch-packages.asc
FETCHED_FPR=$(gpg --show-keys --with-colons /tmp/vouch-packages.asc | awk -F: '/^fpr:/{print $10; exit}')
if [ "$FETCHED_FPR" != "$VOUCH_GPG_FPR" ]; then
  echo "FATAL: packages key fingerprint is ${FETCHED_FPR:-none}, expected $VOUCH_GPG_FPR" >&2
  exit 1
fi
rpm --import /tmp/vouch-packages.asc

# `rpm --checksig` exits 0 for an unsigned package whose digests are intact, so
# the presence of a PGP signature is asserted separately.
RPM_SIG=$(rpm --query --queryformat '%{SIGPGP:pgpsig}' --package "/tmp/${RPM_NAME}")
if [ -z "$RPM_SIG" ] || [ "$RPM_SIG" = "(none)" ]; then
  echo "FATAL: ${RPM_NAME} carries no PGP signature" >&2
  exit 1
fi
rpm --checksig "/tmp/${RPM_NAME}"
echo "Verified ${RPM_NAME}: signed by $VOUCH_GPG_FPR ($RPM_SIG)"

# Extract binary from RPM into KIWI overlay
mkdir -p /tmp/ami-build/root/usr/bin /tmp/rpm-extract
cd /tmp/rpm-extract
rpm2cpio "/tmp/${RPM_NAME}" | cpio -idm --no-absolute-filenames
cp usr/bin/vouch-server /tmp/ami-build/root/usr/bin/vouch-server
chmod 755 /tmp/ami-build/root/usr/bin/vouch-server
cd /tmp/ami-build
rm -rf /tmp/rpm-extract "/tmp/${RPM_NAME}"
echo "Extracted vouch-server binary to overlay"

# Download Secure Boot signing key from S3 (if configured)
if [ -n "${SB_KEY_S3_PATH}" ]; then
    echo "=== Downloading Secure Boot DB key ==="
    aws s3 cp "${SB_KEY_S3_PATH}/DB.key" /tmp/ami-build/DB.key
    aws s3 cp "${SB_KEY_S3_PATH}/DB.crt" /tmp/ami-build/DB.crt
    chmod 600 /tmp/ami-build/DB.key
    export DB_KEY="/tmp/ami-build/DB.key"
    export DB_CRT="/tmp/ami-build/DB.crt"
    echo "Secure Boot DB key downloaded"
else
    echo "WARNING: SB_KEY_S3_PATH not set, UKI will not be signed"
fi

# Substitute version in appliance.kiwi so the output image filename uses the correct version
sed -i "s|<version>1.0.0</version>|<version>${VERSION}</version>|" /tmp/ami-build/appliance.kiwi

# Show build configuration
echo "=== Build configuration ==="
ls -la /tmp/ami-build/
cat appliance.kiwi

# Build the image
echo "=== Starting kiwi-ng build ==="
kiwi-ng --color-output system build \
    --description /tmp/ami-build \
    --target-dir /tmp/image \
    --allow-existing-root \
    --clear-cache
echo "=== kiwi-ng build completed ==="

# Securely delete Secure Boot signing key
if [ -f /tmp/ami-build/DB.key ]; then
    echo "=== Securely deleting Secure Boot DB key ==="
    shred -u /tmp/ami-build/DB.key 2>/dev/null || rm -f /tmp/ami-build/DB.key
    rm -f /tmp/ami-build/DB.crt
    echo "Secure Boot DB key deleted"
fi

# Upload PCR measurements to S3
echo "=== Uploading PCR measurements to S3 ==="
if [ -f /tmp/image/pcr_measurements.json ]; then
    aws s3 cp /tmp/image/pcr_measurements.json "s3://${S3_BUCKET}/${S3_PREFIX}/pcr_measurements.json"
    echo "PCR measurements uploaded"
else
    echo "WARNING: pcr_measurements.json not found"
fi

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
COLDSNAP_VERSION="v0.9.1"
ARCH=$(uname -m)
# Piping the tarball straight into tar left no opportunity to verify it.
case "$ARCH" in
  x86_64)
    COLDSNAP_SHA256="7b78ad69dfaddf61e3a1819f794ea123d859705dcb5bfacdefeff2b1f92d713d"
    ;;
  aarch64)
    COLDSNAP_SHA256="0faec00abeb085da165b6a0d8944eeb2f0ac2227047c5556cf03b81128636ad9"
    ;;
  *)
    echo "FATAL: no pinned coldsnap checksum for architecture $ARCH" >&2
    exit 1
    ;;
esac
curl -sfL "https://github.com/jplock/coldsnap/releases/download/${COLDSNAP_VERSION}/coldsnap-${COLDSNAP_VERSION}-${ARCH}-unknown-linux-musl.tar.gz" \
  -o /tmp/coldsnap.tar.gz
echo "${COLDSNAP_SHA256}  /tmp/coldsnap.tar.gz" | sha256sum --check --strict -
tar -xzf /tmp/coldsnap.tar.gz -C /usr/local/bin
rm -f /tmp/coldsnap.tar.gz
chmod +x /usr/local/bin/coldsnap
echo "Coldsnap installed: $(which coldsnap)"

# Upload to EBS snapshot using coldsnap
echo "=== Uploading image to EBS snapshot ==="
SNAPSHOT_ID=$(coldsnap --region "${AWS_REGION}" upload "$RAW_IMAGE" --wait)
echo "=== Coldsnap upload completed ==="

echo "Created snapshot: $SNAPSHOT_ID"
echo "$SNAPSHOT_ID" > /tmp/snapshot-id.txt

# Upload snapshot ID to S3
echo "=== Uploading snapshot ID to S3 ==="
aws s3 cp /tmp/snapshot-id.txt "s3://${S3_BUCKET}/${S3_PREFIX}/snapshot-id.txt"

echo "=== Build script completed successfully ==="
