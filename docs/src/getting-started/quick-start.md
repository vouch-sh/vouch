# Quick Start

Get up and running with Vouch in minutes. This guide assumes a Vouch server is already deployed and you have a YubiKey 5 series.

## Install

```bash
# macOS
brew install vouch-sh/tap/vouch

# Linux (Debian/Ubuntu)
# See https://packages.vouch.sh for repository setup
sudo apt install vouch

# Linux (RPM-based)
# See https://packages.vouch.sh for repository setup
sudo dnf install vouch

# From source
cargo install --git https://github.com/vouch-sh/vouch vouch-cli
```

## Enroll (One-Time)

Enrollment links your corporate identity to your YubiKey. This is done once per device.

```bash
vouch enroll
```

This opens a browser where you:
1. Sign in with your corporate identity (Google Workspace, Entra ID, etc.)
2. Touch your YubiKey and enter your PIN to register it
3. The CLI receives an access token automatically

## Configure Integrations

Set up the tools you use daily:

```bash
# SSH certificates
vouch setup ssh

# AWS credentials
vouch setup aws --role arn:aws:iam::123456789:role/developer

# EKS (Kubernetes)
vouch setup eks --cluster my-cluster

# GitHub
vouch setup github --configure

# Docker / ECR
vouch setup docker --account-id 123456789 --region us-east-1

# Cargo private registries
vouch setup cargo --configure
```

## Daily Use

Start your day with one command:

```bash
$ vouch login
Touch your YubiKey...
Enter PIN: ****
Authenticated as you@company.com (8 hours)
```

Then use your tools normally — no wrappers, no extra steps:

```bash
ssh prod-server                              # Uses SSH certificate
aws s3 ls                                    # Uses temporary AWS credentials
git push origin main                         # Uses GitHub token
kubectl get pods                             # Uses EKS credentials
docker pull 123456789.dkr.ecr...             # Uses ECR credentials
cargo publish --registry my-private-registry # Uses Cargo token
```

## Check Status

```bash
$ vouch status
Authenticated as you@company.com
Session expires in 7h 42m
```

## End of Day

Sessions expire automatically after 8 hours. To end early:

```bash
vouch logout
```

## Next Steps

- [Requirements](requirements.md) — Hardware and software prerequisites
- [Your First Enrollment](first-enrollment.md) — Detailed enrollment walkthrough
- [SSH Certificates](../integrations/ssh.md) — Configure SSH integration
- [AWS Credentials](../integrations/aws.md) — Configure AWS integration
