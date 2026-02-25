# CLI Commands

The `vouch` CLI is the user-facing tool for authentication and credential management. Below is a reference for all available commands.

## Authentication

### `vouch enroll`

One-time enrollment that registers your YubiKey with the Vouch server. Opens a browser for OIDC-based identity verification, then completes WebAuthn registration.

```bash
# Enroll with your YubiKey (opens browser)
vouch enroll
```

This is typically only done once per user per device. After enrollment, use `vouch login` for daily authentication.

### `vouch login`

Daily authentication using your YubiKey. Performs FIDO2 assertion (touch + PIN) directly from the CLI without requiring a browser. Establishes an 8-hour session.

```bash
# Authenticate with your YubiKey
vouch login
```

The login flow uses FAPI 2.0 with DPoP-bound access tokens for sender-constrained security.

### `vouch logout`

End the current session and clear cached credentials.

```bash
# End your session
vouch logout
```

### `vouch status`

Check the current session status, including the authenticated user, session expiration time, and remaining duration.

```bash
# Check session status
vouch status
```

### `vouch register`

Add an additional YubiKey to your account (e.g., a backup key). Requires an active session (run `vouch login` first).

```bash
# Register a backup YubiKey
vouch register
```

### `vouch keys`

Manage registered YubiKeys. Supports listing, removing, and renaming keys. Can be used as an interactive menu or with subcommands.

```bash
# Interactive key management menu
vouch keys

# List all registered keys
vouch keys list

# Remove a key
vouch keys remove

# Rename a key
vouch keys rename
```

## Credential Helpers

These commands retrieve short-lived credentials from the Vouch server. They are typically invoked automatically by native tools via credential helper configuration.

### `vouch credential ssh`

Get an SSH certificate signed by the Vouch SSH CA. Used by the vouch agent's SSH agent protocol to transparently provide certificates to the `ssh` command.

```bash
# Get an SSH certificate
vouch credential ssh
```

### `vouch credential aws`

Get temporary AWS credentials (via STS AssumeRoleWithWebIdentity). Used as an AWS `credential_process` provider.

```bash
# Get AWS credentials
vouch credential aws
```

### `vouch credential github`

Get a GitHub access token via the Vouch GitHub App integration. Used as a git credential helper.

```bash
# Get a GitHub token
vouch credential github
```

### `vouch credential docker`

Get Docker/ECR credentials for authenticating with container registries.

```bash
# Get Docker/ECR credentials
vouch credential docker
```

### `vouch credential cargo`

Get a Cargo registry authentication token for private crate registries.

```bash
# Get Cargo registry token
vouch credential cargo
```

### `vouch credential codeartifact`

Get an AWS CodeArtifact authentication token for accessing private package repositories.

```bash
# Get CodeArtifact token
vouch credential codeartifact
```

### `vouch credential codecommit`

Get AWS CodeCommit credentials for git operations.

```bash
# Get CodeCommit credentials
vouch credential codecommit
```

## Setup Commands

These commands configure native tools to use Vouch as their credential provider. Typically run once per integration.

### `vouch setup ssh`

Configure SSH to use Vouch certificates by setting the `IdentityAgent` to point to the vouch agent's SSH agent socket.

```bash
# Configure SSH to use vouch certificates
vouch setup ssh
```

### `vouch setup aws`

Configure AWS CLI to use Vouch as its `credential_process` provider.

```bash
# Configure AWS with a specific IAM role
vouch setup aws --role arn:aws:iam::123456789012:role/VouchRole
```

### `vouch setup eks`

Configure `kubectl` for Amazon EKS clusters. Chains through `vouch credential aws` and `aws eks get-token` for transparent Kubernetes authentication.

```bash
# Configure kubectl for an EKS cluster
vouch setup eks --cluster my-cluster
```

### `vouch setup github`

Configure git to use Vouch as the credential helper for GitHub repositories.

```bash
# Configure git credential helper for GitHub
vouch setup github --configure
```

### `vouch setup docker`

Configure Docker to use Vouch for ECR authentication.

```bash
# Configure Docker/ECR integration
vouch setup docker
```

### `vouch setup cargo`

Configure Cargo to use Vouch for private registry authentication.

```bash
# Configure Cargo registry integration
vouch setup cargo
```

### `vouch setup codeartifact`

Configure tools to use Vouch for AWS CodeArtifact authentication.

```bash
# Configure CodeArtifact integration
vouch setup codeartifact
```

### `vouch setup codecommit`

Configure git to use Vouch for AWS CodeCommit authentication.

```bash
# Configure CodeCommit integration
vouch setup codecommit
```

## Diagnostic & Utility

### `vouch doctor`

Run diagnostic checks on your system, verifying YubiKey connectivity, agent status, server reachability, and integration configuration.

```bash
# Run diagnostic checks
vouch doctor
```

### `vouch completions`

Generate shell completion scripts for bash, zsh, or fish.

```bash
# Generate zsh completions
vouch completions zsh

# Generate bash completions
vouch completions bash

# Generate fish completions
vouch completions fish
```
