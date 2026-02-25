# YubiKey Provisioning

In an air-gapped environment, YubiKey provisioning is done entirely on the internal network through the Vouch server's web UI. This chapter covers the provisioning workflow, hardware requirements, and spare key strategy.

## Provisioning Workflow

1. **Administrator** creates a user account via the Vouch server web interface
2. **User** navigates to `https://auth.internal` on their workstation browser
3. **User** inserts their YubiKey and completes the WebAuthn registration flow
4. **User** sets a PIN on their YubiKey if one is not already configured (minimum 8 characters)
5. The credential is registered and the user can begin authenticating

## YubiKey Requirements

- YubiKey 5 series with firmware 5.2+
- FIDO2/WebAuthn support enabled
- PIN configured (minimum 8 characters)

## Spare Key Strategy

Each user should register at least two YubiKeys (primary and backup). If a YubiKey is lost or damaged:

1. User reports lost key to administrator
2. Administrator revokes the lost key's credential via the web UI
3. User registers their backup YubiKey
