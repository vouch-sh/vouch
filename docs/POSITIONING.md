# Positioning

This document describes Vouch's competitive positioning and differentiation.

## Differences from Amazon Midway

Vouch is inspired by Amazon's internal Midway system but differs in several ways:

| Aspect | Midway (Amazon Internal) | Vouch |
|--------|-------------------------|-------|
| Deployment | Internal only | SaaS + self-hosted |
| Hardware | Amazon-issued Yubikeys | BYOD hardware FIDO2 keys |
| Login | Email required | Discoverable credential (no email) |
| CA | External PKI | Built-in Ed25519 CA |
| IdP | Internal | Google Workspace (extensible) |
| Open source | No | CLI is open source |

## Vouch vs WorkOS

| Aspect | WorkOS | Vouch |
|--------|--------|-------|
| **Target Customer** | B2B SaaS vendors | Enterprises (internal use) |
| **Purpose** | "Make your app enterprise-ready" | "Secure internal access with hardware auth" |
| **IdP Role** | Integrates with customer's IdP | IS the IdP |
| **Direction** | Your app → customer's Okta/Entra | Your employees → Vouch → your apps |
| **Hardware Focus** | None specific | Hardware FIDO2 key required |

**Summary**: Not competitors. WorkOS helps SaaS companies add SSO/SCIM to sell to enterprises. Vouch IS the enterprise authentication system.

- WorkOS customer: "I'm building a SaaS product and need to support customer SSO."
- Vouch customer: "I'm an enterprise and need to secure my employees' access to internal tools."

## Vouch vs AWS Verified Access

| Aspect | AWS Verified Access | Vouch |
|--------|---------------------|-------|
| **What it is** | Zero-trust access gateway | Hardware-backed identity provider |
| **Authentication** | Integrates with IdPs | IS the IdP |
| **Where it runs** | AWS-hosted (network layer) | Self-hosted or cloud |
| **Access Model** | Per-request evaluation | Session + short-lived credentials |
| **Device Trust** | Via MDM integration | Via hardware FIDO2 key |
| **VPN** | Replaces VPN | Complements/replaces VPN |

**Summary**: Complementary, not competitive. AWS Verified Access needs an IdP to authenticate users — Vouch can be that IdP. Different layers: Vouch = identity layer, AWS VA = access layer.

## Vouch vs Traditional IdPs (Okta, Auth0, etc.)

| Feature | Vouch | Okta/Auth0/etc. | Platform Passkeys |
|---------|-------|-----------------|-------------------|
| Hardware required | Yes | Optional | No |
| Syncable credentials | No | Yes | Yes |
| Built-in SSH CA | Yes | No | No |
| Discoverable login | Yes | No | Yes |
| 8-hour sessions | Yes | Configurable | N/A |
| Self-hosted | Yes | No | N/A |

**Core differentiator**: Most identity systems allow platform passkeys (Touch ID, Windows Hello), TOTP/SMS, and push notifications. Vouch requires hardware FIDO2 keys only — hardware-bound, non-extractable, presence required.

## Positioning Summary

```
                    Hardware Required
                          │
          Vouch ◄─────────┼─────────► Platform Passkeys
   (hardware keys only)   │          (Touch ID, Windows Hello)
                          │
    Amazon Midway         │          Most IdPs
    (internal only)       │          (Okta, Auth0, etc.)
                          │
                          │
                    Software Optional
```

**Target customers**: Organizations where credential theft is an existential risk (finance, healthcare, critical infrastructure), compliance requires hardware tokens (SOC 2, FedRAMP, HIPAA), remote work makes "trust the network" obsolete, or platform passkeys are too risky (syncable = exfiltrable).
