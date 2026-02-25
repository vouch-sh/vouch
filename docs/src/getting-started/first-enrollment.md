# Your First Enrollment

Enrollment is a one-time process that links your corporate identity to your hardware FIDO2 key. After enrollment, daily authentication is CLI-only — no browser required.

## Before You Begin

1. Your Vouch server is deployed and accessible
2. You have a YubiKey 5 series (firmware 5.2+) plugged in
3. You know which corporate identity provider your organization uses (Google Workspace, Entra ID, etc.)

## Step 1: Start Enrollment

```bash
vouch enroll
```

The CLI will:
1. Contact the Vouch server and request a device code (RFC 8628)
2. Display a URL and an 8-character code

```
To enroll, open this URL in your browser:

    https://vouch.example.com/device

And enter code: ABCD-1234

Waiting for authorization...
```

## Step 2: Authorize in Browser

1. Open the URL in your browser
2. Enter the code shown in the terminal
3. Sign in with your corporate identity (Google Workspace, Entra ID, etc.)

## Step 3: Register Your YubiKey

After signing in, the browser prompts you to register your YubiKey:

1. Touch your YubiKey when prompted
2. Enter your YubiKey PIN (or set one up if this is a new key)

> **PIN Requirements**: Vouch requires a minimum 8-character PIN. If your YubiKey doesn't have a PIN configured, the enrollment process will guide you through setting one up.

## Step 4: Enrollment Complete

The browser confirms enrollment and the CLI receives an access token:

```
Enrolled as you@company.com
Session valid for 8 hours
```

Behind the scenes, the CLI also:
- Generates an ES256 key pair for FAPI 2.0 client authentication (stored at `~/.vouch/client_key.json`)
- Registers as an OAuth client with the server via RFC 7591 Dynamic Client Registration

## Step 5: Register a Backup Key (Recommended)

Register a second YubiKey as a backup:

```bash
vouch register --name "Backup Key"
```

This requires your current session (from the enrollment you just completed) and a second YubiKey.

## What's Stored Where

| Location | Contents | Permissions |
|----------|----------|-------------|
| `~/.vouch/config.json` | Server URL, access token | 0600 |
| `~/.vouch/client_key.json` | FAPI 2.0 ES256 key pair | 0600 |
| `~/.vouch/cookie.txt` | Session cookie (Netscape format) | 0600 |
| `~/.vouch/agent.sock` | Agent IPC socket | 0700 (directory) |
| YubiKey | Discoverable credential (private key) | Hardware-protected |

## Next Steps

Now configure the integrations you need:

- [SSH Certificates](../integrations/ssh.md)
- [AWS Credentials](../integrations/aws.md)
- [GitHub](../integrations/github.md)
- [Quick Start](quick-start.md) — Full setup overview

## Troubleshooting

**YubiKey not detected:**
```bash
# Check USB connection
vouch doctor

# On Linux, verify udev rules are configured
lsusb | grep Yubico
```

**PIN setup fails:**
- Ensure PIN is at least 8 characters
- If PIN is blocked (too many wrong attempts), reset with `ykman fido reset` (destructive — re-enrollment required)

**Browser authorization times out:**
- Device codes expire after 10 minutes
- Run `vouch enroll` again to get a fresh code
