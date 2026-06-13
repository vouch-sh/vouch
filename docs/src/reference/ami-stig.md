# AMI STIG Alignment

This page documents how the Vouch Server **attestable AMI** aligns with the
[DISA Security Technical Implementation Guide (STIG)](https://public.cyber.mil/stigs/)
for its base operating system, **Amazon Linux 2023 (STIG V1R2)**.

It complements the application-level [Compliance Mapping](compliance.md): that
page covers the Vouch authentication model, while this page covers the operating
system posture of the AMI itself.

## Why Vouch does not run the AWS STIG hardening scripts

AWS publishes
[STIG hardening script bundles](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-stig-downloads.html)
(`LinuxAWSConfigureSTIG.tgz`) that are applied to a *running, mutable* instance,
typically through an SSM document or as EC2 Image Builder `STIG-Build-Linux`
components.

The Vouch AMI does not use them, by design:

- **Immutable root filesystem.** The root partition is mounted read-only with
  **dm-verity** and `panic-on-corruption`. Runtime remediation scripts either
  fail to persist (writes land on an overlay tmpfs) or trip the integrity check.
  All hardening is instead baked in at build time so it lives behind the same
  dm-verity measurement and TPM attestation (PCR4/7/12) as the rest of the image.
- **Minimal attack surface.** The scripts can re-enable services and install
  third-party packages. The AMI deliberately omits SSH, the SSM agent,
  cloud-init, and `ec2-instance-connect`; re-introducing them would weaken the
  posture rather than strengthen it.
- **Already met or exceeded.** As the mapping below shows, the appliance design
  satisfies — and in several areas exceeds — the controls those scripts enforce.

## Control mapping

Status legend:

- **Met** — satisfied by an explicit configuration in the image.
- **Exceeded** — satisfied by a stronger mechanism than the STIG requires.
- **N/A by design** — the control targets functionality the appliance does not
  ship (no interactive login, no SSH, no desktop).
- **Build-time control** — enforced via configuration baked into the image.

| STIG area | Status | Mechanism (file) |
|-----------|--------|------------------|
| Remote access / SSH daemon hardening | **N/A by design / Exceeded** | `openssh-server` is not installed, `sshd` is masked, and any host keys are removed — there is no remote shell to harden (`appliance.kiwi`, `config.sh`) |
| Interactive account policy (PAM, `pwquality`, `faillock`, session timeout, login banners) | **N/A by design** | No interactive user accounts exist and the root account is locked (`passwd -l root`); configuration is delivered only via AWS Parameter Store |
| FIPS-validated cryptography | **Met** | Kernel `fips=1` plus OS crypto-policy set to FIPS (`appliance.kiwi`, `config.sh`); the server binary additionally embeds the aws-lc-rs FIPS module |
| Boot loader integrity / boot loader password | **Exceeded** | UEFI Secure Boot with a signed Unified Kernel Image, no GRUB present, and TPM PCR measurements (PCR4/7/12) published as AMI tags for attestation |
| File-integrity monitoring (e.g. AIDE) | **Exceeded** | dm-verity provides cryptographic, kernel-enforced integrity of the entire root filesystem with `panic-on-corruption` |
| Filesystem mount options (`nosuid`/`nodev`/`noexec`) | **Met (partial)** | `/boot/efi` is mounted `ro,nosuid,nodev,noexec` (`fstab.script`); the root filesystem is read-only via dm-verity |
| Kernel parameters / `sysctl` hardening | **Build-time control** | `etc/sysctl.d/90-vouch-hardening.conf` sets ASLR, `dmesg_restrict`, `kptr_restrict`, `ptrace_scope`, `suid_dumpable`, reverse-path filtering, redirect/source-route rejection, SYN cookies, and related settings |
| Host firewall | **N/A by design** | `firewalld` is not installed; network exposure is controlled by EC2 security groups, and the only listening service is the Vouch server |
| Time synchronization integrity | **Met** | chrony with the command port disabled (`chrony.d/10-disable-cmdport.conf`); GPS/NTP supported for air-gapped deployments |
| Audit logging (`auditd` rules) | **Partial — see note** | Application and system logs are forwarded to CloudWatch Logs; a kernel `auditd` ruleset is not currently shipped |
| Service / package minimization | **Met / Exceeded** | Curated minimal package set; `ec2-hibinit-agent`, `update-motd`, GRUB, and remote-access packages are explicitly excluded (`appliance.kiwi`) |
| Process privilege restriction | **Exceeded** | The server runs as an unprivileged user under strict systemd sandboxing (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `ReadWritePaths`) |

## Known gap: kernel audit (`auditd`)

The most material difference from a fully STIG-hardened general-purpose host is
the absence of a kernel `auditd` ruleset. On this appliance the gap is narrow:

- There are no interactive users or shells to audit, which is the primary target
  of most STIG audit rules.
- Application and credential-issuance events are logged by the Vouch server and
  forwarded to CloudWatch Logs alongside system journald output.

For deployments with a contractual `auditd` requirement, `auditd` and a STIG
audit ruleset can be added to the image (package in `appliance.kiwi`, service
enablement in `config.sh`, rules under `etc/audit/rules.d/`, and log forwarding
in the CloudWatch agent configuration). This is not enabled by default to keep
the image minimal and avoid a writable audit-log path on an otherwise userless
appliance.
