#!/usr/bin/env python3
"""Register an OAuth client with the Vouch server via Dynamic Client Registration.

Reads client_alias and variant from the plan config JSON, then:
  - client_secret_basic       (OIDC Basic plans)
  - private_key_jwt           (FAPI 2.0 plans — generates an ES256 key pair)
  - tls_client_auth           (FAPI 2.0 MTLS plans — generates self-signed cert)

Writes CLIENT_ID, CLIENT_SECRET, CLIENT_JWKS, and optionally MTLS_CERT,
MTLS_KEY, TLS_CLIENT_AUTH_SUBJECT_DN to GITHUB_ENV.
"""

import argparse
import base64
import datetime
import json
import os
import re
import sys
import urllib.request
from pathlib import Path


def parse_variant(raw: str) -> dict[str, str]:
    """Extract the variant object from raw config JSON."""
    match = re.search(r'"variant"\s*:\s*(\{[^}]+\})', raw, re.DOTALL)
    if not match:
        return {}
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return {}


def generate_self_signed_cert(cn: str) -> tuple[str, str, str]:
    """Generate a self-signed X.509 cert. Returns (cert_pem, key_pem, subject_dn)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(
            datetime.datetime.now(datetime.UTC)
            + datetime.timedelta(days=365)
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem, f"CN={cn}"


def b64url(n: int, length: int = 32) -> str:
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()


def generate_ec_jwk(key_dir: Path) -> tuple[dict, dict]:
    """Generate an ES256 key pair and return (public_jwks, private_jwks)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    private_key = ec.generate_private_key(ec.SECP256R1())
    key_dir.mkdir(parents=True, exist_ok=True)
    pem_path = key_dir / "client.key"
    pem_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

    pub = private_key.public_key().public_numbers()
    priv = private_key.private_numbers()

    public_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(pub.x),
        "y": b64url(pub.y),
        "kid": "cert-key-1",
        "use": "sig",
        "alg": "ES256",
    }
    private_jwk = {**public_jwk, "d": b64url(priv.private_value)}

    return {"keys": [public_jwk]}, {"keys": [private_jwk]}


def build_payload(
    plan: str,
    client_alias: str,
    public_jwks: dict | None,
    is_second_client: bool = False,
    client_auth_type: str = "private_key_jwt",
    sender_constrain: str = "dpop",
    subject_dn: str = "",
) -> dict:
    conformance_redirect = (
        f"https://www.certification.openid.net/test/a/{client_alias}/callback"
    )
    if public_jwks is None:
        return {
            "redirect_uris": [conformance_redirect],
            "token_endpoint_auth_method": "client_secret_basic",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid email",
        }

    redirect_uris = [conformance_redirect]
    if is_second_client:
        redirect_uris.append(
            f"{conformance_redirect}?dummy1=lorem&dummy2=ipsum"
        )

    auth_method = (
        "tls_client_auth"
        if client_auth_type == "mtls"
        else "private_key_jwt"
    )

    payload: dict = {
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": auth_method,
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "scope": "openid email",
        "jwks": public_jwks,
    }

    if client_auth_type == "mtls" and subject_dn:
        payload["tls_client_auth_subject_dn"] = subject_dn

    if sender_constrain == "dpop":
        payload["dpop_bound_access_tokens"] = True
    elif sender_constrain == "mtls":
        payload["tls_client_certificate_bound_access_tokens"] = True

    return payload


def post_dcr(vouch_url: str, payload: dict) -> dict:
    url = vouch_url.rstrip("/") + "/oauth/register"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:  # noqa: S310
        return json.loads(resp.read())


def write_github_env(env: dict[str, str]) -> None:
    github_env = os.environ.get("GITHUB_ENV")
    if github_env:
        with open(github_env, "a") as f:
            for k, v in env.items():
                f.write(f"{k}={v}\n")
    else:
        # Local dev: just print
        for k, v in env.items():
            print(f"{k}={v}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, help="Conformance test plan name")
    parser.add_argument(
        "--config",
        required=True,
        type=Path,
        help="Path to plan config JSON (reads client_alias from it)",
    )
    parser.add_argument(
        "--vouch-url",
        default="http://localhost:3000",
        help="Base URL of the Vouch server",
    )
    parser.add_argument(
        "--key-dir",
        default="/tmp/vouch-cert-keys",
        help="Directory for generated key files",
    )
    args = parser.parse_args()

    # The config template may contain bare placeholders like {CLIENT_JWKS}
    # that aren't valid JSON, so we extract client_alias via regex instead
    # of json.loads.
    raw = args.config.read_text()
    match = re.search(r'"client_alias"\s*:\s*"([^"]+)"', raw)
    client_alias = match.group(1) if match else None
    if not client_alias:
        print(f"ERROR: No client_alias in {args.config}", file=sys.stderr)
        sys.exit(1)

    is_fapi2 = "fapi2" in args.plan
    variant = parse_variant(raw)
    client_auth_type = variant.get("client_auth_type", "private_key_jwt")
    sender_constrain = variant.get("sender_constrain", "dpop")
    needs_mtls = client_auth_type == "mtls" or sender_constrain == "mtls"

    public_jwks = None
    private_jwks = None
    if is_fapi2:
        public_jwks, private_jwks = generate_ec_jwk(Path(args.key_dir))
        print("ES256 key pair generated")

    cert_pem = ""
    key_pem = ""
    subject_dn = ""
    if is_fapi2 and needs_mtls:
        cert_pem, key_pem, subject_dn = generate_self_signed_cert(
            f"{client_alias}-client1"
        )
        print("mTLS client cert generated")

    payload = build_payload(
        args.plan,
        client_alias,
        public_jwks,
        client_auth_type=client_auth_type,
        sender_constrain=sender_constrain,
        subject_dn=subject_dn,
    )
    response = post_dcr(args.vouch_url, payload)
    print(f"DCR response: {json.dumps(response)}")

    client_jwks = (
        json.dumps(private_jwks, separators=(",", ":")) if private_jwks else ""
    )

    env: dict[str, str] = {
        "CLIENT_ID": response["client_id"],
        "CLIENT_SECRET": response.get("client_secret", ""),
        "CLIENT_JWKS": client_jwks,
        "CLIENT_REG_TOKEN": response.get("registration_access_token", ""),
    }

    if is_fapi2 and needs_mtls:
        env["MTLS_CERT"] = cert_pem
        env["MTLS_KEY"] = key_pem
        env["TLS_CLIENT_AUTH_SUBJECT_DN"] = subject_dn

    # FAPI 2.0 tests require a second client for certain modules.
    if is_fapi2:
        public_jwks2, private_jwks2 = generate_ec_jwk(
            Path(args.key_dir) / "client2"
        )
        print("ES256 key pair generated for client2")

        cert_pem2 = ""
        key_pem2 = ""
        subject_dn2 = ""
        if needs_mtls:
            cert_pem2, key_pem2, subject_dn2 = generate_self_signed_cert(
                f"{client_alias}-client2"
            )
            print("mTLS client cert generated for client2")

        payload2 = build_payload(
            args.plan,
            client_alias,
            public_jwks2,
            is_second_client=True,
            client_auth_type=client_auth_type,
            sender_constrain=sender_constrain,
            subject_dn=subject_dn2,
        )
        response2 = post_dcr(args.vouch_url, payload2)
        print(f"DCR response (client2): {json.dumps(response2)}")
        env["CLIENT2_ID"] = response2["client_id"]
        env["CLIENT2_SECRET"] = response2.get("client_secret", "")
        env["CLIENT2_JWKS"] = json.dumps(
            private_jwks2, separators=(",", ":")
        )
        env["CLIENT2_REG_TOKEN"] = response2.get("registration_access_token", "")

        if needs_mtls:
            env["MTLS2_CERT"] = cert_pem2
            env["MTLS2_KEY"] = key_pem2
            env["TLS_CLIENT_AUTH_SUBJECT_DN2"] = subject_dn2

    write_github_env(env)


if __name__ == "__main__":
    main()
