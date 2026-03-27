#!/usr/bin/env python3
"""Register an OAuth client with the Vouch server via Dynamic Client Registration.

Reads client_alias and auth method from the plan config JSON, then:
  - client_secret_basic  (OIDC Basic plans)
  - private_key_jwt      (FAPI 2.0 plans — generates an ES256 key pair)

Writes CLIENT_ID, CLIENT_SECRET, and CLIENT_JWKS to GITHUB_ENV so that
subsequent workflow steps can reference them as environment variables.
"""

import argparse
import base64
import json
import os
import re
import sys
import urllib.request
from pathlib import Path


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


def build_payload(plan: str, client_alias: str, public_jwks: dict | None) -> dict:
    conformance_redirect = (
        f"https://www.certification.openid.net/test/a/{client_alias}/callback"
    )
    if public_jwks is not None:
        return {
            "redirect_uris": [conformance_redirect],
            "token_endpoint_auth_method": "private_key_jwt",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid",
            "jwks": public_jwks,
            "dpop_bound_access_tokens": True,
        }
    return {
        "redirect_uris": [conformance_redirect],
        "token_endpoint_auth_method": "client_secret_basic",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "scope": "openid email",
    }


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

    public_jwks = None
    private_jwks = None
    if is_fapi2:
        public_jwks, private_jwks = generate_ec_jwk(Path(args.key_dir))
        print("ES256 key pair generated")

    payload = build_payload(args.plan, client_alias, public_jwks)
    response = post_dcr(args.vouch_url, payload)
    print(f"DCR response: {json.dumps(response)}")

    client_jwks = (
        json.dumps(private_jwks, separators=(",", ":")) if private_jwks else ""
    )

    env = {
        "CLIENT_ID": response["client_id"],
        "CLIENT_SECRET": response.get("client_secret", ""),
        "CLIENT_JWKS": client_jwks,
        "CLIENT_REG_TOKEN": response.get("registration_access_token", ""),
    }

    # FAPI 2.0 tests require a second client for certain modules.
    if is_fapi2:
        public_jwks2, private_jwks2 = generate_ec_jwk(
            Path(args.key_dir) / "client2"
        )
        print("ES256 key pair generated for client2")
        payload2 = build_payload(args.plan, client_alias, public_jwks2)
        response2 = post_dcr(args.vouch_url, payload2)
        print(f"DCR response (client2): {json.dumps(response2)}")
        env["CLIENT2_ID"] = response2["client_id"]
        env["CLIENT2_SECRET"] = response2.get("client_secret", "")
        env["CLIENT2_JWKS"] = json.dumps(
            private_jwks2, separators=(",", ":")
        )
        env["CLIENT2_REG_TOKEN"] = response2.get("registration_access_token", "")

    write_github_env(env)


if __name__ == "__main__":
    main()
