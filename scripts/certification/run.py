#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""
Run an OpenID conformance test plan against a Vouch server.

Orchestrates the full certification workflow:
  1. Load config template and substitute {BASEURL}, {CLIENT_ID}, {CLIENT_SECRET}, {CLIENT_JWKS}
  2. Create a test plan (public only when --publish is set)
  3. Run each module sequentially, collecting results
  4. Export HTML report and ZIP archive
  5. Optionally create a formal certification package (--publish)
  6. Print a summary table; exit non-zero if any module is not in PASSING_RESULTS

Usage:
    python3 run.py \\
        --plan oidcc-basic-certification-test-plan \\
        --config config/oidcc-basic.json \\
        --base-url https://xxx.trycloudflare.com \\
        --client-id <CLIENT_ID> \\
        --client-secret <CLIENT_SECRET> \\
        [--export-dir /tmp/cert-results] \\
        [--publish]

Environment variables:
    CONFORMANCE_SERVER   Base URL of the conformance server (default: https://www.certification.openid.net/)
    CONFORMANCE_TOKEN    Bearer token for the conformance API
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from conformance import ConformanceClient, ConformanceError

log = logging.getLogger(__name__)

# Result values that count as "passed enough" (WARNING is still OK for cert).
# Anything not in this set — including "FAILED" and "UNKNOWN" — is treated as
# a failure so that missing or unexpected result values never silently pass CI.
PASSING_RESULTS = {"PASSED", "WARNING", "REVIEW", "SKIPPED"}


def load_config(
    config_path: Path,
    base_url: str,
    client_id: str,
    client_secret: str,
    client_jwks: str,
    publish: bool,
    version: str = "",
) -> dict:
    """Load and substitute the config template."""
    raw = config_path.read_text()
    # Placeholders embedded in JSON strings must be escaped as JSON string
    # fragments so special characters (", \, newlines, etc.) cannot break JSON.
    def json_escape_fragment(value: str) -> str:
        return json.dumps(value)[1:-1]

    substitutions = {
        "{BASEURL}": json_escape_fragment(base_url.rstrip("/")),
        "{CLIENT_ID}": json_escape_fragment(client_id),
        "{CLIENT_SECRET}": json_escape_fragment(client_secret),
        "{CLIENT_JWKS}": client_jwks or "null",
        "{VERSION}": json_escape_fragment(version or "dev"),
    }
    for placeholder, value in substitutions.items():
        raw = raw.replace(placeholder, value)
    config = json.loads(raw)
    if publish:
        config["publish"] = "everything"
    else:
        config.pop("publish", None)
    return config


def print_summary(results: list[dict], plan_id: str, conformance_server: str) -> None:
    """Print a formatted summary table of module results."""
    width = 60
    print("\n" + "=" * width)
    print("OpenID Conformance Test Results")
    print("=" * width)

    counts: dict[str, int] = {}
    for r in results:
        result = r.get("result", "UNKNOWN")
        counts[result] = counts.get(result, 0) + 1
        icon = "✓" if result in PASSING_RESULTS else "✗"
        print(f"  {icon} [{result:<8}] {r['name']}")

    print("-" * width)
    print("  " + " | ".join(f"{v} {k}" for k, v in sorted(counts.items())))
    print("=" * width)
    print(f"\nPublic results: {conformance_server}/plans.html?public=true")
    print(f"Plan ID: {plan_id}\n")


def run_plan(
    plan_name: str,
    config: dict,
    variant: dict | None,
    export_dir: Path,
    publish: bool,
    conformance_server: str,
    conformance_token: str,
    module_timeout: int,
) -> bool:
    """Run all modules in a test plan. Returns True if all passed."""
    client = ConformanceClient(server=conformance_server, token=conformance_token)

    plan_id = client.create_test_plan(plan_name, config, variant)
    log.info("Plan ID: %s", plan_id)

    modules = client.get_plan_modules(plan_id)
    log.info("Plan has %d modules", len(modules))

    results = []
    any_failed = False

    for module in modules:
        module_name = module.get("testModule") or module.get("name", "unknown")
        log.info("Running module: %s", module_name)

        try:
            module_id = client.start_test_module(plan_id, module_name)
            info = client.wait_for_state(module_id, timeout=module_timeout)
            result = info.get("result", "UNKNOWN")
        except ConformanceError as e:
            log.error("Module %s error: %s", module_name, e)
            result = "FAILED"

        results.append({"name": module_name, "result": result})

        if result not in PASSING_RESULTS:
            any_failed = True
            log.error("%s: %s", result, module_name)
        else:
            log.info("%s: %s", result, module_name)

    try:
        client.export_html(plan_id, export_dir)
        client.export_results(plan_id, export_dir)
    except ConformanceError as e:
        log.warning("Failed to export results: %s", e)

    if publish and not any_failed:
        try:
            pkg = client.create_certification_package(plan_id)
            log.info("Certification package created: %s", pkg)
        except ConformanceError as e:
            log.warning("Failed to create certification package: %s", e)

    print_summary(results, plan_id, conformance_server)
    return not any_failed


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(description="Run OpenID conformance tests against Vouch")
    parser.add_argument(
        "--plan",
        required=True,
        help="Conformance suite plan name (e.g. oidcc-basic-certification-test-plan)",
    )
    parser.add_argument(
        "--config",
        required=True,
        type=Path,
        help="Path to plan config JSON template",
    )
    parser.add_argument(
        "--base-url",
        required=True,
        help="Public base URL of the Vouch server (e.g. https://xxx.trycloudflare.com)",
    )
    parser.add_argument(
        "--client-id",
        default=os.environ.get("VOUCH_CLIENT_ID", ""),
        help="OAuth client ID (or set VOUCH_CLIENT_ID env var)",
    )
    parser.add_argument(
        "--client-secret",
        default=os.environ.get("VOUCH_CLIENT_SECRET", ""),
        help="OAuth client secret (or set VOUCH_CLIENT_SECRET env var)",
    )
    parser.add_argument(
        "--client-jwks",
        default=os.environ.get("VOUCH_CLIENT_JWKS", ""),
        help="Client private JWKS JSON for private_key_jwt auth",
    )
    parser.add_argument(
        "--variant",
        default=None,
        help='Variant JSON (e.g. \'{"sender_constrained_access_tokens": "dpop"}\')',
    )
    parser.add_argument(
        "--export-dir",
        default=Path("/tmp/cert-results"),
        type=Path,
        help="Directory for exported test results (default: /tmp/cert-results)",
    )
    parser.add_argument(
        "--version",
        default=os.environ.get("VOUCH_VERSION", "dev"),
        help="Vouch version string for plan description (e.g. 1.2.0)",
    )
    parser.add_argument(
        "--publish",
        action="store_true",
        help="Create a formal certification package if all tests pass",
    )
    parser.add_argument(
        "--module-timeout",
        type=int,
        default=300,
        help="Seconds to wait for each module to complete (default: 300)",
    )
    args = parser.parse_args()

    conformance_server = os.environ.get(
        "CONFORMANCE_SERVER", "https://www.certification.openid.net/"
    ).rstrip("/")
    conformance_token = os.environ.get("CONFORMANCE_TOKEN", "")
    if not conformance_token:
        print("ERROR: CONFORMANCE_TOKEN environment variable is required", file=sys.stderr)
        sys.exit(1)

    config = load_config(
        args.config,
        args.base_url,
        args.client_id,
        args.client_secret,
        args.client_jwks,
        args.publish,
        version=args.version,
    )

    variant = json.loads(args.variant) if args.variant else None

    success = run_plan(
        plan_name=args.plan,
        config=config,
        variant=variant,
        export_dir=args.export_dir,
        publish=args.publish,
        conformance_server=conformance_server,
        conformance_token=conformance_token,
        module_timeout=args.module_timeout,
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
