#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""
Run an OpenID conformance test plan against a Vouch server.

Orchestrates the full certification workflow:
  1. Load config template and substitute placeholders
  2. Extract variant from config (passed separately to the API)
  3. Create a test plan
  4. Run each module sequentially, collecting results
  5. Export HTML report and ZIP archive
  6. Optionally create a formal certification package (--publish)
  7. Print a summary table; exit non-zero if any module is not in PASSING_RESULTS

Iteration helpers (work with .last-run.json saved after each run):
  --module NAME         Run only specific module(s)
  --rerun-failures      Rerun only failed modules from the last run
  --logs MODULE         Fetch and display logs for a module ID or name
  --verbose             Show all log entries, not just failures/HTTP

Usage:
    python3 run.py \\
        --plan oidcc-basic-certification-test-plan \\
        --config config/oidcc-basic.json \\
        --base-url https://xxx.trycloudflare.com \\
        [--publish]

    python3 run.py --rerun-failures \\
        --plan oidcc-basic-certification-test-plan \\
        --config config/oidcc-basic.json

    python3 run.py --logs <module-id-or-name>

Environment variables:
    CONFORMANCE_SERVER   Base URL of the conformance server (default: https://www.certification.openid.net/)
    CONFORMANCE_TOKEN    Bearer token for the conformance API
"""

import argparse
import concurrent.futures
import json
import logging
import os
import sys
from pathlib import Path

from conformance import ConformanceClient, ConformanceError, format_module_log

log = logging.getLogger(__name__)

# Result values that count as "passed enough" (WARNING is still OK for cert).
# Anything not in this set — including "FAILED" and "UNKNOWN" — is treated as
# a failure so that missing or unexpected result values never silently pass CI.
PASSING_RESULTS = {"PASSED", "WARNING", "REVIEW", "SKIPPED"}

STATE_FILE = Path(__file__).parent / ".last-run.json"


def load_config(
    config_path: Path,
    base_url: str,
    client_id: str,
    client_secret: str,
    client_jwks: str,
    publish: bool,
    version: str = "",
) -> tuple[dict, dict | None]:
    """Load config template, substitute placeholders, extract variant."""
    raw = config_path.read_text()
    # Placeholders embedded in JSON strings must be escaped as JSON string
    # fragments so special characters (", \, newlines, etc.) cannot break JSON.
    def json_escape_fragment(value: str) -> str:
        return json.dumps(value)[1:-1]

    client2_id = os.environ.get("CLIENT2_ID", "")
    client2_jwks = os.environ.get("CLIENT2_JWKS", "")
    substitutions = {
        "{BASEURL}": json_escape_fragment(base_url.rstrip("/")),
        "{CLIENT_ID}": json_escape_fragment(client_id),
        "{CLIENT_SECRET}": json_escape_fragment(client_secret),
        "{CLIENT_JWKS}": client_jwks or "null",
        "{CLIENT2_ID}": json_escape_fragment(client2_id),
        "{CLIENT2_JWKS}": client2_jwks or "null",
        "{VERSION}": json_escape_fragment(version or "dev"),
        "{CLIENT_REG_TOKEN}": json_escape_fragment(os.environ.get("CLIENT_REG_TOKEN", "")),
        "{CLIENT2_REG_TOKEN}": json_escape_fragment(os.environ.get("CLIENT2_REG_TOKEN", "")),
        "{MTLS_CERT}": json_escape_fragment(os.environ.get("MTLS_CERT", "")),
        "{MTLS_KEY}": json_escape_fragment(os.environ.get("MTLS_KEY", "")),
        "{MTLS2_CERT}": json_escape_fragment(os.environ.get("MTLS2_CERT", "")),
        "{MTLS2_KEY}": json_escape_fragment(os.environ.get("MTLS2_KEY", "")),
        "{TLS_CLIENT_AUTH_SUBJECT_DN}": json_escape_fragment(
            os.environ.get("TLS_CLIENT_AUTH_SUBJECT_DN", "")
        ),
        "{TLS_CLIENT_AUTH_SUBJECT_DN2}": json_escape_fragment(
            os.environ.get("TLS_CLIENT_AUTH_SUBJECT_DN2", "")
        ),
    }
    for placeholder, value in substitutions.items():
        raw = raw.replace(placeholder, value)
    config = json.loads(raw)
    if publish:
        config["publish"] = "everything"
    else:
        config.pop("publish", None)

    # Extract variant — this is our field, not part of the conformance
    # API config body. Rename client_alias -> alias (the conformance API
    # field name). When alias is set, redirect_uri uses /test/a/{alias}/callback
    # which matches the pre-registered redirect_uri.
    variant = config.pop("variant", None)
    client_alias = config.pop("client_alias", None)
    if client_alias and "alias" not in config:
        config["alias"] = client_alias

    return config, variant


def save_state(state: dict) -> None:
    """Save run state for reruns and log lookups."""
    STATE_FILE.write_text(json.dumps(state, indent=2) + "\n")


def load_state() -> dict:
    """Load last run state."""
    if not STATE_FILE.exists():
        print("No previous run state found (.last-run.json)", file=sys.stderr)
        sys.exit(1)
    return json.loads(STATE_FILE.read_text())


def dump_failure_log(
    client: ConformanceClient, module_name: str, module_id: str
) -> None:
    """Fetch and print the detailed log for a failed module."""
    print(f"\n{'─' * 70}")
    print(f"FAILURE LOG: {module_name}")
    print(f"Module ID:   {module_id}")
    print(f"{'─' * 70}")
    try:
        entries = client.get_module_log(module_id)
        output = format_module_log(entries)
        if output:
            print(output)
        else:
            print("  (no failure details in log)")
    except ConformanceError as e:
        print(f"  (could not fetch log: {e})")
    print(f"{'─' * 70}\n")


def print_summary(results: list[dict], plan_id: str, conformance_server: str) -> None:
    """Print a formatted summary table of module results."""
    width = 70
    print("\n" + "=" * width)
    print("OpenID Conformance Test Results")
    print("=" * width)

    counts: dict[str, int] = {}
    for r in results:
        result = r.get("result", "UNKNOWN")
        counts[result] = counts.get(result, 0) + 1
        if result in {"PASSED", "SKIPPED"}:
            cmd = "notice"
        elif result in {"WARNING", "REVIEW"}:
            cmd = "warning"
        else:
            cmd = "error"
        print(f"::{cmd}::{result:<8} {r['name']}")

    print("-" * width)
    print("  " + " | ".join(f"{v} {k}" for k, v in sorted(counts.items())))
    print("=" * width)
    print(f"\nUI:      {conformance_server}/plan-detail.html?plan={plan_id}")
    print(f"Plan ID: {plan_id}")

    failed = [r for r in results if r["result"] not in PASSING_RESULTS]
    if failed:
        print(f"\nTo rerun failures: python3 scripts/certification/run.py --rerun-failures"
              f" --plan <PLAN> --config <CONFIG>")
        print(f"To view logs:      python3 scripts/certification/run.py --logs <module-id>")
    print()


def run_plan(
    plan_name: str,
    config: dict,
    variant: dict | None,
    publish: bool,
    parallel: int,
    conformance_server: str,
    conformance_token: str,
    module_timeout: int,
    verify_ssl: bool = True,
    only_modules: list[str] | None = None,
) -> bool:
    """Run all modules in a test plan. Returns True if all passed."""
    client = ConformanceClient(
        server=conformance_server,
        token=conformance_token,
        verify_ssl=verify_ssl,
    )

    plan_id = client.create_test_plan(plan_name, config, variant)
    log.info("Plan ID: %s", plan_id)

    modules = client.get_plan_modules(plan_id)
    log.info("Plan has %d modules", len(modules))

    if only_modules:
        modules = [
            m for m in modules
            if (m.get("testModule") or m.get("name", "")) in only_modules
        ]
        if not modules:
            print(f"ERROR: none of {only_modules} found in plan", file=sys.stderr)
            return False
        log.info("Filtered to %d modules: %s", len(modules), only_modules)

    def run_module(module: dict) -> dict:
        module_name = module.get("testModule") or module.get("name", "unknown")
        log.info("Running module: %s", module_name)
        module_id = ""
        try:
            module_id = client.start_test_module(plan_id, module_name)
            info = client.wait_for_state(module_id, timeout=module_timeout)
            result = info.get("result", "UNKNOWN")
        except ConformanceError as e:
            log.error("Module %s error: %s", module_name, e)
            result = "FAILED"
        if result in PASSING_RESULTS:
            log.info("Module %s: %s", module_name, result)
        else:
            log.error("Module %s: %s", module_name, result)
        return {"name": module_name, "result": result, "module_id": module_id}

    with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as pool:
        results = list(pool.map(run_module, modules))

    # Save state for reruns and log lookups.
    state = {
        "plan_name": plan_name,
        "plan_id": plan_id,
        "conformance_server": conformance_server,
        "results": results,
    }
    save_state(state)

    # Dump detailed logs for failed modules.
    failed = [r for r in results if r["result"] not in PASSING_RESULTS]
    for r in failed:
        if r["module_id"]:
            dump_failure_log(client, r["name"], r["module_id"])

    any_failed = len(failed) > 0

    if publish and not any_failed:
        try:
            pkg = client.create_certification_package(plan_id)
            log.info("Certification package created: %s", pkg)
        except ConformanceError as e:
            log.warning("Failed to create certification package: %s", e)

    print_summary(results, plan_id, conformance_server)
    return not any_failed


def cmd_logs(args: argparse.Namespace, conformance_server: str, conformance_token: str) -> None:
    """Fetch and display logs for a module ID or name."""
    state = load_state()
    server = state.get("conformance_server", conformance_server)
    client = ConformanceClient(
        server=server,
        token=conformance_token,
        verify_ssl=args.verify_ssl,
    )

    module_id = args.logs
    # Allow looking up by module name from last run.
    for r in state.get("results", []):
        if r["name"] == module_id:
            module_id = r["module_id"]
            break

    try:
        entries = client.get_module_log(module_id)
    except ConformanceError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    output = format_module_log(entries, verbose=args.verbose)
    print(output)


def cmd_rerun_failures(
    args: argparse.Namespace, conformance_server: str, conformance_token: str
) -> None:
    """Rerun failed modules from the last run in a new plan."""
    state = load_state()
    failed = [
        r["name"]
        for r in state.get("results", [])
        if r["result"] not in PASSING_RESULTS
    ]
    if not failed:
        print("No failures in last run.")
        sys.exit(0)

    if args.module:
        failed = [m for m in failed if m in args.module]

    print(f"Rerunning {len(failed)} failed module(s): {', '.join(failed)}")

    if not args.config or not args.plan or not args.base_url:
        print(
            "ERROR: --config, --plan, and --base-url are required for --rerun-failures\n"
            f"  Last plan was: {state['plan_name']}",
            file=sys.stderr,
        )
        sys.exit(1)

    config, variant = load_config(
        args.config,
        args.base_url,
        args.client_id,
        args.client_secret,
        args.client_jwks,
        publish=False,
        version=args.version,
    )

    success = run_plan(
        plan_name=args.plan,
        config=config,
        variant=variant,
        publish=False,
        parallel=args.parallel,
        conformance_server=conformance_server,
        conformance_token=conformance_token,
        module_timeout=args.module_timeout,
        verify_ssl=args.verify_ssl,
        only_modules=failed,
    )
    sys.exit(0 if success else 1)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(description="Run OpenID conformance tests against Vouch")
    parser.add_argument(
        "--plan",
        help="Conformance suite plan name (e.g. oidcc-basic-certification-test-plan)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to plan config JSON (includes variant, client config, browser tasks)",
    )
    parser.add_argument(
        "--base-url",
        required=False,
        help="Public base URL of the Vouch server (e.g. https://xxx.trycloudflare.com)",
    )
    parser.add_argument(
        "--conformance-server",
        default=os.environ.get(
            "CONFORMANCE_SERVER", "https://www.certification.openid.net/"
        ).rstrip("/"),
        help="Conformance suite API URL (default: CONFORMANCE_SERVER env or certification.openid.net)",
    )
    parser.add_argument(
        "--client-id",
        default=os.environ.get("VOUCH_CLIENT_ID", os.environ.get("CLIENT_ID", "")),
        help="OAuth client ID (or set VOUCH_CLIENT_ID / CLIENT_ID env var)",
    )
    parser.add_argument(
        "--client-secret",
        default=os.environ.get("VOUCH_CLIENT_SECRET", os.environ.get("CLIENT_SECRET", "")),
        help="OAuth client secret (or set VOUCH_CLIENT_SECRET / CLIENT_SECRET env var)",
    )
    parser.add_argument(
        "--client-jwks",
        default=os.environ.get("VOUCH_CLIENT_JWKS", os.environ.get("CLIENT_JWKS", "")),
        help="Client private JWKS JSON for private_key_jwt auth",
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
        "--parallel",
        type=int,
        default=1,
        help="Number of modules to run in parallel (default: 1)",
    )
    parser.add_argument(
        "--module-timeout",
        type=int,
        default=300,
        help="Seconds to wait for each module to complete (default: 300)",
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification (for local self-signed certs)",
    )

    # Module filtering.
    parser.add_argument(
        "--module",
        action="append",
        help="Run only this module (can be repeated)",
    )

    # Iteration helpers.
    parser.add_argument(
        "--rerun-failures",
        action="store_true",
        help="Rerun only failed modules from the last run",
    )
    parser.add_argument(
        "--logs",
        metavar="MODULE_ID",
        help="Fetch and display logs for a module ID or name from last run",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show all log entries, not just failures/HTTP",
    )

    args = parser.parse_args()
    args.verify_ssl = not args.no_verify_ssl

    conformance_server = args.conformance_server
    conformance_token = os.environ.get("CONFORMANCE_TOKEN", "")

    # Dispatch to sub-commands.
    if args.logs:
        cmd_logs(args, conformance_server, conformance_token)
        return

    if args.rerun_failures:
        cmd_rerun_failures(args, conformance_server, conformance_token)
        return

    # Normal run requires --plan, --config, and --base-url.
    if not args.plan or not args.config:
        parser.error("--plan and --config are required")
    if not args.base_url:
        parser.error("--base-url is required")

    if not conformance_token and "certification.openid.net" in conformance_server:
        print("ERROR: CONFORMANCE_TOKEN environment variable is required", file=sys.stderr)
        sys.exit(1)

    config, variant = load_config(
        args.config,
        args.base_url,
        args.client_id,
        args.client_secret,
        args.client_jwks,
        args.publish,
        version=args.version,
    )

    success = run_plan(
        plan_name=args.plan,
        config=config,
        variant=variant,
        publish=args.publish,
        parallel=args.parallel,
        conformance_server=conformance_server,
        conformance_token=conformance_token,
        module_timeout=args.module_timeout,
        verify_ssl=args.verify_ssl,
        only_modules=args.module,
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
