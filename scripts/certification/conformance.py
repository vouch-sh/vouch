#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""
API client for the OpenID Foundation conformance suite.

Usage:
    from conformance import ConformanceClient
    client = ConformanceClient()
    plan_id = client.create_test_plan("oidcc-basic-certification-test-plan", config)
    modules = client.get_plan_modules(plan_id)
    ...
"""

import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Default conformance server URL
CONFORMANCE_SERVER = os.environ.get(
    "CONFORMANCE_SERVER", "https://www.certification.openid.net/"
).rstrip("/")

# Bearer token for the conformance API (required)
CONFORMANCE_TOKEN = os.environ.get("CONFORMANCE_TOKEN", "")

# How often to poll for test module state changes (seconds)
POLL_INTERVAL = 2.0

# Maximum time to wait for a test module to complete (seconds)
DEFAULT_TIMEOUT = 300


class ConformanceError(Exception):
    """Raised when the conformance API returns an unexpected response."""


class ConformanceClient:
    """HTTP client for certification.openid.net."""

    def __init__(
        self,
        server: str = CONFORMANCE_SERVER,
        token: str = CONFORMANCE_TOKEN,
    ) -> None:
        self.server = server.rstrip("/")
        self.token = token

    def _get(self, path: str, params: dict | None = None) -> Any:
        return json.loads(self._get_bytes(path, params=params))

    def _get_bytes(self, path: str, params: dict | None = None) -> bytes:
        url = f"{self.server}{path}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.token}"})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            raise ConformanceError(
                f"GET {path} failed: HTTP {e.code}: {e.read().decode()}"
            ) from e

    def _post(self, path: str, params: dict | None = None, body: Any = None) -> Any:
        url = f"{self.server}{path}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        headers: dict[str, str] = {"Authorization": f"Bearer {self.token}"}
        data: bytes | None = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise ConformanceError(
                f"POST {path} failed: HTTP {e.code}: {e.read().decode()}"
            ) from e

    # ── Plan management ──────────────────────────────────────────────────────

    def create_test_plan(
        self,
        plan_name: str,
        config: dict[str, Any],
        variant: dict[str, str] | None = None,
    ) -> str:
        """Create a new test plan and return its ID."""
        params: dict = {"planName": plan_name}
        if variant:
            params["variant"] = json.dumps(variant)
        log.info("Creating test plan %s", plan_name)
        data = self._post("/api/plan", params=params, body=config)
        plan_id = data.get("id") or data.get("plan", {}).get("id")
        if not plan_id:
            raise ConformanceError(f"No plan ID in create response: {data}")
        log.info("Created plan %s with ID %s", plan_name, plan_id)
        return plan_id

    def get_test_plan(self, plan_id: str) -> dict[str, Any]:
        """Fetch plan details including the list of test modules."""
        return self._get(f"/api/plan/{plan_id}")

    def get_plan_modules(self, plan_id: str) -> list[dict[str, Any]]:
        """Return the list of test module descriptors for a plan."""
        plan = self.get_test_plan(plan_id)
        modules = plan.get("modules", [])
        if not modules:
            raise ConformanceError(f"Plan {plan_id} has no modules")
        return modules

    # ── Module execution ─────────────────────────────────────────────────────

    def start_test_module(self, plan_id: str, module_name: str) -> str:
        """Start a test module and return the module instance ID."""
        log.info("Starting module %s in plan %s", module_name, plan_id)
        data = self._post("/api/runner", params={"plan": plan_id, "test": module_name})
        module_id = data.get("id")
        if not module_id:
            raise ConformanceError(f"No module ID in start response: {data}")
        log.info("Started module %s with ID %s", module_name, module_id)
        return module_id

    def get_module_info(self, module_id: str) -> dict[str, Any]:
        """Fetch module instance status and results."""
        return self._get(f"/api/info/{module_id}")

    def wait_for_state(
        self,
        module_id: str,
        terminal_states: set[str] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> dict[str, Any]:
        """Poll module info until it reaches a terminal state.

        Raises:
            ConformanceError: If timeout is exceeded.
        """
        if terminal_states is None:
            # FINISHED = test completed normally
            # INTERRUPTED = test was interrupted (counts as done)
            # FAILED = test framework error (distinct from FAILED test result)
            # Note: WAITING means the suite is waiting for browser interaction;
            # we do NOT treat it as terminal since our browser task handles it.
            terminal_states = {"FINISHED", "INTERRUPTED", "FAILED"}

        deadline = time.monotonic() + timeout
        while True:
            info = self.get_module_info(module_id)
            status = info.get("status", "")
            log.debug("Module %s status: %s", module_id, status)

            if status in terminal_states:
                return info

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ConformanceError(
                    f"Module {module_id} did not complete within {timeout}s "
                    f"(last status: {status})"
                )

            time.sleep(min(POLL_INTERVAL, remaining))

    # ── Module logs ─────────────────────────────────────────────────────────

    def get_module_log(self, module_id: str) -> list[dict[str, Any]]:
        """Fetch the full structured log for a test module."""
        return self._get(f"/api/log/{module_id}")

    # ── Certification ────────────────────────────────────────────────────────

    def create_certification_package(self, plan_id: str) -> dict[str, Any]:
        """Generate an official certification package for a passing plan."""
        log.info("Creating certification package for plan %s", plan_id)
        return self._post(f"/api/plan/{plan_id}/certificationpackage")


def format_log_entry(entry: dict) -> str | None:
    """Format a single log entry for debugging output.

    Returns None for entries that aren't useful for debugging
    (e.g. INFO-level successes).
    """
    result = entry.get("result", "")
    src = entry.get("src", "")
    msg = entry.get("msg", "")

    # Skip noise: only show failures, warnings, and HTTP exchanges.
    if result in ("SUCCESS", "INFO", "") and "http" not in entry:
        return None

    lines = []

    # Header line with result and source condition.
    if result and result not in ("SUCCESS", "INFO"):
        lines.append(f"[{result}] {src}: {msg}")
    elif "http" in entry:
        lines.append(f"[HTTP] {src}: {msg}")
    else:
        return None

    # RFC requirements.
    reqs = entry.get("requirements", [])
    if reqs:
        lines.append(f"  requirements: {', '.join(reqs)}")

    # HTTP request/response details.
    http = entry.get("http", "")
    if isinstance(http, str) and http:
        lines.append(f"  http: {http}")
    elif isinstance(http, dict):
        req = http.get("request", {})
        resp = http.get("response", {})
        if req:
            method = req.get("method", "?")
            url = req.get("url", "?")
            lines.append(f"  request: {method} {url}")
            body = req.get("body", "")
            if body:
                lines.append(f"    body: {body}")
        if resp:
            status = resp.get("status", "?")
            lines.append(f"  response: HTTP {status}")
            body = resp.get("body", "")
            if body:
                lines.append(f"    body: {body}")

    # Upload/endpoint data that might be useful.
    for key in ("upload", "endpoint", "actual", "expected"):
        val = entry.get(key)
        if val is not None:
            if isinstance(val, (dict, list)):
                lines.append(f"  {key}: {json.dumps(val, indent=2)}")
            else:
                lines.append(f"  {key}: {val}")

    return "\n".join(lines)


def format_module_log(entries: list[dict]) -> str:
    """Format a module's log entries for debugging.

    Shows only failures, warnings, and HTTP exchanges.
    """
    lines = []
    for entry in entries:
        formatted = format_log_entry(entry)
        if formatted:
            lines.append(formatted)
    return "\n".join(lines)
