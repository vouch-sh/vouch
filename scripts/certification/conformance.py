#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""
Async API client for the OpenID Foundation conformance suite.

Adapted from the upstream conformance-suite Python client at:
https://gitlab.com/openid/conformance-suite/-/blob/master/scripts/conformance.py

Usage:
    from conformance import ConformanceClient
    async with ConformanceClient() as client:
        plan_id = await client.create_test_plan("oidcc-basic-certification-test-plan", config)
        modules = await client.get_test_plan(plan_id)
        ...
"""

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any

import aiohttp

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
    """Async HTTP client for certification.openid.net."""

    def __init__(
        self,
        server: str = CONFORMANCE_SERVER,
        token: str = CONFORMANCE_TOKEN,
    ) -> None:
        self.server = server.rstrip("/")
        self.token = token
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "ConformanceClient":
        headers = {"Authorization": f"Bearer {self.token}"}
        self._session = aiohttp.ClientSession(headers=headers)
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._session:
            await self._session.close()

    @property
    def session(self) -> aiohttp.ClientSession:
        if self._session is None:
            raise RuntimeError("ConformanceClient must be used as an async context manager")
        return self._session

    # ── Plan management ──────────────────────────────────────────────────────

    async def create_test_plan(
        self,
        plan_name: str,
        config: dict[str, Any],
        variant: dict[str, str] | None = None,
    ) -> str:
        """Create a new test plan and return its ID.

        Args:
            plan_name: Conformance suite plan name (e.g. "oidcc-basic-certification-test-plan").
            config: Plan configuration JSON object.
            variant: Optional variant parameters (e.g. {"sender_constrained_access_tokens": "dpop"}).

        Returns:
            The plan ID string.
        """
        params = {"planName": plan_name}
        if variant:
            # Variant params are passed as separate query parameters
            for k, v in variant.items():
                params[k] = v

        url = f"{self.server}/api/plan"
        log.info("Creating test plan %s", plan_name)

        async with self.session.post(url, params=params, json=config) as resp:
            if resp.status not in (200, 201):
                text = await resp.text()
                raise ConformanceError(
                    f"Failed to create plan {plan_name}: HTTP {resp.status}: {text}"
                )
            data = await resp.json()

        plan_id = data.get("id") or data.get("plan", {}).get("id")
        if not plan_id:
            raise ConformanceError(f"No plan ID in create response: {data}")

        log.info("Created plan %s with ID %s", plan_name, plan_id)
        return plan_id

    async def get_test_plan(self, plan_id: str) -> dict[str, Any]:
        """Fetch plan details including the list of test modules."""
        url = f"{self.server}/api/plan/{plan_id}"
        async with self.session.get(url) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise ConformanceError(f"Failed to get plan {plan_id}: HTTP {resp.status}: {text}")
            return await resp.json()

    async def get_plan_modules(self, plan_id: str) -> list[dict[str, Any]]:
        """Return the list of test module descriptors for a plan."""
        plan = await self.get_test_plan(plan_id)
        modules = plan.get("modules", [])
        if not modules:
            raise ConformanceError(f"Plan {plan_id} has no modules")
        return modules

    # ── Module execution ─────────────────────────────────────────────────────

    async def start_test_module(self, plan_id: str, module_name: str) -> str:
        """Start a test module and return the module instance ID."""
        url = f"{self.server}/api/runner"
        params = {"planId": plan_id, "test": module_name}

        log.info("Starting module %s in plan %s", module_name, plan_id)

        async with self.session.post(url, params=params) as resp:
            if resp.status not in (200, 201):
                text = await resp.text()
                raise ConformanceError(
                    f"Failed to start module {module_name}: HTTP {resp.status}: {text}"
                )
            data = await resp.json()

        module_id = data.get("id")
        if not module_id:
            raise ConformanceError(f"No module ID in start response: {data}")

        log.info("Started module %s with ID %s", module_name, module_id)
        return module_id

    async def get_module_info(self, module_id: str) -> dict[str, Any]:
        """Fetch module instance status and results."""
        url = f"{self.server}/api/info/{module_id}"
        async with self.session.get(url) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise ConformanceError(
                    f"Failed to get module {module_id}: HTTP {resp.status}: {text}"
                )
            return await resp.json()

    async def wait_for_state(
        self,
        module_id: str,
        terminal_states: set[str] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> dict[str, Any]:
        """Poll module info until it reaches a terminal state.

        Args:
            module_id: Module instance ID.
            terminal_states: Set of status strings that indicate completion.
                Defaults to {"FINISHED", "INTERRUPTED", "FAILED"}.
            timeout: Maximum seconds to wait.

        Returns:
            Final module info dict.

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
            info = await self.get_module_info(module_id)
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

            await asyncio.sleep(min(POLL_INTERVAL, remaining))

    # ── Results and export ───────────────────────────────────────────────────

    async def get_module_result(self, module_id: str) -> str:
        """Return the overall result string of a finished module.

        Typical values: "PASSED", "FAILED", "WARNING", "REVIEW", "SKIPPED".
        """
        info = await self.get_module_info(module_id)
        return info.get("result", "UNKNOWN")

    async def export_results(self, plan_id: str, output_dir: Path) -> Path:
        """Download the ZIP export of test results for a plan.

        Args:
            plan_id: The plan ID.
            output_dir: Directory to write the results ZIP.

        Returns:
            Path to the downloaded ZIP file.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        url = f"{self.server}/api/plan/{plan_id}/export"
        zip_path = output_dir / f"plan-{plan_id}.zip"

        log.info("Exporting results for plan %s to %s", plan_id, zip_path)
        async with self.session.get(url) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise ConformanceError(
                    f"Failed to export plan {plan_id}: HTTP {resp.status}: {text}"
                )
            zip_path.write_bytes(await resp.read())

        log.info("Results exported to %s", zip_path)
        return zip_path

    async def export_html(self, plan_id: str, output_dir: Path) -> Path:
        """Download the HTML report for a plan.

        Args:
            plan_id: The plan ID.
            output_dir: Directory to write the HTML report.

        Returns:
            Path to the downloaded HTML file.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        url = f"{self.server}/api/plan/exporthtml/{plan_id}"
        html_path = output_dir / f"plan-{plan_id}.html"

        log.info("Exporting HTML report for plan %s", plan_id)
        async with self.session.get(url) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise ConformanceError(
                    f"Failed to export HTML for plan {plan_id}: HTTP {resp.status}: {text}"
                )
            html_path.write_bytes(await resp.read())

        log.info("HTML report exported to %s", html_path)
        return html_path

    async def create_certification_package(self, plan_id: str) -> dict[str, Any]:
        """Generate an official certification package for a passing plan.

        This is the API call that initiates the formal certification submission
        process at certification.openid.net.

        Args:
            plan_id: The plan ID (must have all modules PASSED).

        Returns:
            API response dict.
        """
        url = f"{self.server}/api/plan/{plan_id}/certificationpackage"
        log.info("Creating certification package for plan %s", plan_id)

        async with self.session.post(url) as resp:
            if resp.status not in (200, 201):
                text = await resp.text()
                raise ConformanceError(
                    f"Failed to create certification package for {plan_id}: "
                    f"HTTP {resp.status}: {text}"
                )
            return await resp.json()
