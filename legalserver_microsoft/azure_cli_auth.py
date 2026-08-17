import json
import shutil
import subprocess  # nosec
from dataclasses import dataclass
from typing import Any

AZURE_CLI_INSTALL_GUIDANCE = "Install Azure CLI and ensure the 'az' command is available on PATH before running Azure-backed workflows."


@dataclass
class AzureCliContext:
    """Normalized details about the current Azure CLI login context."""

    username: str
    tenant_id: str
    tenant_name: str
    subscription_id: str
    subscription_name: str
    environment_name: str


@dataclass
class AzureCliInspectionResult:
    """Structured result for Azure CLI session inspection."""

    success: bool
    context: AzureCliContext | None = None
    error: str | None = None


@dataclass
class AzureCliLoginResult:
    """Structured result for an Azure CLI login attempt."""

    success: bool
    error: str | None = None


def _normalize_string(value: Any) -> str:
    """Return a stable operator-facing string for optional Azure CLI fields."""
    if isinstance(value, str):
        normalized = value.strip()
        return normalized or "Unknown"
    return "Unknown"


def _build_azure_cli_not_found_error() -> str:
    """Return actionable guidance when Azure CLI is not installed or not on PATH."""
    return f"Azure CLI was not found on PATH. {AZURE_CLI_INSTALL_GUIDANCE}"


def _format_subprocess_details(*, exc: subprocess.CalledProcessError) -> str:
    """Return the most useful available subprocess failure details."""
    stderr = exc.stderr.strip() if isinstance(exc.stderr, str) else ""
    stdout = exc.stdout.strip() if isinstance(exc.stdout, str) else ""
    return stderr or stdout or str(exc)


def _build_account_inspection_failure(*, details: str) -> str:
    """Return an actionable account inspection error message."""
    normalized_details = details.lower()
    if (
        "az login" in normalized_details
        or "please run 'az login'" in normalized_details
    ):
        return (
            "Azure CLI account inspection failed because no active Azure login was found. "
            "Run 'az login' or allow the workflow to launch it for you."
        )
    return f"Azure CLI account inspection failed: {details}"


def _build_login_failure(*, details: str) -> str:
    """Return an actionable Azure CLI login failure message."""
    return (
        "Azure CLI login failed. Complete the Azure sign-in flow in the opened Azure CLI prompt or rerun 'az login' manually. "
        f"Details: {details}"
    )


def inspect_azure_cli_session() -> AzureCliInspectionResult:
    """Inspect the current Azure CLI account context and return normalized data."""
    azure_cli_path = shutil.which("az")
    if azure_cli_path is None:
        return AzureCliInspectionResult(
            success=False,
            error=_build_azure_cli_not_found_error(),
        )

    try:
        completed_process = subprocess.run(  # nosec
            [azure_cli_path, "account", "show", "--output", "json"],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        details = _format_subprocess_details(exc=exc)
        return AzureCliInspectionResult(
            success=False,
            error=_build_account_inspection_failure(details=details),
        )
    except OSError as exc:
        return AzureCliInspectionResult(
            success=False,
            error=f"Azure CLI account inspection failed: Unable to launch 'az account show': {exc}",
        )

    try:
        payload = json.loads(completed_process.stdout)
    except json.JSONDecodeError as exc:
        return AzureCliInspectionResult(
            success=False,
            error=f"Azure CLI account inspection returned invalid JSON: {exc}",
        )

    if not isinstance(payload, dict):
        return AzureCliInspectionResult(
            success=False,
            error=(
                "Azure CLI account inspection returned a non-object JSON payload. "
                "The current Azure CLI output could not be interpreted."
            ),
        )

    user_payload = payload.get("user")
    username = "Unknown"
    if isinstance(user_payload, dict):
        username = _normalize_string(user_payload.get("name"))

    context = AzureCliContext(
        username=username,
        tenant_id=_normalize_string(payload.get("tenantId")),
        tenant_name=_normalize_string(payload.get("tenantDisplayName")),
        subscription_id=_normalize_string(payload.get("id")),
        subscription_name=_normalize_string(payload.get("name")),
        environment_name=_normalize_string(payload.get("environmentName")),
    )
    return AzureCliInspectionResult(success=True, context=context)


def run_azure_cli_login() -> AzureCliLoginResult:
    """Launch Azure CLI interactive login and return a structured result."""
    azure_cli_path = shutil.which("az")
    if azure_cli_path is None:
        return AzureCliLoginResult(
            success=False,
            error=_build_azure_cli_not_found_error(),
        )

    try:
        subprocess.run(  # nosec
            [azure_cli_path, "login"],
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        details = _format_subprocess_details(exc=exc)
        return AzureCliLoginResult(
            success=False,
            error=_build_login_failure(details=details),
        )
    except OSError as exc:
        return AzureCliLoginResult(
            success=False,
            error=f"Azure CLI login failed: Unable to launch 'az login': {exc}",
        )

    inspection_result = inspect_azure_cli_session()
    if not inspection_result.success:
        return AzureCliLoginResult(
            success=False,
            error=(
                "Azure CLI login completed, but the resulting account context could not be validated: "
                f"{inspection_result.error}"
            ),
        )

    return AzureCliLoginResult(success=True)
