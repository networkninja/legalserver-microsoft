import os
import sys
from argparse import ArgumentParser, Namespace
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path
from typing import Any, Callable, Optional, TextIO, Tuple

questionary: Any
try:
    import questionary as _questionary
except ImportError:  # pragma: no cover - fallback for minimal environments
    questionary = None
else:
    questionary = _questionary

Console: Any
Panel: Any
try:
    from rich.console import Console as _Console
    from rich.panel import Panel as _Panel
except ImportError:  # pragma: no cover - fallback for minimal environments
    Console = None
    Panel = None
else:
    Console = _Console
    Panel = _Panel

from legalserver_microsoft.models import (
    ExistingSsoInstallRequest,
    ExistingInstallRequest,
    FullInstallRequest,
    ManualCertificateRequest,
    SelectedSitesHelperAppConfig,
    SsoInstallRequest,
)
from legalserver_microsoft.utils import (
    CertificateValidityPolicy,
    build_certificate_expiration,
    convert_sharepoint_url,
    generate_random_password,
    get_max_valid_years,
    is_valid_sharepoint_site_url,
    is_valid_sharepoint_url,
    normalize_sharepoint_site_url,
    validate_password_complexity,
)


@dataclass(frozen=True)
class InteractivePrompts:
    """Represents injectable prompt functions for the interactive CLI flow."""

    text_prompt: Callable[[str], str]
    secret_prompt: Callable[[str], str]


def render_welcome(*, output: TextIO) -> None:
    """Render the CLI welcome message with rich when available."""
    if Console is not None and Panel is not None and output is sys.stdout:
        console = Console()
        console.print(
            Panel.fit(
                "LegalServer / Microsoft Integration Tools\n\n"
                "Use this tool for SharePoint integration setup, certificate rotation, "
                "and Site SSO app registration setup.",
                title="LegalServer / Microsoft Integration Tools",
            )
        )
        return

    print("LegalServer / Microsoft Integration Tools", file=output)
    print(
        "Use this tool for SharePoint integration setup, certificate rotation, and Site SSO app registration setup.",
        file=output,
    )


@dataclass(frozen=True)
class InteractiveRequestBuildResult:
    """Represents the built request plus prompt-time metadata."""

    request: ManualCertificateRequest
    generated_password: bool


@dataclass(frozen=True)
class ExistingInstallBuildResult:
    """Represents the built request for updating an existing installation."""

    request: ExistingInstallRequest
    generated_password: bool
    dry_run: bool


@dataclass(frozen=True)
class ExistingSsoInstallBuildResult:
    """Represents the built request for updating an existing Site SSO installation."""

    request: ExistingSsoInstallRequest
    generated_password: bool
    dry_run: bool


@dataclass(frozen=True)
class FullInstallBuildResult:
    """Represents the built request for a full install."""

    request: FullInstallRequest
    generated_password: bool
    dry_run: bool


@dataclass(frozen=True)
class SsoInstallBuildResult:
    """Represents the built request for an SSO install."""

    request: SsoInstallRequest
    generated_password: bool
    dry_run: bool


def _prompt_non_empty(*, prompt_text: str, prompts: InteractivePrompts) -> str:
    """Prompt until the user provides a non-empty response."""
    while True:
        value = prompts.text_prompt(prompt_text).strip()
        if value:
            return value
        print("A value is required. Please try again.")


def _prompt_yes_no(
    *,
    prompt_text: str,
    prompts: InteractivePrompts,
    default: bool,
) -> bool:
    """Prompt for a yes or no answer with a default option."""
    default_label = "Y/n" if default else "y/N"
    while True:
        if questionary is not None and prompts.text_prompt is input:
            result = questionary.confirm(prompt_text, default=default).ask()
            if result is None:
                raise KeyboardInterrupt
            if not isinstance(result, bool):
                raise RuntimeError(
                    "Questionary returned a non-boolean confirmation result."
                )
            return result
        response = (
            prompts.text_prompt(f"{prompt_text} [{default_label}]: ").strip().lower()
        )
        if not response:
            return default
        if response in {"y", "yes"}:
            return True
        if response in {"n", "no"}:
            return False
        print("Please answer yes or no.")


def _prompt_int(
    *,
    prompt_text: str,
    prompts: InteractivePrompts,
    minimum: int = 1,
) -> int:
    """Prompt until the user provides an integer greater than or equal to minimum."""
    while True:
        response = prompts.text_prompt(prompt_text).strip()
        try:
            value = int(response)
        except ValueError:
            print("Please enter a whole number.")
            continue
        if value < minimum:
            print(f"Please enter a number greater than or equal to {minimum}.")
            continue
        return value


def _prompt_password(*, prompts: InteractivePrompts) -> str:
    """Prompt for a user-provided password with validation and confirmation."""
    while True:
        if questionary is not None and prompts.secret_prompt is getpass:
            password = questionary.password("Enter certificate password").ask()
            if password is None:
                raise KeyboardInterrupt
            if not isinstance(password, str):
                raise RuntimeError("Questionary returned a non-string password value.")
        else:
            password = prompts.secret_prompt("Enter certificate password: ")
        if not validate_password_complexity(password):
            print(
                "Password must be at least 12 characters and include uppercase, "
                "lowercase, number, and special character."
            )
            continue
        if questionary is not None and prompts.secret_prompt is getpass:
            confirm_password = questionary.password(
                "Confirm certificate password"
            ).ask()
            if confirm_password is None:
                raise KeyboardInterrupt
            if not isinstance(confirm_password, str):
                raise RuntimeError(
                    "Questionary returned a non-string password confirmation value."
                )
        else:
            confirm_password = prompts.secret_prompt("Confirm certificate password: ")
        if password != confirm_password:
            print("Passwords do not match. Please try again.")
            continue
        return password


def _collect_password(*, prompts: InteractivePrompts) -> Tuple[str, bool]:
    """Collect a password and indicate whether the tool generated it."""
    use_custom_password = _prompt_yes_no(
        prompt_text="Do you want to create your own certificate password?",
        prompts=prompts,
        default=False,
    )
    if not use_custom_password:
        password = generate_random_password()
        print("A secure password was generated for you.")
        return password, True
    return _prompt_password(prompts=prompts), False


def _resolve_text_value(
    *,
    provided_value: Optional[str],
    prompt_text: str,
    prompts: InteractivePrompts,
) -> str:
    """Use a provided text value or fall back to an interactive prompt."""
    if provided_value is not None and provided_value.strip():
        return provided_value.strip()
    return _prompt_non_empty(prompt_text=prompt_text, prompts=prompts)


def _resolve_years_value(
    *,
    provided_value: Optional[int],
    prompts: InteractivePrompts,
) -> int:
    """Use a provided year value or fall back to an interactive prompt."""
    if provided_value is not None:
        if provided_value < 1:
            raise ValueError("Certificate validity years must be greater than zero.")
        return provided_value
    return _prompt_int(
        prompt_text="How many years should the certificate be valid for? ",
        prompts=prompts,
        minimum=1,
    )


def _resolve_output_dir(
    *,
    provided_value: Optional[Path],
    default_dir: Path,
    prompts: InteractivePrompts,
) -> Path:
    """Use a provided output directory or fall back to the default location."""
    if provided_value is not None:
        return provided_value
    del prompts
    return default_dir


def _resolve_password(
    *,
    provided_password: Optional[str],
    generate_password: bool,
    prompts: InteractivePrompts,
) -> Tuple[str, bool]:
    """Use a provided password, generate one, or prompt interactively.

    Resolution order:
    1. ``--generate-password`` flag — generate a random password.
    2. ``--password`` CLI flag (``provided_password`` argument).
    3. ``LS_CERT_PASSWORD`` environment variable — lower-exposure alternative
       to the CLI flag; the value is not visible in the process listing.
    4. Interactive prompt.
    """
    if generate_password:
        password = generate_random_password()
        return password, True
    if provided_password is not None:
        if not validate_password_complexity(provided_password):
            raise ValueError("Provided password does not meet complexity requirements.")
        return provided_password, False
    env_password = os.environ.get("LS_CERT_PASSWORD")
    if env_password is not None:
        if not validate_password_complexity(env_password):
            raise ValueError(
                "Password supplied via LS_CERT_PASSWORD does not meet complexity requirements."
            )
        return env_password, False
    return _collect_password(prompts=prompts)


def _resolve_dry_run(*, prompts: InteractivePrompts, provided_value: bool) -> bool:
    """Resolve whether the workflow should run in dry-run mode."""
    return provided_value


def _prompt_sharepoint_site_url(*, prompts: InteractivePrompts) -> str:
    """Prompt until the user provides a valid SharePoint site/library URL."""
    while True:
        sharepoint_site_url = _prompt_non_empty(
            prompt_text=(
                "SharePoint default site/library URL "
                "(example: https://tenant.sharepoint.com/sites/site/Shared%20Documents/Forms/AllItems.aspx): "
            ),
            prompts=prompts,
        )
        if not is_valid_sharepoint_url(sharepoint_site_url):
            print(
                "Please enter a valid SharePoint library URL ending in /Forms/AllItems.aspx."
            )
            continue
        convert_sharepoint_url(sharepoint_site_url)
        return sharepoint_site_url


def _prompt_sharepoint_access_mode(
    *, prompts: InteractivePrompts, output: TextIO
) -> str:
    """Prompt for broad or selected-sites SharePoint access mode."""
    print("Choose SharePoint access model:", file=output)
    print("1. Broad access across the tenant", file=output)
    print("2. Selected SharePoint sites only", file=output)
    while True:
        response = prompts.text_prompt("Choose 1 or 2 [1]: ").strip().lower()
        if response in {"", "1", "broad"}:
            return "broad"
        if response in {"2", "selected-sites", "sites.selected"}:
            return "selected-sites"
        print("Please enter 1 or 2.", file=output)


def _prompt_selected_sharepoint_site_urls(
    *,
    prompts: InteractivePrompts,
    output: TextIO,
    allow_empty: bool,
) -> list[str]:
    """Collect selected SharePoint site URLs for selected-sites mode."""
    selected_site_urls: list[str] = []
    prompt_text = (
        "Selected SharePoint site URL "
        "(example: https://tenant.sharepoint.com/sites/hr)"
    )

    while True:
        suffix = (
            " [press Enter when finished]" if selected_site_urls or allow_empty else ""
        )
        response = prompts.text_prompt(f"{prompt_text}{suffix}: ").strip()
        if not response:
            if selected_site_urls or allow_empty:
                return selected_site_urls
            print("At least one SharePoint site URL is required.", file=output)
            continue
        if not is_valid_sharepoint_site_url(response):
            print(
                "Please enter a valid SharePoint site URL such as https://tenant.sharepoint.com/sites/hr.",
                file=output,
            )
            continue
        normalized_url = normalize_sharepoint_site_url(response)
        if normalized_url not in selected_site_urls:
            selected_site_urls.append(normalized_url)


def _prompt_selected_sites_helper_app_config(
    *, prompts: InteractivePrompts, output: TextIO
) -> SelectedSitesHelperAppConfig:
    """Collect helper-app setup details for selected-sites grant automation."""
    print(
        "Selected-sites grant automation requires a helper Azure application.",
        file=output,
    )
    print(
        "The helper app uses Microsoft Graph Sites.FullControl.All application permission for this workflow.",
        file=output,
    )
    print(
        "Treat helper-app credentials as high-privilege tenant credentials and retain them only when reuse is necessary.",
        file=output,
    )
    create_new_helper_app = _prompt_yes_no(
        prompt_text="Create a new helper app inside this workflow?",
        prompts=prompts,
        default=True,
    )
    if create_new_helper_app:
        return SelectedSitesHelperAppConfig(
            create_new_helper_app=True,
            tenant_id="",
            authentication_method="generated-certificate",
            generate_helper_certificate_automatically=True,
        )

    existing_helper_app_client_id = ""
    existing_helper_app_client_id = _prompt_non_empty(
        prompt_text="Existing helper app client ID: ",
        prompts=prompts,
    )
    helper_certificate_thumbprint = _prompt_non_empty(
        prompt_text="Helper certificate thumbprint: ",
        prompts=prompts,
    )
    helper_certificate_file_path = _prompt_non_empty(
        prompt_text="Helper certificate PFX file path: ",
        prompts=prompts,
    )
    print(
        "Reused helper-app ownership, certificate rotation, and cleanup remain your responsibility.",
        file=output,
    )
    return SelectedSitesHelperAppConfig(
        create_new_helper_app=False,
        tenant_id="",
        authentication_method="file-path",
        existing_helper_app_client_id=existing_helper_app_client_id,
        helper_certificate_thumbprint=helper_certificate_thumbprint,
        helper_certificate_file_path=helper_certificate_file_path,
    )


def build_interactive_request(
    *,
    prompts: InteractivePrompts,
    output: TextIO,
    default_output_dir: Optional[Path] = None,
    validity_policy: CertificateValidityPolicy = CertificateValidityPolicy(),
    provided_site: Optional[str] = None,
    provided_years: Optional[int] = None,
    provided_output_dir: Optional[Path] = None,
    provided_password: Optional[str] = None,
    generate_password: bool = False,
) -> InteractiveRequestBuildResult:
    """Build a manual certificate request through an operator-friendly prompt flow."""
    default_dir = default_output_dir or Path.cwd()

    ls_site = _resolve_text_value(
        provided_value=provided_site,
        prompt_text="LegalServer site abbreviation (example: example-demo): ",
        prompts=prompts,
    )

    max_valid_years = get_max_valid_years(validity_policy)
    print(
        f"Tenant validity limit: {validity_policy.max_days} days (~{max_valid_years} years).",
        file=output,
    )
    valid_years = _resolve_years_value(
        provided_value=provided_years,
        prompts=prompts,
    )

    while True:
        try:
            build_certificate_expiration(
                valid_years=valid_years,
                validity_policy=validity_policy,
            )
            break
        except ValueError as exc:
            print(str(exc), file=output)
            valid_years = _prompt_int(
                prompt_text="Enter a smaller number of years: ",
                prompts=prompts,
                minimum=1,
            )

    output_dir = _resolve_output_dir(
        provided_value=provided_output_dir,
        default_dir=default_dir,
        prompts=prompts,
    )

    password, generated_password = _resolve_password(
        provided_password=provided_password,
        generate_password=generate_password,
        prompts=prompts,
    )

    return InteractiveRequestBuildResult(
        request=ManualCertificateRequest(
            ls_site=ls_site,
            valid_years=valid_years,
            password=password,
            output_dir=output_dir,
            validity_policy=validity_policy,
        ),
        generated_password=generated_password,
    )


def prompt_mode_selection(*, prompts: InteractivePrompts, output: TextIO) -> str:
    """Prompt the operator to choose the workflow mode."""
    if questionary is not None and prompts.text_prompt is input:
        result = questionary.select(
            "Choose an integration workflow:",
            choices=[
                questionary.Choice(
                    "Generate certificates only",
                    value="certificate-only",
                ),
                questionary.Choice(
                    "SharePoint: Update existing SharePoint apps",
                    value="update-existing-sharepoint",
                ),
                questionary.Choice(
                    "SSO: Update existing SSO app",
                    value="update-existing-sso",
                ),
                questionary.Choice(
                    "SharePoint: Perform a full SharePoint install",
                    value="full-sharepoint-install",
                ),
                questionary.Choice(
                    "SSO: Perform a full SSO install",
                    value="full-sso-install",
                ),
                questionary.Choice(
                    "SharePoint: Validate selected-sites helper app",
                    value="validate-selected-sites-helper",
                ),
            ],
            default="certificate-only",
        ).ask()
        if result is None:
            raise KeyboardInterrupt
        if not isinstance(result, str):
            raise RuntimeError("Questionary returned a non-string workflow mode.")
        return result

    print("Select a workflow mode:", file=output)
    print("1. Generate certificates only", file=output)
    print("2. SharePoint: Update existing SharePoint apps", file=output)
    print("3. SSO: Update existing SSO app", file=output)
    print("4. SharePoint: Perform a full SharePoint install", file=output)
    print("5. SSO: Perform a full SSO install", file=output)
    print("6. SharePoint: Validate selected-sites helper app", file=output)
    while True:
        response = prompts.text_prompt("Choose 1, 2, 3, 4, 5, or 6 [1]: ").strip()
        if response in {"", "1"}:
            return "certificate-only"
        if response == "2":
            return "update-existing-sharepoint"
        if response == "3":
            return "update-existing-sso"
        if response == "4":
            return "full-sharepoint-install"
        if response == "5":
            return "full-sso-install"
        if response == "6":
            return "validate-selected-sites-helper"
        print("Please enter 1, 2, 3, 4, 5, or 6.")


def build_existing_install_request(
    *,
    prompts: InteractivePrompts,
    output: TextIO,
    default_output_dir: Optional[Path] = None,
    validity_policy: CertificateValidityPolicy = CertificateValidityPolicy(),
    dry_run: bool = False,
) -> ExistingInstallBuildResult:
    """Build a request for the existing-install update workflow."""
    base_request = build_interactive_request(
        prompts=prompts,
        output=output,
        default_output_dir=default_output_dir,
        validity_policy=validity_policy,
    )
    live_app_id = _prompt_non_empty(
        prompt_text="Existing live app-only application ID: ",
        prompts=prompts,
    )
    user_app_id = _prompt_non_empty(
        prompt_text="Existing user authentication application ID: ",
        prompts=prompts,
    )
    sharepoint_access_mode = _prompt_sharepoint_access_mode(
        prompts=prompts,
        output=output,
    )
    additional_selected_sharepoint_site_urls = (
        _prompt_selected_sharepoint_site_urls(
            prompts=prompts,
            output=output,
            allow_empty=True,
        )
        if sharepoint_access_mode == "selected-sites"
        else []
    )
    selected_sites_helper_app_config = (
        _prompt_selected_sites_helper_app_config(prompts=prompts, output=output)
        if sharepoint_access_mode == "selected-sites"
        else None
    )
    return ExistingInstallBuildResult(
        request=ExistingInstallRequest(
            ls_site=base_request.request.ls_site,
            live_app_id=live_app_id,
            user_app_id=user_app_id,
            valid_years=base_request.request.valid_years,
            password=base_request.request.password,
            output_dir=base_request.request.output_dir,
            sharepoint_access_mode=sharepoint_access_mode,
            additional_selected_sharepoint_site_urls=additional_selected_sharepoint_site_urls,
            selected_sites_helper_app_config=selected_sites_helper_app_config,
            validity_policy=base_request.request.validity_policy,
        ),
        generated_password=base_request.generated_password,
        dry_run=_resolve_dry_run(prompts=prompts, provided_value=dry_run),
    )


def build_full_install_request(
    *,
    prompts: InteractivePrompts,
    output: TextIO,
    default_output_dir: Optional[Path] = None,
    validity_policy: CertificateValidityPolicy = CertificateValidityPolicy(),
    dry_run: bool = False,
) -> FullInstallBuildResult:
    """Build a request for the full install workflow."""
    base_request = build_interactive_request(
        prompts=prompts,
        output=output,
        default_output_dir=default_output_dir,
        validity_policy=validity_policy,
    )
    sharepoint_site_url = (
        "https://legalserver.sharepoint.com/sites/michael/Shared%20Documents/Forms/AllItems.aspx"
        if dry_run
        else _prompt_sharepoint_site_url(prompts=prompts)
    )
    sharepoint_access_mode = _prompt_sharepoint_access_mode(
        prompts=prompts,
        output=output,
    )
    selected_sharepoint_site_urls = (
        _prompt_selected_sharepoint_site_urls(
            prompts=prompts,
            output=output,
            allow_empty=False,
        )
        if sharepoint_access_mode == "selected-sites"
        else []
    )
    selected_sites_helper_app_config = (
        _prompt_selected_sites_helper_app_config(prompts=prompts, output=output)
        if sharepoint_access_mode == "selected-sites"
        else None
    )
    return FullInstallBuildResult(
        request=FullInstallRequest(
            ls_site=base_request.request.ls_site,
            sharepoint_site_url=sharepoint_site_url,
            valid_years=base_request.request.valid_years,
            password=base_request.request.password,
            output_dir=base_request.request.output_dir,
            sharepoint_access_mode=sharepoint_access_mode,
            selected_sharepoint_site_urls=selected_sharepoint_site_urls,
            selected_sites_helper_app_config=selected_sites_helper_app_config,
            validity_policy=base_request.request.validity_policy,
        ),
        generated_password=base_request.generated_password,
        dry_run=_resolve_dry_run(prompts=prompts, provided_value=dry_run),
    )


def build_existing_sso_install_request(
    *,
    prompts: InteractivePrompts,
    output: TextIO,
    default_output_dir: Optional[Path] = None,
    validity_policy: CertificateValidityPolicy = CertificateValidityPolicy(),
    dry_run: bool = False,
) -> ExistingSsoInstallBuildResult:
    """Build a request for updating an existing Site SSO installation."""
    base_request = build_interactive_request(
        prompts=prompts,
        output=output,
        default_output_dir=default_output_dir,
        validity_policy=validity_policy,
    )
    sso_app_id = _prompt_non_empty(
        prompt_text="Existing Site SSO application ID: ",
        prompts=prompts,
    )
    return ExistingSsoInstallBuildResult(
        request=ExistingSsoInstallRequest(
            ls_site=base_request.request.ls_site,
            sso_app_id=sso_app_id,
            valid_years=base_request.request.valid_years,
            password=base_request.request.password,
            output_dir=base_request.request.output_dir,
            validity_policy=base_request.request.validity_policy,
        ),
        generated_password=base_request.generated_password,
        dry_run=_resolve_dry_run(prompts=prompts, provided_value=dry_run),
    )


def build_sso_install_request(
    *,
    prompts: InteractivePrompts,
    output: TextIO,
    default_output_dir: Optional[Path] = None,
    validity_policy: CertificateValidityPolicy = CertificateValidityPolicy(),
    dry_run: bool = False,
) -> SsoInstallBuildResult:
    """Build a request for the Site SSO install workflow."""
    base_request = build_interactive_request(
        prompts=prompts,
        output=output,
        default_output_dir=default_output_dir,
        validity_policy=validity_policy,
    )
    return SsoInstallBuildResult(
        request=SsoInstallRequest(
            ls_site=base_request.request.ls_site,
            valid_years=base_request.request.valid_years,
            password=base_request.request.password,
            output_dir=base_request.request.output_dir,
            validity_policy=base_request.request.validity_policy,
        ),
        generated_password=base_request.generated_password,
        dry_run=_resolve_dry_run(prompts=prompts, provided_value=dry_run),
    )


def parse_args(argv: Optional[list[str]] = None) -> Namespace:
    """Parse optional command-line arguments for the interactive CLI."""
    parser = ArgumentParser(
        description="Run LegalServer Microsoft integration setup workflows."
    )
    parser.add_argument(
        "--mode",
        choices=[
            "certificate-only",
            "update-existing-sharepoint",
            "update-existing-sso",
            "full-sharepoint-install",
            "full-sso-install",
            "validate-selected-sites-helper",
        ],
        help="Workflow mode to run",
    )
    parser.add_argument("--site", help="LegalServer site abbreviation")
    parser.add_argument(
        "--years",
        type=int,
        help="Certificate validity in years",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Directory where SharePoint_Certificates will be created",
    )
    parser.add_argument(
        "--password",
        help=(
            "Certificate password that already meets complexity requirements. "
            "CAUTION: values passed here are visible in the process listing. "
            "Prefer --generate-password for scripted use, or set the "
            "LS_CERT_PASSWORD environment variable instead."
        ),
    )
    parser.add_argument(
        "--generate-password",
        action="store_true",
        help="Generate the certificate password automatically",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview Azure-backed changes without applying them",
    )
    parser.add_argument(
        "--helper-app-client-id",
        help="Existing selected-sites helper app client ID for helper validation mode",
    )
    parser.add_argument(
        "--helper-tenant-id",
        help="Tenant ID for selected-sites helper validation mode",
    )
    parser.add_argument(
        "--helper-certificate-path",
        help="PFX certificate path for selected-sites helper validation mode",
    )
    parser.add_argument(
        "--helper-thumbprint",
        help="Certificate thumbprint for selected-sites helper validation mode",
    )
    parser.add_argument(
        "--selected-site-url",
        help="SharePoint site URL to resolve during selected-sites helper validation mode",
    )
    return parser.parse_args(argv or [])


def default_prompts() -> InteractivePrompts:
    """Return the default interactive prompt implementations."""
    return InteractivePrompts(text_prompt=input, secret_prompt=getpass)
