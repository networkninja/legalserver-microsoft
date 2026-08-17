import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from legalserver_microsoft.helper_app import (
    build_helper_app_detail_messages,
    build_helper_app_graph_client,
    build_graph_key_credential,
    cleanup_selected_sites_helper_app,
    describe_selected_sites_grant_error,
    HelperAppCleanupResult,
    HelperAppSetupResult,
    SelectedSitesGrantTarget,
    grant_selected_sites_to_targets,
    setup_selected_sites_helper_app,
    verify_helper_app_graph_access,
)
from legalserver_microsoft.graph_client import GraphClient
from legalserver_microsoft.certificates import (
    export_cer,
    export_pfx,
    generate_cert,
    get_thumbprint,
)
from legalserver_microsoft.full_install import (
    validate_selected_sites_sharepoint_app_role,
)
from legalserver_microsoft.models import (
    ExistingInstallRequest,
    ExistingSsoInstallRequest,
)
from legalserver_microsoft.reporting import sanitize_site_name_for_filename
from legalserver_microsoft.utils import determine_site_type, get_unique_file_path


@dataclass(frozen=True)
class ExistingInstallPlan:
    """Represents the planned Azure updates for an existing installation."""

    site_type: str
    app_home_page_url: str
    expected_redirect_uris: list[str]
    live_app_display_name: str
    user_app_display_name: str
    live_app_missing_redirect_uris: list[str]
    user_app_missing_redirect_uris: list[str]
    live_app_valid_key_credential_count: int
    user_app_valid_key_credential_count: int


@dataclass(frozen=True)
class ExistingInstallApplyResult:
    """Represents the applied Azure changes for an existing installation."""

    plan: ExistingInstallPlan
    cert_path: str
    cer_file_path: str
    pfx_file_path: str
    thumbprint: str
    live_app_redirect_uris_applied: list[str]
    user_app_redirect_uris_applied: list[str]
    live_app_key_credential_count_after: int
    user_app_key_credential_count_after: int
    dry_run: bool
    sharepoint_access_mode: str
    additional_selected_sharepoint_site_urls_requested: list[str]
    selected_sharepoint_site_grant_role: str
    selected_sharepoint_site_grant_results: list[dict[str, str]]
    helper_app_cleanup_message: str


@dataclass(frozen=True)
class ExistingSsoInstallPlan:
    """Represents the planned Azure updates for an existing Site SSO installation."""

    site_type: str
    app_display_name: str
    expected_redirect_uris: list[str]
    missing_redirect_uris: list[str]
    valid_key_credential_count: int


@dataclass(frozen=True)
class ExistingSsoInstallApplyResult:
    """Represents the applied Azure changes for an existing Site SSO installation."""

    plan: ExistingSsoInstallPlan
    cert_path: str
    cer_file_path: str
    pfx_file_path: str
    thumbprint: str
    redirect_uris_applied: list[str]
    key_credential_count_after: int
    dry_run: bool


ProgressReporter = Callable[[str], None]


def _report_progress(*, reporter: ProgressReporter | None, message: str) -> None:
    """Send an optional progress message to the caller."""
    if reporter is not None:
        reporter(message)


def _build_additional_selected_sharepoint_site_grant_results(
    *,
    request: ExistingInstallRequest,
    graph_client: GraphClient,
    live_application: dict[str, Any],
    user_application: dict[str, Any],
    dry_run: bool,
    reporter: ProgressReporter | None,
) -> tuple[list[dict[str, str]], HelperAppSetupResult | None]:
    """Resolve and optionally grant additional selected SharePoint sites."""
    if request.sharepoint_access_mode != "selected-sites":
        return [], None

    helper_app_config = request.selected_sites_helper_app_config
    if helper_app_config is None:
        raise RuntimeError(
            "Selected-sites mode requires helper-app configuration details."
        )

    _report_progress(
        reporter=reporter,
        message=(
            "Preparing selected-sites helper application "
            + ("creation" if helper_app_config.create_new_helper_app else "reuse")
        ),
    )
    helper_setup = setup_selected_sites_helper_app(
        config=helper_app_config,
        graph_client=graph_client,
        helper_app_display_name=(
            f"{request.ls_site} LegalServer Selected Sites Helper"
        ),
        output_dir=request.output_dir,
        dry_run=dry_run,
    )
    _report_progress(
        reporter=reporter,
        message=(
            "Selected-sites helper application ready "
            f"({helper_setup.helper_app_client_id})"
        ),
    )
    for message in build_helper_app_detail_messages(
        helper_setup=helper_setup,
        created_new_helper_app=helper_app_config.create_new_helper_app,
    ):
        _report_progress(reporter=reporter, message=message)
    application_display_name = str(
        live_application.get("displayName", request.live_app_id)
    )
    user_application_display_name = str(
        user_application.get("displayName", request.user_app_id)
    )
    site_results: list[dict[str, str]] = []
    selected_sites_role_ok, selected_sites_role_status = (
        validate_selected_sites_sharepoint_app_role(graph_client=graph_client)
    )
    _report_progress(reporter=reporter, message=selected_sites_role_status)
    if dry_run:
        requested_site_urls = request.additional_selected_sharepoint_site_urls or []
        dry_run_seen_urls: set[str] = set()
        for site_url in requested_site_urls:
            if site_url in dry_run_seen_urls:
                site_results.append(
                    {
                        "requested_url": site_url,
                        "resolved_site_id": "",
                        "resolved_web_url": site_url,
                        "action": "already requested",
                        "grant_role": "write",
                        "error_message": "Duplicate selected site request was skipped.",
                    }
                )
                continue
            dry_run_seen_urls.add(site_url)
            site_result = grant_selected_sites_to_targets(
                graph_client=graph_client,
                requested_site_url=site_url,
                grant_targets=[
                    SelectedSitesGrantTarget(
                        application_id=request.live_app_id,
                        application_display_name=application_display_name,
                        target_label="app-only",
                    ),
                    SelectedSitesGrantTarget(
                        application_id=request.user_app_id,
                        application_display_name=user_application_display_name,
                        target_label="user-auth",
                    ),
                ],
                dry_run=True,
            )
            for target_result in site_result.target_results:
                site_results.append(
                    {
                        "requested_url": site_result.requested_url,
                        "resolved_site_id": site_result.resolved_site_id,
                        "resolved_web_url": site_result.resolved_web_url,
                        "action": target_result.action,
                        "grant_role": site_result.grant_role,
                        "error_message": target_result.error_message,
                        "target_label": target_result.target_label,
                        "application_id": target_result.application_id,
                        "application_display_name": target_result.application_display_name,
                    }
                )
        return site_results, helper_setup
    if not selected_sites_role_ok:
        for site_url in request.additional_selected_sharepoint_site_urls or []:
            for target_label, application_id, current_application_display_name in [
                ("app-only", request.live_app_id, application_display_name),
                ("user-auth", request.user_app_id, user_application_display_name),
            ]:
                site_results.append(
                    {
                        "requested_url": site_url,
                        "resolved_site_id": "",
                        "resolved_web_url": site_url,
                        "action": "failed",
                        "grant_role": "write",
                        "error_message": selected_sites_role_status,
                        "target_label": target_label,
                        "application_id": application_id,
                        "application_display_name": current_application_display_name,
                    }
                )
        return site_results, helper_setup
    if not helper_setup.helper_permissions_configured:
        helper_error = helper_setup.helper_admin_consent_status
        for site_url in request.additional_selected_sharepoint_site_urls or []:
            for target_label, application_id, current_application_display_name in [
                ("app-only", request.live_app_id, application_display_name),
                ("user-auth", request.user_app_id, user_application_display_name),
            ]:
                site_results.append(
                    {
                        "requested_url": site_url,
                        "resolved_site_id": "",
                        "resolved_web_url": site_url,
                        "action": "failed",
                        "grant_role": "write",
                        "error_message": helper_error,
                        "target_label": target_label,
                        "application_id": application_id,
                        "application_display_name": current_application_display_name,
                    }
                )
        _report_progress(
            reporter=reporter,
            message=(
                "Selected-sites helper app requires manual follow-up before site grants: "
                f"{helper_error}"
            ),
        )
        return site_results, helper_setup
    helper_graph_client = build_helper_app_graph_client(helper_setup=helper_setup)

    requested_site_urls = request.additional_selected_sharepoint_site_urls or []
    seen_urls: set[str] = set()

    for site_url in requested_site_urls:
        if site_url in seen_urls:
            site_results.append(
                {
                    "requested_url": site_url,
                    "resolved_site_id": "",
                    "resolved_web_url": site_url,
                    "action": "already requested",
                    "grant_role": "write",
                    "error_message": "Duplicate selected site request was skipped.",
                }
            )
            continue
        seen_urls.add(site_url)

        try:
            _report_progress(
                reporter=reporter,
                message=f"Resolving additional selected SharePoint site {site_url}",
            )
            site_result = grant_selected_sites_to_targets(
                graph_client=helper_graph_client,
                requested_site_url=site_url,
                grant_targets=[
                    SelectedSitesGrantTarget(
                        application_id=request.live_app_id,
                        application_display_name=application_display_name,
                        target_label="app-only",
                    ),
                    SelectedSitesGrantTarget(
                        application_id=request.user_app_id,
                        application_display_name=user_application_display_name,
                        target_label="user-auth",
                    ),
                ],
                dry_run=False,
            )
            for target_result in site_result.target_results:
                site_results.append(
                    {
                        "requested_url": site_result.requested_url,
                        "resolved_site_id": site_result.resolved_site_id,
                        "resolved_web_url": site_result.resolved_web_url,
                        "action": target_result.action,
                        "grant_role": site_result.grant_role,
                        "error_message": target_result.error_message,
                        "target_label": target_result.target_label,
                        "application_id": target_result.application_id,
                        "application_display_name": target_result.application_display_name,
                    }
                )
        except RuntimeError as exc:
            operator_error = describe_selected_sites_grant_error(error=exc)
            for target_label, application_id, current_application_display_name in [
                ("app-only", request.live_app_id, application_display_name),
                ("user-auth", request.user_app_id, user_application_display_name),
            ]:
                site_results.append(
                    {
                        "requested_url": site_url,
                        "resolved_site_id": "",
                        "resolved_web_url": site_url,
                        "action": "failed",
                        "grant_role": "write",
                        "error_message": operator_error,
                        "target_label": target_label,
                        "application_id": application_id,
                        "application_display_name": current_application_display_name,
                    }
                )
            _report_progress(
                reporter=reporter,
                message=(
                    "Selected SharePoint site grant follow-up required for "
                    f"{site_url}: {operator_error}"
                ),
            )

    return site_results, helper_setup


def cleanup_helper_app_after_existing_update(
    *,
    graph_client: GraphClient,
    helper_setup: HelperAppSetupResult | None,
    delete_created_helper_app: bool,
    retain_local_helper_artifacts: bool,
    dry_run: bool,
    reporter: ProgressReporter | None,
) -> HelperAppCleanupResult:
    """Apply optional helper-app cleanup for selected-sites update workflow."""
    if helper_setup is None:
        return HelperAppCleanupResult(
            attempted=False,
            deleted=False,
            local_artifacts_deleted=False,
            message="No helper app was used for this workflow.",
        )
    cleanup_result = cleanup_selected_sites_helper_app(
        graph_client=graph_client,
        helper_setup=helper_setup,
        delete_created_helper_app=delete_created_helper_app,
        retain_local_helper_artifacts=retain_local_helper_artifacts,
        dry_run=dry_run,
    )
    _report_progress(reporter=reporter, message=cleanup_result.message)
    return cleanup_result


def build_expected_redirect_uris(ls_site: str) -> tuple[str, list[str]]:
    """Build the expected homepage and redirect URIs for an installation."""
    site_type = determine_site_type(ls_site)
    if site_type == "Demo":
        live_site = ls_site[:-5]
        demo_site = ls_site
        app_home_page_url = f"https://{live_site.lower()}.legalserver.org"
        redirect_uris = [
            f"https://{live_site.lower()}.legalserver.org/user/office365",
            f"https://{demo_site.lower()}.legalserver.org/user/office365",
        ]
        return app_home_page_url, redirect_uris

    if site_type == "Dev":
        dev_site = ls_site
        if "-" in ls_site and ls_site.endswith(".dev"):
            org_name = ls_site.split("-", 1)[1].removesuffix(".dev")
            test_site = f"{org_name}.test"
        else:
            test_site = ls_site.removesuffix(".dev") + ".test"
        app_home_page_url = f"https://{test_site.lower()}.legalserver.org"
        redirect_uris = [
            f"https://{dev_site.lower()}.legalserver.org/user/office365",
            f"https://{test_site.lower()}.legalserver.org/user/office365",
        ]
        return app_home_page_url, redirect_uris

    app_home_page_url = f"https://{ls_site.lower()}.legalserver.org"
    redirect_uris = [
        f"https://{ls_site.lower()}.legalserver.org/user/office365",
        f"https://{ls_site.lower()}-demo.legalserver.org/user/office365",
    ]
    return app_home_page_url, redirect_uris


def get_missing_redirect_uris(
    current_redirect_uris: list[str], expected_redirect_uris: list[str]
) -> list[str]:
    """Return the redirect URIs that still need to be added."""
    current_normalized = {uri.lower() for uri in current_redirect_uris}
    return [
        uri for uri in expected_redirect_uris if uri.lower() not in current_normalized
    ]


def count_valid_key_credentials(key_credentials: list[dict[str, Any]]) -> int:
    """Count non-expired key credentials from an application payload."""
    now = datetime.now(timezone.utc)
    valid_count = 0
    for credential in key_credentials:
        end_date = _parse_credential_end_date(credential.get("endDateTime"))
        if end_date is None:
            continue
        if end_date > now:
            valid_count += 1
    return valid_count


def _parse_credential_end_date(raw: Any) -> datetime | None:
    """Parse a Graph key credential end date into a timezone-aware datetime."""
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def merge_redirect_uris(
    current_redirect_uris: list[str], expected_redirect_uris: list[str]
) -> list[str]:
    """Merge current and expected redirect URIs without duplicates."""
    merged: list[str] = []
    seen: set[str] = set()
    for uri in [*current_redirect_uris, *expected_redirect_uris]:
        normalized = uri.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        merged.append(uri)
    return merged


def prune_expired_key_credentials(
    key_credentials: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Remove expired key credentials while keeping valid ones intact."""
    now = datetime.now(timezone.utc)
    valid_credentials: list[dict[str, Any]] = []
    for credential in key_credentials:
        end_date = _parse_credential_end_date(credential.get("endDateTime"))
        if end_date is None:
            continue
        if end_date > now:
            valid_credentials.append(credential)
    return valid_credentials


def build_existing_install_plan(
    *,
    request: ExistingInstallRequest,
    live_application: dict[str, Any],
    user_application: dict[str, Any],
) -> ExistingInstallPlan:
    """Build a plan describing what an existing SharePoint update should change."""
    site_type = determine_site_type(request.ls_site)
    app_home_page_url, expected_redirect_uris = build_expected_redirect_uris(
        request.ls_site
    )
    live_redirect_uris = live_application.get("web", {}).get("redirectUris", []) or []
    user_redirect_uris = user_application.get("web", {}).get("redirectUris", []) or []

    return ExistingInstallPlan(
        site_type=site_type,
        app_home_page_url=app_home_page_url,
        expected_redirect_uris=expected_redirect_uris,
        live_app_display_name=live_application.get("displayName", request.live_app_id),
        user_app_display_name=user_application.get("displayName", request.user_app_id),
        live_app_missing_redirect_uris=get_missing_redirect_uris(
            live_redirect_uris,
            expected_redirect_uris,
        ),
        user_app_missing_redirect_uris=get_missing_redirect_uris(
            user_redirect_uris,
            expected_redirect_uris,
        ),
        live_app_valid_key_credential_count=count_valid_key_credentials(
            live_application.get("keyCredentials", []) or []
        ),
        user_app_valid_key_credential_count=count_valid_key_credentials(
            user_application.get("keyCredentials", []) or []
        ),
    )


def build_existing_sso_install_plan(
    *,
    request: ExistingSsoInstallRequest,
    application: dict[str, Any],
) -> ExistingSsoInstallPlan:
    """Build a plan describing what an existing Site SSO update should change."""
    expected_redirect_uris = ["https://aws-auth.legalserver.org/sso"]
    redirect_uris = application.get("web", {}).get("redirectUris", []) or []
    return ExistingSsoInstallPlan(
        site_type=determine_site_type(request.ls_site),
        app_display_name=application.get("displayName", request.sso_app_id),
        expected_redirect_uris=expected_redirect_uris,
        missing_redirect_uris=get_missing_redirect_uris(
            redirect_uris,
            expected_redirect_uris,
        ),
        valid_key_credential_count=count_valid_key_credentials(
            application.get("keyCredentials", []) or []
        ),
    )


def apply_existing_install_updates(
    *,
    request: ExistingInstallRequest,
    graph_client: GraphClient,
    live_application: dict[str, Any],
    user_application: dict[str, Any],
    dry_run: bool = False,
    delete_created_helper_app: bool = False,
    retain_local_helper_artifacts: bool = False,
    progress_reporter: ProgressReporter | None = None,
) -> ExistingInstallApplyResult:
    """Apply redirect URI and certificate rotation updates to existing apps."""
    _report_progress(
        reporter=progress_reporter, message="Building existing SharePoint update plan"
    )
    plan = build_existing_install_plan(
        request=request,
        live_application=live_application,
        user_application=user_application,
    )
    _report_progress(
        reporter=progress_reporter, message="Existing SharePoint update plan ready"
    )

    cert_path = request.output_dir / "SharePoint_Certificates"
    cert_path.mkdir(parents=True, exist_ok=True)
    cert_base_name = sanitize_site_name_for_filename(ls_site=request.ls_site)
    cer_file_path = get_unique_file_path(
        cert_path / f"{cert_base_name}_certificate_cer.cer"
    )
    pfx_file_path = get_unique_file_path(
        cert_path / f"{cert_base_name}_certificate_pfx.pfx"
    )

    _report_progress(
        reporter=progress_reporter, message="Generating certificate artifacts"
    )
    key, cert = generate_cert(
        request.ls_site,
        request.valid_years,
        validity_policy=request.validity_policy,
    )
    export_cer(cert=cert, path=cer_file_path)
    export_pfx(key=key, cert=cert, password=request.password, path=pfx_file_path)
    thumbprint = get_thumbprint(cert)
    new_key_credential = build_graph_key_credential(cert=cert)
    _report_progress(
        reporter=progress_reporter, message="Certificate artifacts generated"
    )

    _report_progress(
        reporter=progress_reporter, message="Merging redirect URIs and key credentials"
    )
    live_redirect_uris = merge_redirect_uris(
        live_application.get("web", {}).get("redirectUris", []) or [],
        plan.expected_redirect_uris,
    )
    user_redirect_uris = merge_redirect_uris(
        user_application.get("web", {}).get("redirectUris", []) or [],
        plan.expected_redirect_uris,
    )

    live_key_credentials = prune_expired_key_credentials(
        live_application.get("keyCredentials", []) or []
    )
    user_key_credentials = prune_expired_key_credentials(
        user_application.get("keyCredentials", []) or []
    )
    live_key_credentials.append(new_key_credential)
    user_key_credentials.append(new_key_credential)
    _report_progress(
        reporter=progress_reporter, message="Redirect URI and key credential plan ready"
    )

    if not dry_run:
        _report_progress(
            reporter=progress_reporter,
            message="Updating live application web configuration",
        )
        graph_client.update_application_web_config(
            application_object_id=live_application["id"],
            home_page_url=plan.app_home_page_url,
            redirect_uris=live_redirect_uris,
        )
        _report_progress(
            reporter=progress_reporter,
            message="Live application web configuration updated",
        )
        _report_progress(
            reporter=progress_reporter,
            message="Updating live application key credentials",
        )
        graph_client.update_application_key_credentials(
            application_object_id=live_application["id"],
            key_credentials=live_key_credentials,
        )
        _report_progress(
            reporter=progress_reporter,
            message="Live application key credentials updated",
        )
        _report_progress(
            reporter=progress_reporter,
            message="Updating user application web configuration",
        )
        graph_client.update_application_web_config(
            application_object_id=user_application["id"],
            home_page_url=plan.app_home_page_url,
            redirect_uris=user_redirect_uris,
        )
        _report_progress(
            reporter=progress_reporter,
            message="User application web configuration updated",
        )
        _report_progress(
            reporter=progress_reporter,
            message="Updating user application key credentials",
        )
        graph_client.update_application_key_credentials(
            application_object_id=user_application["id"],
            key_credentials=user_key_credentials,
        )
        _report_progress(
            reporter=progress_reporter,
            message="User application key credentials updated",
        )

    selected_sharepoint_site_grant_results, helper_setup = (
        _build_additional_selected_sharepoint_site_grant_results(
            request=request,
            graph_client=graph_client,
            live_application=live_application,
            user_application=user_application,
            dry_run=dry_run,
            reporter=progress_reporter,
        )
    )
    helper_app_cleanup_message = "No helper app cleanup was performed."
    if helper_setup is not None:
        cleanup_result = cleanup_helper_app_after_existing_update(
            graph_client=graph_client,
            helper_setup=helper_setup,
            delete_created_helper_app=delete_created_helper_app,
            retain_local_helper_artifacts=retain_local_helper_artifacts,
            dry_run=dry_run,
            reporter=progress_reporter,
        )
        helper_app_cleanup_message = cleanup_result.message

    return ExistingInstallApplyResult(
        plan=plan,
        cert_path=str(cert_path),
        cer_file_path=str(cer_file_path),
        pfx_file_path=str(pfx_file_path),
        thumbprint=thumbprint,
        live_app_redirect_uris_applied=live_redirect_uris,
        user_app_redirect_uris_applied=user_redirect_uris,
        live_app_key_credential_count_after=len(live_key_credentials),
        user_app_key_credential_count_after=len(user_key_credentials),
        dry_run=dry_run,
        sharepoint_access_mode=request.sharepoint_access_mode,
        additional_selected_sharepoint_site_urls_requested=request.additional_selected_sharepoint_site_urls
        or [],
        selected_sharepoint_site_grant_role=(
            "write" if request.sharepoint_access_mode == "selected-sites" else ""
        ),
        selected_sharepoint_site_grant_results=selected_sharepoint_site_grant_results,
        helper_app_cleanup_message=helper_app_cleanup_message,
    )


def apply_existing_sso_install_updates(
    *,
    request: ExistingSsoInstallRequest,
    graph_client: GraphClient,
    application: dict[str, Any],
    dry_run: bool = False,
    progress_reporter: ProgressReporter | None = None,
) -> ExistingSsoInstallApplyResult:
    """Apply redirect URI and certificate rotation updates to an existing Site SSO app."""
    _report_progress(
        reporter=progress_reporter, message="Building existing Site SSO update plan"
    )
    plan = build_existing_sso_install_plan(request=request, application=application)
    _report_progress(
        reporter=progress_reporter, message="Existing Site SSO update plan ready"
    )

    cert_path = request.output_dir / "SharePoint_Certificates"
    cert_path.mkdir(parents=True, exist_ok=True)
    cert_base_name = sanitize_site_name_for_filename(ls_site=request.ls_site)
    cer_file_path = get_unique_file_path(
        cert_path / f"{cert_base_name}_sso_certificate_cer.cer"
    )
    pfx_file_path = get_unique_file_path(
        cert_path / f"{cert_base_name}_sso_certificate_pfx.pfx"
    )

    _report_progress(
        reporter=progress_reporter, message="Generating certificate artifacts"
    )
    key, cert = generate_cert(
        request.ls_site,
        request.valid_years,
        validity_policy=request.validity_policy,
    )
    export_cer(cert=cert, path=cer_file_path)
    export_pfx(key=key, cert=cert, password=request.password, path=pfx_file_path)
    thumbprint = get_thumbprint(cert)
    new_key_credential = build_graph_key_credential(cert=cert)
    _report_progress(
        reporter=progress_reporter, message="Certificate artifacts generated"
    )

    _report_progress(
        reporter=progress_reporter, message="Merging redirect URIs and key credentials"
    )
    redirect_uris = merge_redirect_uris(
        application.get("web", {}).get("redirectUris", []) or [],
        plan.expected_redirect_uris,
    )
    key_credentials = prune_expired_key_credentials(
        application.get("keyCredentials", []) or []
    )
    key_credentials.append(new_key_credential)
    _report_progress(
        reporter=progress_reporter, message="Redirect URI and key credential plan ready"
    )

    if not dry_run:
        _report_progress(
            reporter=progress_reporter,
            message="Updating Site SSO application web configuration",
        )
        graph_client.update_application_web_config(
            application_object_id=application["id"],
            home_page_url=plan.expected_redirect_uris[0],
            redirect_uris=redirect_uris,
        )
        _report_progress(
            reporter=progress_reporter,
            message="Site SSO application web configuration updated",
        )
        _report_progress(
            reporter=progress_reporter,
            message="Updating Site SSO application key credentials",
        )
        graph_client.update_application_key_credentials(
            application_object_id=application["id"],
            key_credentials=key_credentials,
        )
        _report_progress(
            reporter=progress_reporter,
            message="Site SSO application key credentials updated",
        )

    return ExistingSsoInstallApplyResult(
        plan=plan,
        cert_path=str(cert_path),
        cer_file_path=str(cer_file_path),
        pfx_file_path=str(pfx_file_path),
        thumbprint=thumbprint,
        redirect_uris_applied=redirect_uris,
        key_credential_count_after=len(key_credentials),
        dry_run=dry_run,
    )
