from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

from legalserver_microsoft.certificates import (
    export_cer,
    export_pfx,
    generate_cert,
    get_thumbprint,
)
from legalserver_microsoft.graph_client import GraphClient
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
    wait_for_helper_app_site_resolution_readiness,
)
from legalserver_microsoft.models import FullInstallRequest, SsoInstallRequest
from legalserver_microsoft.reporting import sanitize_site_name_for_filename
from legalserver_microsoft.utils import (
    convert_sharepoint_url,
    determine_site_type,
    get_unique_file_path,
)


@dataclass(frozen=True)
class FullInstallPlan:
    """Represents the planned app registration values for a full install."""

    site_type: str
    app_only_display_name: str
    user_display_name: str
    app_home_page_url: str
    redirect_uris: list[str]
    app_identifier_uri: str
    user_identifier_uri: str


@dataclass(frozen=True)
class FullInstallApplyResult:
    """Represents the applied Azure creation results for a full install."""

    plan: FullInstallPlan
    tenant_id: str
    app_only_app_id: str
    user_app_id: str
    app_only_object_id: str
    user_object_id: str
    app_only_service_principal_id: str
    user_service_principal_id: str
    cert_path: str
    cer_file_path: str
    pfx_file_path: str
    thumbprint: str
    certificate_expiration: str
    top_level_web_url: str
    home_default_site: str
    default_document_library: str
    certificate_password: str
    app_only_permissions_configured: bool
    user_permissions_configured: bool
    admin_consent_status: str
    admin_consent_instructions: str
    dry_run: bool
    owner_assignment_status: str
    delegated_consent_status: str
    delegated_consent_instructions: str
    sharepoint_access_mode: str
    selected_sharepoint_site_urls_requested: list[str]
    selected_sharepoint_site_grant_role: str
    selected_sharepoint_site_grant_results: list[dict[str, str]]
    helper_app_cleanup_message: str


@dataclass(frozen=True)
class SsoInstallPlan:
    """Represents the planned app registration values for the Site SSO install."""

    site_type: str
    display_name: str
    redirect_uris: list[str]
    identifier_uri: str


@dataclass(frozen=True)
class SsoInstallApplyResult:
    """Represents the applied Azure creation results for a Site SSO install."""

    plan: SsoInstallPlan
    tenant_id: str
    app_id: str
    object_id: str
    service_principal_id: str
    cert_path: str
    cer_file_path: str
    pfx_file_path: str
    thumbprint: str
    certificate_expiration: str
    certificate_password: str
    permissions_configured: bool
    admin_consent_status: str
    admin_consent_instructions: str
    owner_assignment_status: str
    dry_run: bool


ProgressReporter = Callable[[str], None]

SHAREPOINT_RESOURCE_APP_ID = "00000003-0000-0ff1-ce00-000000000000"
GRAPH_RESOURCE_APP_ID = "00000003-0000-0000-c000-000000000000"
SHAREPOINT_BROAD_APP_ROLE_IDS = (
    "2a8d57a5-4090-4a41-bf1c-3c621d2ccad3",
    "fbcd29d2-fcca-4405-aded-518d457caae4",
)
SHAREPOINT_SELECTED_SITES_ROLE_ID = "20d37865-089c-4dee-8c41-6967602d4ac8"
GRAPH_SITES_SELECTED_ROLE_ID = "9492366f-7969-46a4-8d15-ed1a20078fff"
HELPER_APP_READINESS_RETRY_DELAYS_SECONDS = (0.0, 10.0, 20.0, 30.0, 60.0, 120.0)


def _report_progress(*, reporter: ProgressReporter | None, message: str) -> None:
    """Send an optional progress message to the caller."""
    if reporter is not None:
        reporter(message)


def validate_selected_sites_sharepoint_app_role(
    *, graph_client: GraphClient
) -> tuple[bool, str]:
    """Validate that the tenant SharePoint service principal exposes the expected selected-sites app role."""
    try:
        sharepoint_sp = graph_client.get_service_principal_by_app_id(
            SHAREPOINT_RESOURCE_APP_ID
        )
    except RuntimeError as exc:
        error_text = str(exc).strip()
        if not error_text:
            return (
                True,
                "Selected-sites SharePoint app role validation was skipped because the SharePoint service principal lookup returned no usable details.",
            )
        return (
            False,
            f"Unable to load SharePoint service principal for role validation: {error_text}",
        )

    app_roles = sharepoint_sp.get("appRoles", []) or []
    if not isinstance(app_roles, list):
        return (
            True,
            "Selected-sites SharePoint app role validation was skipped because the SharePoint service principal appRoles payload was not a list.",
        )
    available_roles: list[str] = []
    available_role_ids = [
        str(app_role.get("id"))
        for app_role in app_roles
        if isinstance(app_role, dict) and app_role.get("id")
    ]
    for app_role in app_roles:
        if not isinstance(app_role, dict):
            continue
        role_id = str(app_role.get("id", ""))
        role_value = str(app_role.get("value", ""))
        role_name = str(app_role.get("displayName", ""))
        allowed_member_types = app_role.get("allowedMemberTypes", [])
        available_roles.append(
            "{"
            + f"id={role_id}, value={role_value}, displayName={role_name}, allowedMemberTypes={allowed_member_types}"
            + "}"
        )
    if not available_role_ids:
        return (
            True,
            "Selected-sites SharePoint app role validation was skipped because the SharePoint service principal returned no app role IDs.",
        )
    if SHAREPOINT_SELECTED_SITES_ROLE_ID in available_role_ids:
        return (
            True,
            "Selected-sites SharePoint app role was found on the tenant SharePoint service principal.",
        )

    return (
        False,
        "Selected-sites SharePoint app role was not found on the tenant SharePoint service principal. "
        f"Expected role ID: {SHAREPOINT_SELECTED_SITES_ROLE_ID}. Available roles: {'; '.join(available_roles) if available_roles else 'none returned'}.",
    )


def _build_selected_sharepoint_site_grant_results(
    *,
    request: FullInstallRequest,
    graph_client: GraphClient,
    app_only_application_id: str,
    app_only_application_display_name: str,
    user_application_id: str,
    user_application_display_name: str,
    helper_setup: HelperAppSetupResult | None,
    dry_run: bool,
    reporter: ProgressReporter | None,
) -> tuple[list[dict[str, str]], HelperAppSetupResult | None]:
    """Resolve and optionally grant selected SharePoint site access for full install."""
    if request.sharepoint_access_mode != "selected-sites":
        return [], None

    if helper_setup is None:
        raise RuntimeError(
            "Selected-sites mode requires prepared helper-app setup details."
        )

    def build_site_result_entries(
        *,
        action: str,
        error_message: str,
    ) -> list[dict[str, str]]:
        """Build per-site selected-sites result entries for both app targets."""
        results: list[dict[str, str]] = []
        for site_url in request.selected_sharepoint_site_urls or []:
            for target_label, application_id, application_display_name in [
                (
                    "app-only",
                    app_only_application_id,
                    app_only_application_display_name,
                ),
                ("user-auth", user_application_id, user_application_display_name),
            ]:
                results.append(
                    {
                        "requested_url": site_url,
                        "resolved_site_id": "",
                        "resolved_web_url": site_url,
                        "action": action,
                        "grant_role": "write",
                        "error_message": error_message,
                        "target_label": target_label,
                        "application_id": application_id,
                        "application_display_name": application_display_name,
                    }
                )
        return results

    site_results: list[dict[str, str]] = []
    selected_sites_role_ok, selected_sites_role_status = (
        validate_selected_sites_sharepoint_app_role(graph_client=graph_client)
    )
    _report_progress(reporter=reporter, message=selected_sites_role_status)
    if dry_run:
        for site_url in request.selected_sharepoint_site_urls or []:
            site_result = grant_selected_sites_to_targets(
                graph_client=graph_client,
                requested_site_url=site_url,
                grant_targets=[
                    SelectedSitesGrantTarget(
                        application_id=app_only_application_id,
                        application_display_name=app_only_application_display_name,
                        target_label="app-only",
                    ),
                    SelectedSitesGrantTarget(
                        application_id=user_application_id,
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
        site_results.extend(
            build_site_result_entries(
                action="failed",
                error_message=selected_sites_role_status,
            )
        )
        return site_results, helper_setup
    if not helper_setup.helper_permissions_configured:
        helper_error = helper_setup.helper_admin_consent_status
        site_results.extend(
            build_site_result_entries(action="failed", error_message=helper_error)
        )
        _report_progress(
            reporter=reporter,
            message=(
                "Selected-sites helper app requires manual follow-up before site grants: "
                f"{helper_error}"
            ),
        )
        return site_results, helper_setup
    requested_site_urls = request.selected_sharepoint_site_urls or []
    if helper_setup.created_in_this_run and requested_site_urls:
        readiness_site_url = requested_site_urls[0]
        _report_progress(
            reporter=reporter,
            message=(
                "Waiting for newly created selected-sites helper app propagation "
                f"using {readiness_site_url}. "
                f"This may take up to about {int(sum(HELPER_APP_READINESS_RETRY_DELAYS_SECONDS) // 60)} minute(s) "
                f"across {len(HELPER_APP_READINESS_RETRY_DELAYS_SECONDS)} attempt(s)."
            ),
        )
        readiness_result = wait_for_helper_app_site_resolution_readiness(
            helper_setup=helper_setup,
            requested_site_url=readiness_site_url,
            retry_delays_seconds=HELPER_APP_READINESS_RETRY_DELAYS_SECONDS,
            progress_reporter=reporter,
        )
        if not readiness_result.ready:
            follow_up_message = (
                "Helper app was created successfully, but it is not yet ready for Microsoft Graph "
                "SharePoint site calls. Rerun this workflow later using helper app reuse after "
                f"propagation completes. Attempts: {readiness_result.attempts}. "
                f"Last error: {readiness_result.last_error}"
            )
            _report_progress(
                reporter=reporter,
                message=(
                    "Selected-sites helper app propagation is still incomplete. "
                    "Preserving created artifacts and skipping site grants for this run."
                ),
            )
            site_results.extend(
                build_site_result_entries(
                    action="follow-up required",
                    error_message=follow_up_message,
                )
            )
            return site_results, helper_setup
        _report_progress(
            reporter=reporter,
            message=(
                "Selected-sites helper app readiness confirmed after "
                f"{readiness_result.attempts} attempt(s)."
            ),
        )
    helper_graph_client = build_helper_app_graph_client(helper_setup=helper_setup)

    for site_url in requested_site_urls:
        try:
            _report_progress(
                reporter=reporter,
                message=f"Resolving selected SharePoint site {site_url}",
            )
            site_result = grant_selected_sites_to_targets(
                graph_client=helper_graph_client,
                requested_site_url=site_url,
                grant_targets=[
                    SelectedSitesGrantTarget(
                        application_id=app_only_application_id,
                        application_display_name=app_only_application_display_name,
                        target_label="app-only",
                    ),
                    SelectedSitesGrantTarget(
                        application_id=user_application_id,
                        application_display_name=user_application_display_name,
                        target_label="user-auth",
                    ),
                ],
                dry_run=dry_run,
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
            for target_label, application_id, application_display_name in [
                (
                    "app-only",
                    app_only_application_id,
                    app_only_application_display_name,
                ),
                ("user-auth", user_application_id, user_application_display_name),
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
                        "application_display_name": application_display_name,
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


def _prepare_selected_sites_helper_setup(
    *,
    request: FullInstallRequest,
    graph_client: GraphClient,
    dry_run: bool,
    reporter: ProgressReporter | None,
) -> HelperAppSetupResult | None:
    """Prepare helper-app setup early for selected-sites workflows."""
    if request.sharepoint_access_mode != "selected-sites":
        return None

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
    return helper_setup


def cleanup_helper_app_after_full_install(
    *,
    graph_client: GraphClient,
    helper_setup: HelperAppSetupResult | None,
    delete_created_helper_app: bool,
    retain_local_helper_artifacts: bool,
    dry_run: bool,
    reporter: ProgressReporter | None,
) -> HelperAppCleanupResult:
    """Apply optional helper-app cleanup for selected-sites full install."""
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


def build_app_only_required_resource_access() -> list[dict[str, Any]]:
    """Build the required resource access payload for the app-only app."""
    return [
        {
            "resourceAppId": SHAREPOINT_RESOURCE_APP_ID,
            "resourceAccess": [
                {
                    "id": SHAREPOINT_BROAD_APP_ROLE_IDS[0],
                    "type": "Role",
                },
                {
                    "id": SHAREPOINT_BROAD_APP_ROLE_IDS[1],
                    "type": "Role",
                },
            ],
        },
        {
            "resourceAppId": GRAPH_RESOURCE_APP_ID,
            "resourceAccess": [
                {
                    "id": GRAPH_SITES_SELECTED_ROLE_ID,
                    "type": "Role",
                }
            ],
        },
    ]


def build_app_only_selected_sites_required_resource_access() -> list[dict[str, Any]]:
    """Build the required resource access payload for selected-sites app-only use."""
    return [
        {
            "resourceAppId": SHAREPOINT_RESOURCE_APP_ID,
            "resourceAccess": [
                {
                    "id": SHAREPOINT_SELECTED_SITES_ROLE_ID,
                    "type": "Role",
                }
            ],
        },
        {
            "resourceAppId": GRAPH_RESOURCE_APP_ID,
            "resourceAccess": [
                {
                    "id": GRAPH_SITES_SELECTED_ROLE_ID,
                    "type": "Role",
                }
            ],
        },
    ]


def build_app_only_required_resource_access_for_mode(
    *,
    sharepoint_access_mode: str,
) -> list[dict[str, Any]]:
    """Build the app-only required resource access payload for the selected mode."""
    if sharepoint_access_mode == "selected-sites":
        return build_app_only_selected_sites_required_resource_access()
    return build_app_only_required_resource_access()


def build_user_required_resource_access() -> list[dict[str, Any]]:
    """Build the required resource access payload for the user-auth app."""
    return [
        {
            "resourceAppId": "00000003-0000-0ff1-ce00-000000000000",
            "resourceAccess": [
                {
                    "id": "640ddd16-e5b7-4d71-9690-3f4022699ee7",
                    "type": "Scope",
                },
                {
                    "id": "1002502a-9a71-4426-8551-69ab83452fab",
                    "type": "Scope",
                },
                {
                    "id": "0cea5a30-f6f8-42b5-87a0-84cc26822e02",
                    "type": "Scope",
                },
                {
                    "id": "a468ea40-458c-4cc2-80c4-51781af71e41",
                    "type": "Scope",
                },
            ],
        },
        {
            "resourceAppId": "00000003-0000-0000-c000-000000000000",
            "resourceAccess": [
                {
                    "id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d",
                    "type": "Scope",
                },
                {
                    "id": "863451e7-0667-486c-a5d6-d135439485f0",
                    "type": "Scope",
                },
            ],
        },
    ]


def build_sso_required_resource_access() -> list[dict[str, Any]]:
    """Build the required resource access payload for the Site SSO app."""
    return [
        {
            "resourceAppId": "00000003-0000-0000-c000-000000000000",
            "resourceAccess": [
                {
                    "id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d",
                    "type": "Scope",
                }
            ],
        }
    ]


def _build_manual_consent_instructions(
    *,
    app_only_app_id: str,
    user_app_id: str,
) -> str:
    """Build manual admin consent instructions for the created applications."""
    return "\n".join(
        [
            "Admin consent may still be required.",
            "Review the created applications in Azure and grant admin consent if your tenant did not allow automatic assignment.",
            f"App-Only Application App ID: {app_only_app_id}",
            f"User Authentication Application App ID: {user_app_id}",
        ]
    )


def _build_manual_delegated_consent_instructions(
    *,
    user_app_id: str,
) -> str:
    """Build manual delegated-consent instructions for the user-auth application."""
    return "\n".join(
        [
            "Delegated permissions may still require tenant admin consent.",
            "Review the User Authentication application in Azure and grant admin consent for delegated permissions if prompted.",
            f"User Authentication Application App ID: {user_app_id}",
        ]
    )


def attempt_admin_consent(
    *,
    graph_client: GraphClient,
    app_only_app_id: str,
    app_only_service_principal_id: str,
    required_resource_access: list[dict[str, Any]],
) -> tuple[bool, str]:
    """Attempt admin consent for application-role permissions and report the result."""
    errors: list[str] = []
    for resource in required_resource_access:
        resource_app_id = resource.get("resourceAppId")
        if not resource_app_id:
            errors.append("required resource access entry is missing resourceAppId")
            continue

        raw_resource_access = resource.get("resourceAccess")
        if not isinstance(raw_resource_access, list):
            errors.append(
                f"resource app {resource_app_id} is missing a valid resourceAccess list"
            )
            continue

        role_accesses = [
            access
            for access in raw_resource_access
            if isinstance(access, dict) and access.get("type") == "Role"
        ]
        if not role_accesses:
            continue

        try:
            resource_service_principal = graph_client.get_service_principal_by_app_id(
                resource_app_id
            )
        except RuntimeError as exc:
            errors.append(
                f"resource app {resource_app_id} service principal lookup failed: {exc}"
            )
            continue

        resource_service_principal_id = resource_service_principal.get("id")
        if not resource_service_principal_id:
            errors.append(
                f"resource app {resource_app_id} returned a service principal payload missing service principal id"
            )
            continue

        app_roles = resource_service_principal.get("appRoles", []) or []
        for access in role_accesses:
            access_id = access.get("id")
            if not access_id:
                errors.append(
                    f"resource app {resource_app_id} has a role access entry missing app role id"
                )
                continue

            matching_role = next(
                (app_role for app_role in app_roles if app_role.get("id") == access_id),
                None,
            )
            if matching_role is None:
                errors.append(
                    f"resource app {resource_app_id} app role {access_id} was not found on service principal {resource_service_principal_id}"
                )
                continue

            matching_role_id = matching_role.get("id")
            if not matching_role_id:
                errors.append(
                    f"resource app {resource_app_id} returned a matching app role missing an id on service principal {resource_service_principal_id}"
                )
                continue
            try:
                graph_client.create_service_principal_app_role_assignment(
                    service_principal_id=app_only_service_principal_id,
                    principal_id=app_only_service_principal_id,
                    resource_id=resource_service_principal_id,
                    app_role_id=matching_role_id,
                )
            except RuntimeError as exc:
                errors.append(
                    f"resource app {resource_app_id} app role {matching_role_id} assignment failed for service principal {resource_service_principal_id}: {exc}"
                )

    if errors:
        return False, "Automatic admin consent was not fully completed: " + "; ".join(
            errors
        )
    return True, "Automatic admin consent succeeded for application-role permissions."


def evaluate_delegated_consent(
    *,
    user_required_resource_access: list[dict[str, Any]],
    user_app_id: str,
    dry_run: bool,
) -> tuple[str, str]:
    """Report delegated-consent expectations for the user-auth application."""
    delegated_permissions = [
        access
        for resource in user_required_resource_access
        for access in resource["resourceAccess"]
        if access["type"] == "Scope"
    ]
    if dry_run:
        return (
            "Dry run only. Delegated consent was not evaluated against Azure.",
            "Dry run only. Review delegated-permission requirements before re-running without --dry-run.",
        )
    if not delegated_permissions:
        return (
            "No delegated permissions were configured.",
            "No delegated-permission consent is required.",
        )
    return (
        "Delegated permissions were configured. Tenant admin consent may still need to be completed manually.",
        _build_manual_delegated_consent_instructions(user_app_id=user_app_id),
    )


def build_full_install_plan(
    *, request: FullInstallRequest, tenant_domain: str
) -> FullInstallPlan:
    """Build the naming and URI plan for a full install."""
    site_type = determine_site_type(request.ls_site)
    if site_type == "Demo":
        live_site = request.ls_site[:-5]
        demo_site = request.ls_site
        app_home_page_url = f"https://{live_site.lower()}.legalserver.org"
        redirect_uris = [
            f"https://{live_site.lower()}.legalserver.org/user/office365",
            f"https://{demo_site.lower()}.legalserver.org/user/office365",
        ]
        name_root = live_site
    elif site_type == "Dev":
        dev_site = request.ls_site
        if "-" in request.ls_site and request.ls_site.endswith(".dev"):
            org_name = request.ls_site.split("-", 1)[1].removesuffix(".dev")
            test_site = f"{org_name}.test"
        else:
            test_site = request.ls_site.removesuffix(".dev") + ".test"
        app_home_page_url = f"https://{test_site.lower()}.legalserver.org"
        redirect_uris = [
            f"https://{dev_site.lower()}.legalserver.org/user/office365",
            f"https://{test_site.lower()}.legalserver.org/user/office365",
        ]
        name_root = test_site
    else:
        app_home_page_url = f"https://{request.ls_site.lower()}.legalserver.org"
        redirect_uris = [
            f"https://{request.ls_site.lower()}.legalserver.org/user/office365",
            f"https://{request.ls_site.lower()}-demo.legalserver.org/user/office365",
        ]
        name_root = request.ls_site

    return FullInstallPlan(
        site_type=site_type,
        app_only_display_name=f"{name_root} LegalServer App-Only Authentication",
        user_display_name=f"{name_root} LegalServer User Authentication",
        app_home_page_url=app_home_page_url,
        redirect_uris=redirect_uris,
        app_identifier_uri=f"https://{tenant_domain}/{uuid4()}",
        user_identifier_uri=f"https://{tenant_domain}/{uuid4()}",
    )


def build_sso_install_plan(
    *, request: SsoInstallRequest, tenant_domain: str
) -> SsoInstallPlan:
    """Build the naming and URI plan for a Site SSO install."""
    return SsoInstallPlan(
        site_type=determine_site_type(request.ls_site),
        display_name=f"LegalServer {request.ls_site} SSO",
        redirect_uris=["https://aws-auth.legalserver.org/sso"],
        identifier_uri=f"https://{tenant_domain}/{uuid4()}",
    )


def extract_default_tenant_domain(tenant: dict[str, Any]) -> str:
    """Extract the default verified domain from a tenant payload."""
    verified_domains = tenant.get("verifiedDomains", []) or []
    for domain in verified_domains:
        if isinstance(domain, dict) and domain.get("isDefault"):
            name = domain.get("name")
            if isinstance(name, str):
                return name
    raise RuntimeError("No default verified tenant domain was found.")


def apply_full_install(
    *,
    request: FullInstallRequest,
    graph_client: GraphClient,
    tenant: dict[str, Any],
    dry_run: bool = False,
    delete_created_helper_app: bool = False,
    retain_local_helper_artifacts: bool = False,
    progress_reporter: ProgressReporter | None = None,
) -> FullInstallApplyResult:
    """Create Azure applications, service principals, and certificate artifacts."""
    tenant_id = tenant.get("id", "Unknown")
    tenant_domain = extract_default_tenant_domain(tenant)
    _report_progress(reporter=progress_reporter, message="Building full-install plan")
    plan = build_full_install_plan(request=request, tenant_domain=tenant_domain)
    sharepoint_details = convert_sharepoint_url(request.sharepoint_site_url)
    top_level_web_url = f"https://{sharepoint_details['Domain']}"
    home_default_site = sharepoint_details["Subsite"]
    default_document_library = sharepoint_details["Library"]
    _report_progress(reporter=progress_reporter, message="Full-install plan ready")
    helper_setup = _prepare_selected_sites_helper_setup(
        request=request,
        graph_client=graph_client,
        dry_run=dry_run,
        reporter=progress_reporter,
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
    key_credential = build_graph_key_credential(cert=cert)
    _report_progress(
        reporter=progress_reporter, message="Certificate artifacts generated"
    )

    if dry_run:
        app_only_application = {
            "id": "dry-run-app-only-object-id",
            "appId": "dry-run-app-only-app-id",
        }
        user_application = {
            "id": "dry-run-user-object-id",
            "appId": "dry-run-user-app-id",
        }
        app_only_service_principal = {"id": "dry-run-app-only-sp-id"}
        user_service_principal = {"id": "dry-run-user-sp-id"}
        owner_assignment_status = "Dry run only. No owner assignment was applied."
    else:
        _report_progress(
            reporter=progress_reporter, message="Creating app-only Azure application"
        )
        app_only_application = graph_client.create_application(
            {
                "displayName": plan.app_only_display_name,
                "signInAudience": "AzureADMyOrg",
                "identifierUris": [plan.app_identifier_uri],
                "web": {
                    "homePageUrl": plan.app_home_page_url,
                    "redirectUris": plan.redirect_uris,
                },
                "keyCredentials": [key_credential],
            }
        )
        _report_progress(
            reporter=progress_reporter, message="App-only Azure application created"
        )
        _report_progress(
            reporter=progress_reporter, message="Creating user Azure application"
        )
        user_application = graph_client.create_application(
            {
                "displayName": plan.user_display_name,
                "signInAudience": "AzureADMyOrg",
                "identifierUris": [plan.user_identifier_uri],
                "web": {
                    "homePageUrl": plan.app_home_page_url,
                    "redirectUris": plan.redirect_uris,
                },
                "keyCredentials": [key_credential],
            }
        )
        _report_progress(
            reporter=progress_reporter, message="User Azure application created"
        )

        _report_progress(
            reporter=progress_reporter, message="Creating app-only service principal"
        )
        app_only_service_principal = graph_client.create_service_principal(
            app_id=app_only_application["appId"]
        )
        _report_progress(
            reporter=progress_reporter, message="App-only service principal created"
        )
        _report_progress(
            reporter=progress_reporter, message="Creating user service principal"
        )
        user_service_principal = graph_client.create_service_principal(
            app_id=user_application["appId"]
        )
        _report_progress(
            reporter=progress_reporter, message="User service principal created"
        )
        try:
            _report_progress(
                reporter=progress_reporter,
                message="Assigning current user as application owner",
            )
            current_user = graph_client.get_me()
            owner_id = current_user["id"]
            graph_client.add_application_owner(
                application_object_id=app_only_application["id"],
                owner_directory_object_id=owner_id,
            )
            graph_client.add_application_owner(
                application_object_id=user_application["id"],
                owner_directory_object_id=owner_id,
            )
            owner_assignment_status = (
                "Current authenticated user was added as an owner to both applications."
            )
            _report_progress(
                reporter=progress_reporter,
                message="Application owner assignment completed",
            )
        except Exception as exc:
            # Broad catch is intentional: owner assignment is a best-effort step.
            # Any failure must not prevent the created application from being returned.
            owner_assignment_status = (
                "Owner assignment was not completed automatically: " + str(exc)
            )
            _report_progress(
                reporter=progress_reporter,
                message="Application owner assignment could not be completed automatically",
            )

    app_only_required_resource_access = (
        build_app_only_required_resource_access_for_mode(
            sharepoint_access_mode=request.sharepoint_access_mode,
        )
    )
    user_required_resource_access = build_user_required_resource_access()

    if dry_run:
        app_only_permissions_configured = False
        user_permissions_configured = False
        admin_consent_status = (
            "Dry run only. No Azure permission or consent changes were applied."
        )
        admin_consent_instructions = "Dry run only. Review the planned output before re-running without --dry-run."
    else:
        _report_progress(
            reporter=progress_reporter,
            message="Configuring app-only application permissions",
        )
        graph_client.update_application_required_resource_access(
            application_object_id=app_only_application["id"],
            required_resource_access=app_only_required_resource_access,
        )
        app_only_permissions_configured = True
        _report_progress(
            reporter=progress_reporter,
            message="App-only application permissions configured",
        )
        _report_progress(
            reporter=progress_reporter,
            message="Configuring user application permissions",
        )
        graph_client.update_application_required_resource_access(
            application_object_id=user_application["id"],
            required_resource_access=user_required_resource_access,
        )
        user_permissions_configured = True
        _report_progress(
            reporter=progress_reporter,
            message="User application permissions configured",
        )

        _report_progress(
            reporter=progress_reporter, message="Attempting automatic admin consent"
        )
        admin_consent_succeeded, admin_consent_status = attempt_admin_consent(
            graph_client=graph_client,
            app_only_app_id=app_only_application["appId"],
            app_only_service_principal_id=app_only_service_principal["id"],
            required_resource_access=app_only_required_resource_access,
        )
        _report_progress(
            reporter=progress_reporter,
            message=(
                "Automatic admin consent completed"
                if admin_consent_succeeded
                else "Automatic admin consent needs manual follow-up"
            ),
        )
        admin_consent_instructions = (
            "Automatic admin consent completed for the application-role permissions."
            if admin_consent_succeeded
            else _build_manual_consent_instructions(
                app_only_app_id=app_only_application["appId"],
                user_app_id=user_application["appId"],
            )
        )

    _report_progress(
        reporter=progress_reporter, message="Evaluating delegated consent requirements"
    )
    delegated_consent_status, delegated_consent_instructions = (
        evaluate_delegated_consent(
            user_required_resource_access=user_required_resource_access,
            user_app_id=user_application["appId"],
            dry_run=dry_run,
        )
    )
    _report_progress(
        reporter=progress_reporter, message="Delegated consent evaluation completed"
    )

    selected_sharepoint_site_grant_results, helper_setup = (
        _build_selected_sharepoint_site_grant_results(
            request=request,
            graph_client=graph_client,
            app_only_application_id=app_only_application["appId"],
            app_only_application_display_name=plan.app_only_display_name,
            user_application_id=user_application["appId"],
            user_application_display_name=plan.user_display_name,
            helper_setup=helper_setup,
            dry_run=dry_run,
            reporter=progress_reporter,
        )
    )
    helper_app_cleanup_message = "No helper app cleanup was performed."
    if helper_setup is not None:
        cleanup_result = cleanup_helper_app_after_full_install(
            graph_client=graph_client,
            helper_setup=helper_setup,
            delete_created_helper_app=delete_created_helper_app,
            retain_local_helper_artifacts=retain_local_helper_artifacts,
            dry_run=dry_run,
            reporter=progress_reporter,
        )
        helper_app_cleanup_message = cleanup_result.message

    return FullInstallApplyResult(
        plan=plan,
        tenant_id=tenant_id,
        app_only_app_id=app_only_application["appId"],
        user_app_id=user_application["appId"],
        app_only_object_id=app_only_application["id"],
        user_object_id=user_application["id"],
        app_only_service_principal_id=app_only_service_principal["id"],
        user_service_principal_id=user_service_principal["id"],
        cert_path=str(cert_path),
        cer_file_path=str(cer_file_path),
        pfx_file_path=str(pfx_file_path),
        thumbprint=thumbprint,
        certificate_expiration=cert.not_valid_after_utc.isoformat(),
        top_level_web_url=top_level_web_url,
        home_default_site=home_default_site,
        default_document_library=default_document_library,
        certificate_password=request.password,
        app_only_permissions_configured=app_only_permissions_configured,
        user_permissions_configured=user_permissions_configured,
        admin_consent_status=admin_consent_status,
        admin_consent_instructions=admin_consent_instructions,
        dry_run=dry_run,
        owner_assignment_status=owner_assignment_status,
        delegated_consent_status=delegated_consent_status,
        delegated_consent_instructions=delegated_consent_instructions,
        sharepoint_access_mode=request.sharepoint_access_mode,
        selected_sharepoint_site_urls_requested=request.selected_sharepoint_site_urls
        or [],
        selected_sharepoint_site_grant_role=(
            "write" if request.sharepoint_access_mode == "selected-sites" else ""
        ),
        selected_sharepoint_site_grant_results=selected_sharepoint_site_grant_results,
        helper_app_cleanup_message=helper_app_cleanup_message,
    )


def apply_sso_install(
    *,
    request: SsoInstallRequest,
    graph_client: GraphClient,
    tenant: dict[str, Any],
    dry_run: bool = False,
    progress_reporter: ProgressReporter | None = None,
) -> SsoInstallApplyResult:
    """Create the Site SSO Azure application, service principal, and certificate artifacts."""
    tenant_id = tenant.get("id", "Unknown")
    tenant_domain = extract_default_tenant_domain(tenant)
    _report_progress(
        reporter=progress_reporter, message="Building Site SSO install plan"
    )
    plan = build_sso_install_plan(request=request, tenant_domain=tenant_domain)
    _report_progress(reporter=progress_reporter, message="Site SSO install plan ready")

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
    key_credential = build_graph_key_credential(cert=cert)
    _report_progress(
        reporter=progress_reporter, message="Certificate artifacts generated"
    )

    required_resource_access = build_sso_required_resource_access()

    if dry_run:
        application = {"id": "dry-run-sso-object-id", "appId": "dry-run-sso-app-id"}
        service_principal = {"id": "dry-run-sso-sp-id"}
        owner_assignment_status = "Dry run only. No owner assignment was applied."
        permissions_configured = False
    else:
        _report_progress(
            reporter=progress_reporter, message="Creating Site SSO Azure application"
        )
        application = graph_client.create_application(
            {
                "displayName": plan.display_name,
                "signInAudience": "AzureADMyOrg",
                "identifierUris": [plan.identifier_uri],
                "web": {
                    "homePageUrl": plan.redirect_uris[0],
                    "redirectUris": plan.redirect_uris,
                },
                "keyCredentials": [key_credential],
                "requiredResourceAccess": required_resource_access,
            }
        )
        _report_progress(
            reporter=progress_reporter,
            message="Creating Site SSO service principal",
        )
        service_principal = graph_client.create_service_principal(
            app_id=application["appId"]
        )
        _report_progress(
            reporter=progress_reporter,
            message="Loading current Azure CLI user for owner assignment",
        )
        try:
            current_user = graph_client.get_me()
            graph_client.add_application_owner(
                application_object_id=application["id"],
                owner_directory_object_id=current_user["id"],
            )
            owner_assignment_status = (
                "Current Azure CLI user was added as an application owner."
            )
        except Exception as exc:
            # Broad catch is intentional: owner assignment is a best-effort step.
            # Any failure must not prevent the created application from being returned.
            owner_assignment_status = (
                "Owner assignment was not completed automatically: " f"{exc}"
            )
        permissions_configured = True

    _report_progress(
        reporter=progress_reporter,
        message="Evaluating delegated consent requirements",
    )
    admin_consent_status, admin_consent_instructions = evaluate_delegated_consent(
        user_required_resource_access=required_resource_access,
        user_app_id=application["appId"],
        dry_run=dry_run,
    )
    _report_progress(
        reporter=progress_reporter,
        message="Delegated consent evaluation completed",
    )

    return SsoInstallApplyResult(
        plan=plan,
        tenant_id=tenant_id,
        app_id=application["appId"],
        object_id=application["id"],
        service_principal_id=service_principal["id"],
        cert_path=str(cert_path),
        cer_file_path=str(cer_file_path),
        pfx_file_path=str(pfx_file_path),
        thumbprint=thumbprint,
        certificate_expiration=cert.not_valid_after_utc.isoformat(),
        certificate_password=request.password,
        permissions_configured=permissions_configured,
        admin_consent_status=admin_consent_status,
        admin_consent_instructions=admin_consent_instructions,
        owner_assignment_status=owner_assignment_status,
        dry_run=dry_run,
    )
