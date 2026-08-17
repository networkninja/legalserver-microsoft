from dataclasses import dataclass
import base64
from datetime import datetime, timezone
from pathlib import Path
import os
import time
from typing import Any, Callable, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from legalserver_microsoft.certificates import (
    export_cer,
    export_pfx,
    generate_cert,
    get_thumbprint,
)
from legalserver_microsoft.graph_client import (
    ClientCertificateGraphAuthProvider,
    GraphClient,
    HelperAppAuthDiagnostics,
)
from legalserver_microsoft.models import SelectedSitesHelperAppConfig
from legalserver_microsoft.utils import generate_random_password, get_unique_file_path


@dataclass(frozen=True)
class HelperAppSetupResult:
    """Represents the resolved or created helper-app setup details."""

    create_new_helper_app: bool
    tenant_id: str
    authentication_method: str
    helper_app_client_id: str
    helper_app_object_id: str
    helper_service_principal_id: str
    helper_certificate_thumbprint: str
    helper_certificate_file_path: str
    helper_private_key_file_path: str
    helper_public_certificate_file_path: str
    helper_certificate_password: Optional[str]
    helper_permissions_configured: bool
    helper_owner_assignment_status: str
    helper_admin_consent_status: str
    created_in_this_run: bool
    local_helper_artifacts_created_in_this_run: bool


@dataclass(frozen=True)
class HelperAppCleanupResult:
    """Represents the outcome of an optional helper-app cleanup action."""

    attempted: bool
    deleted: bool
    local_artifacts_deleted: bool
    message: str


@dataclass(frozen=True)
class SelectedSitesGrantTarget:
    """Represents one LegalServer application that should receive site access."""

    application_id: str
    application_display_name: str
    target_label: str


@dataclass(frozen=True)
class SelectedSitesGrantAttemptResult:
    """Represents one per-site, per-target selected-sites grant attempt."""

    target_label: str
    application_id: str
    application_display_name: str
    action: str
    error_message: str


@dataclass(frozen=True)
class SelectedSitesGrantSiteResult:
    """Represents selected-sites grant results for one SharePoint site."""

    requested_url: str
    resolved_site_id: str
    resolved_web_url: str
    grant_role: str
    target_results: list[SelectedSitesGrantAttemptResult]


@dataclass(frozen=True)
class HelperAppValidationResult:
    """Represents the outcome of validating helper-app auth and site resolution."""

    diagnostics: HelperAppAuthDiagnostics
    requested_site_url: str
    token_acquisition_succeeded: bool
    site_resolution_succeeded: bool
    site_resolution_error: str
    resolved_site_id: str
    resolved_web_url: str


@dataclass(frozen=True)
class HelperAppReadinessResult:
    """Represents whether a newly created helper app is ready for site resolution."""

    ready: bool
    attempts: int
    last_error: str
    resolved_site_id: str
    resolved_web_url: str
    retryable_failure: bool


def verify_helper_app_graph_access(
    *,
    helper_graph_client: GraphClient,
    retry_delays_seconds: tuple[float, ...] = (0.0, 2.0, 5.0, 10.0),
) -> tuple[bool, str]:
    """Verify that the helper app can make the site-scoped Graph calls it needs."""
    last_error = ""
    attempts = len(retry_delays_seconds)
    for attempt_index, delay_seconds in enumerate(retry_delays_seconds, start=1):
        if delay_seconds > 0:
            time.sleep(delay_seconds)
        try:
            helper_graph_client.get_json("sites/root")
            return (
                True,
                "Helper app Microsoft Graph site-access preflight succeeded for selected-sites automation. "
                f"Attempts: {attempt_index}/{attempts}.",
            )
        except RuntimeError as exc:
            last_error = str(exc)

    return (
        False,
        "Helper app Microsoft Graph site-access preflight failed after retry/backoff. "
        "Grant tenant admin consent to the helper app Microsoft Graph site-management application permission, "
        "verify the certificate/private key, and confirm the new app registration has propagated. "
        f"Attempts: {attempts}. Original error: {last_error}",
    )


def verify_helper_app_graph_access_once(
    *, helper_graph_client: GraphClient
) -> tuple[bool, str]:
    """Verify helper-app Graph access without retry/backoff for focused tests."""
    return verify_helper_app_graph_access(
        helper_graph_client=helper_graph_client,
        retry_delays_seconds=(0.0,),
    )


def build_helper_app_required_resource_access() -> list[dict[str, Any]]:
    """Build the helper-app permissions needed for site-permission management."""
    return [
        {
            "resourceAppId": "00000003-0000-0000-c000-000000000000",
            "resourceAccess": [
                {
                    "id": "a82116e5-55eb-4c41-a434-62fe8a61c773",
                    "type": "Role",
                }
            ],
        }
    ]


def configure_helper_app_permissions(
    *,
    graph_client: GraphClient,
    helper_service_principal_id: str,
    required_resource_access: list[dict[str, Any]],
) -> bool:
    """Assign required application roles to the helper service principal."""
    for resource in required_resource_access:
        resource_app_id = resource.get("resourceAppId")
        if not resource_app_id:
            return False

        raw_resource_access = resource.get("resourceAccess")
        if not isinstance(raw_resource_access, list):
            return False

        role_accesses = [
            access
            for access in raw_resource_access
            if isinstance(access, dict) and access.get("type") == "Role"
        ]
        if not role_accesses:
            continue

        resource_service_principal = graph_client.get_service_principal_by_app_id(
            str(resource_app_id)
        )
        resource_service_principal_id = resource_service_principal.get("id")
        app_roles = resource_service_principal.get("appRoles", []) or []
        if not resource_service_principal_id or not isinstance(app_roles, list):
            return False

        for access in role_accesses:
            access_id = access.get("id")
            matching_role = next(
                (app_role for app_role in app_roles if app_role.get("id") == access_id),
                None,
            )
            matching_role_id = (
                None if matching_role is None else matching_role.get("id")
            )
            if not matching_role_id:
                return False

            try:
                graph_client.create_service_principal_app_role_assignment(
                    service_principal_id=helper_service_principal_id,
                    principal_id=helper_service_principal_id,
                    resource_id=str(resource_service_principal_id),
                    app_role_id=str(matching_role_id),
                )
            except RuntimeError as exc:
                # Broad string-match on the error message is intentional: Graph returns
                # HTTP 400 with this text when the role assignment already exists, which
                # is an acceptable idempotent outcome.
                error_text = str(exc)
                if (
                    "Permission being assigned already exists on the object"
                    in error_text
                ):
                    continue
                return False

    return True


def build_helper_app_create_payload(*, display_name: str) -> dict[str, Any]:
    """Build the Graph payload used to create the helper app registration."""
    return {
        "displayName": display_name,
        "signInAudience": "AzureADMyOrg",
        "requiredResourceAccess": build_helper_app_required_resource_access(),
    }


def build_graph_key_credential(*, cert: x509.Certificate) -> dict[str, Any]:
    """Build a Microsoft Graph key credential payload from a certificate."""
    certificate_bytes = cert.public_bytes(serialization.Encoding.DER)
    return {
        "type": "AsymmetricX509Cert",
        "usage": "Verify",
        "key": base64.b64encode(certificate_bytes).decode("ascii"),
        "displayName": f"LegalServer Certificate {datetime.now(timezone.utc).year}",
        "startDateTime": cert.not_valid_before_utc.isoformat().replace("+00:00", "Z"),
        "endDateTime": cert.not_valid_after_utc.isoformat().replace("+00:00", "Z"),
    }


def build_helper_app_certificate_paths(
    *, output_dir: Path, helper_app_display_name: str
) -> tuple[Path, Path]:
    """Build unique output paths for a generated helper-app certificate set."""
    cert_path = output_dir / "SharePoint_Certificates"
    cert_path.mkdir(parents=True, exist_ok=True)
    helper_base_name = helper_app_display_name.lower().replace(" ", "-")
    cer_file_path = get_unique_file_path(
        cert_path / f"{helper_base_name}_helper_cer.cer"
    )
    pfx_file_path = get_unique_file_path(
        cert_path / f"{helper_base_name}_helper_pfx.pfx"
    )
    return cer_file_path, pfx_file_path


def build_helper_app_graph_client(*, helper_setup: HelperAppSetupResult) -> GraphClient:
    """Build a Graph client authenticated as the helper application."""
    return GraphClient(
        auth_provider=ClientCertificateGraphAuthProvider(
            client_id=helper_setup.helper_app_client_id,
            tenant_id=helper_setup.tenant_id,
            certificate_path=helper_setup.helper_private_key_file_path,
            thumbprint=helper_setup.helper_certificate_thumbprint,
            certificate_password=helper_setup.helper_certificate_password,
        )
    )


def build_helper_app_auth_diagnostics(
    *, helper_setup: HelperAppSetupResult
) -> HelperAppAuthDiagnostics:
    """Return helper-app certificate-auth diagnostics without exposing secrets."""
    auth_provider = ClientCertificateGraphAuthProvider(
        client_id=helper_setup.helper_app_client_id,
        tenant_id=helper_setup.tenant_id,
        certificate_path=helper_setup.helper_private_key_file_path,
        thumbprint=helper_setup.helper_certificate_thumbprint,
        certificate_password=helper_setup.helper_certificate_password,
    )
    return auth_provider.build_diagnostics()


def validate_existing_helper_app_site_access(
    *, helper_setup: HelperAppSetupResult, requested_site_url: str
) -> HelperAppValidationResult:
    """Validate helper-app token acquisition and real Graph site resolution."""
    diagnostics = build_helper_app_auth_diagnostics(helper_setup=helper_setup)
    if not diagnostics.token_acquisition_succeeded:
        return HelperAppValidationResult(
            diagnostics=diagnostics,
            requested_site_url=requested_site_url,
            token_acquisition_succeeded=False,
            site_resolution_succeeded=False,
            site_resolution_error="",
            resolved_site_id="",
            resolved_web_url="",
        )

    helper_graph_client = build_helper_app_graph_client(helper_setup=helper_setup)
    try:
        resolved_site = helper_graph_client.resolve_sharepoint_site(
            site_url=requested_site_url
        )
    except RuntimeError as exc:
        return HelperAppValidationResult(
            diagnostics=diagnostics,
            requested_site_url=requested_site_url,
            token_acquisition_succeeded=True,
            site_resolution_succeeded=False,
            site_resolution_error=str(exc),
            resolved_site_id="",
            resolved_web_url="",
        )

    return HelperAppValidationResult(
        diagnostics=diagnostics,
        requested_site_url=requested_site_url,
        token_acquisition_succeeded=True,
        site_resolution_succeeded=True,
        site_resolution_error="",
        resolved_site_id=str(resolved_site.get("id", "")),
        resolved_web_url=str(resolved_site.get("webUrl") or requested_site_url),
    )


def wait_for_helper_app_site_resolution_readiness(
    *,
    helper_setup: HelperAppSetupResult,
    requested_site_url: str,
    retry_delays_seconds: tuple[float, ...],
    progress_reporter: Callable[[str], None] | None = None,
) -> HelperAppReadinessResult:
    """Wait for a helper app to succeed at the real Graph site-resolution call."""
    helper_graph_client = build_helper_app_graph_client(helper_setup=helper_setup)
    last_error = ""
    total_attempts = len(retry_delays_seconds)

    for attempt_index, delay_seconds in enumerate(retry_delays_seconds, start=1):
        if progress_reporter is not None:
            progress_reporter(
                f"Helper app propagation check {attempt_index}/{total_attempts} for {requested_site_url}"
            )
        if delay_seconds > 0:
            time.sleep(delay_seconds)
        try:
            resolved_site = helper_graph_client.resolve_sharepoint_site(
                site_url=requested_site_url
            )
            return HelperAppReadinessResult(
                ready=True,
                attempts=attempt_index,
                last_error="",
                resolved_site_id=str(resolved_site.get("id", "")),
                resolved_web_url=str(resolved_site.get("webUrl") or requested_site_url),
                retryable_failure=False,
            )
        except RuntimeError as exc:
            last_error = str(exc)
            non_retryable_error = (
                "Failed to load helper certificate PKCS#12 file" in last_error
                or "Helper certificate PKCS#12 file did not contain a private key"
                in last_error
                or "Failed to read helper certificate private key file" in last_error
                or "Failed to read helper certificate PKCS#12 file" in last_error
            )
            if progress_reporter is not None:
                if non_retryable_error:
                    progress_reporter(
                        "Helper app propagation check "
                        f"{attempt_index}/{total_attempts} failed with a non-retryable helper authentication error: {last_error}."
                    )
                elif attempt_index < total_attempts:
                    next_delay_seconds = retry_delays_seconds[attempt_index]
                    progress_reporter(
                        "Helper app propagation check "
                        f"{attempt_index}/{total_attempts} failed: {last_error}. "
                        f"Next retry in {int(next_delay_seconds)} second(s)."
                    )
                else:
                    progress_reporter(
                        "Helper app propagation check "
                        f"{attempt_index}/{total_attempts} failed: {last_error}. "
                        "No retries remain."
                    )
            if non_retryable_error:
                return HelperAppReadinessResult(
                    ready=False,
                    attempts=attempt_index,
                    last_error=last_error,
                    resolved_site_id="",
                    resolved_web_url="",
                    retryable_failure=False,
                )

    return HelperAppReadinessResult(
        ready=False,
        attempts=total_attempts,
        last_error=last_error,
        resolved_site_id="",
        resolved_web_url="",
        retryable_failure=True,
    )


def build_helper_app_detail_messages(
    *,
    helper_setup: HelperAppSetupResult,
    created_new_helper_app: bool | None = None,
    retain_local_helper_artifacts: bool | None = None,
) -> list[str]:
    """Build copy-friendly helper-app detail lines for reporting and reuse."""
    create_new_helper_app = (
        created_new_helper_app
        if created_new_helper_app is not None
        else getattr(helper_setup, "create_new_helper_app", None)
    )
    private_key_status = (
        "Generated for this run"
        if create_new_helper_app is True
        else (
            "Existing private key material provided"
            if create_new_helper_app is False
            else (
                "Existing private key material provided"
                if helper_setup.helper_private_key_file_path
                == helper_setup.helper_certificate_file_path
                else "Generated for this run"
            )
        )
    )
    if create_new_helper_app is True and retain_local_helper_artifacts is False:
        private_key_status = (
            "Generated for this run and removed after workflow completion"
        )
    elif create_new_helper_app is True and retain_local_helper_artifacts is True:
        private_key_status = "Maintained for helper-app reuse"
    helper_certificate_status = (
        "Retained for helper-app reuse"
        if create_new_helper_app is True and retain_local_helper_artifacts is True
        else (
            "Temporary helper artifacts were not retained"
            if create_new_helper_app is True and retain_local_helper_artifacts is False
            else (
                "Generated for this run"
                if create_new_helper_app is True
                else "Existing helper certificate material used"
            )
        )
    )
    return [
        f"Helper App Client ID: {helper_setup.helper_app_client_id}",
        f"Helper App Object ID: {helper_setup.helper_app_object_id}",
        ("Helper Service Principal ID: " f"{helper_setup.helper_service_principal_id}"),
        (
            "Helper Certificate Thumbprint: "
            f"{helper_setup.helper_certificate_thumbprint}"
        ),
        f"Helper Private Key: {private_key_status}",
        f"Helper Certificate Artifacts: {helper_certificate_status}",
    ]


def _delete_file_if_present(*, file_path: str) -> bool:
    """Delete one generated helper-artifact file when it exists."""
    if not file_path:
        return False
    try:
        os.remove(file_path)
    except FileNotFoundError:
        return False
    return True


def cleanup_local_helper_artifacts(
    *,
    helper_setup: HelperAppSetupResult,
    retain_local_helper_artifacts: bool,
    dry_run: bool,
) -> tuple[bool, str]:
    """Delete generated local helper artifacts unless the operator chose retention."""
    if not helper_setup.local_helper_artifacts_created_in_this_run:
        return False, "No local helper credential artifacts were created in this run."
    if retain_local_helper_artifacts:
        return (
            False,
            "Local helper credential artifacts were retained for future reuse.",
        )
    if dry_run:
        return (
            False,
            "Dry run only. Local helper credential artifact cleanup was not applied.",
        )

    deleted_any = False
    deleted_any = (
        _delete_file_if_present(file_path=helper_setup.helper_certificate_file_path)
        or deleted_any
    )
    deleted_any = (
        _delete_file_if_present(
            file_path=helper_setup.helper_public_certificate_file_path
        )
        or deleted_any
    )
    deleted_any = (
        _delete_file_if_present(file_path=helper_setup.helper_private_key_file_path)
        or deleted_any
    )
    if deleted_any:
        return (
            True,
            "Temporary local helper credential artifacts were removed after workflow completion.",
        )
    return (
        False,
        "Local helper credential artifacts were already absent at workflow completion.",
    )


def describe_selected_sites_grant_error(*, error: Exception) -> str:
    """Build an operator-facing selected-sites grant error message."""
    return (
        "Helper app authentication or Microsoft Graph site-permission grant failed. "
        "Verify the helper app tenant ID, certificate/private key, and granted Graph "
        f"application permissions. Original error: {error}"
    )


def setup_selected_sites_helper_app(
    *,
    config: SelectedSitesHelperAppConfig,
    graph_client: GraphClient,
    helper_app_display_name: str,
    output_dir: Path,
    dry_run: bool = False,
) -> HelperAppSetupResult:
    """Create or load the helper app used for selected-sites grant automation."""
    if dry_run:
        return HelperAppSetupResult(
            create_new_helper_app=config.create_new_helper_app,
            tenant_id=config.tenant_id,
            authentication_method=config.authentication_method,
            helper_app_client_id=(
                "dry-run-helper-app-id"
                if config.create_new_helper_app
                else config.existing_helper_app_client_id
            ),
            helper_app_object_id="dry-run-helper-object-id",
            helper_service_principal_id="dry-run-helper-sp-id",
            helper_certificate_thumbprint=config.helper_certificate_thumbprint,
            helper_certificate_file_path=config.helper_certificate_file_path,
            helper_private_key_file_path=config.helper_certificate_file_path,
            helper_public_certificate_file_path=config.helper_certificate_file_path,
            helper_certificate_password=None,
            helper_permissions_configured=False,
            helper_owner_assignment_status=(
                "Dry run only. No helper app owner assignment was applied."
            ),
            helper_admin_consent_status=(
                "Dry run only. No helper app permission or consent changes were applied."
            ),
            created_in_this_run=False,
            local_helper_artifacts_created_in_this_run=False,
        )

    if config.create_new_helper_app:
        helper_certificate_password = generate_random_password()
        helper_key, helper_cert = generate_cert(helper_app_display_name, 1)
        cer_file_path, pfx_file_path = build_helper_app_certificate_paths(
            output_dir=output_dir,
            helper_app_display_name=helper_app_display_name,
        )
        export_cer(cert=helper_cert, path=cer_file_path)
        export_pfx(
            key=helper_key,
            cert=helper_cert,
            password=helper_certificate_password,
            path=pfx_file_path,
        )
        helper_thumbprint = get_thumbprint(helper_cert)
        application = graph_client.create_application(
            {
                **build_helper_app_create_payload(display_name=helper_app_display_name),
                "keyCredentials": [build_graph_key_credential(cert=helper_cert)],
            }
        )
        service_principal = graph_client.create_service_principal(
            app_id=str(application["appId"])
        )
        try:
            current_user = graph_client.get_me()
            owner_id = str(current_user["id"])
            graph_client.add_application_owner(
                application_object_id=str(application["id"]),
                owner_directory_object_id=owner_id,
            )
            helper_owner_assignment_status = "Current authenticated user was added as an owner to the helper application."
        except Exception as exc:
            # Broad catch is intentional: owner assignment is a best-effort step.
            # Any failure must not block the main helper-app creation workflow.
            helper_owner_assignment_status = (
                "Helper app owner assignment was not completed automatically: "
                + str(exc)
            )
        helper_permissions_configured = configure_helper_app_permissions(
            graph_client=graph_client,
            helper_service_principal_id=str(service_principal["id"]),
            required_resource_access=build_helper_app_required_resource_access(),
        )
        graph_client.update_application_required_resource_access(
            application_object_id=str(application["id"]),
            required_resource_access=build_helper_app_required_resource_access(),
        )
        return HelperAppSetupResult(
            create_new_helper_app=True,
            tenant_id=config.tenant_id,
            authentication_method=config.authentication_method,
            helper_app_client_id=str(application["appId"]),
            helper_app_object_id=str(application["id"]),
            helper_service_principal_id=str(service_principal["id"]),
            helper_certificate_thumbprint=helper_thumbprint,
            helper_certificate_file_path=str(pfx_file_path),
            helper_private_key_file_path=str(pfx_file_path),
            helper_public_certificate_file_path=str(cer_file_path),
            helper_certificate_password=helper_certificate_password,
            helper_permissions_configured=helper_permissions_configured,
            helper_owner_assignment_status=helper_owner_assignment_status,
            helper_admin_consent_status=(
                "Automatic helper-app admin consent succeeded for Microsoft Graph application permissions."
                if helper_permissions_configured
                else "Automatic helper-app admin consent was not fully completed. Grant tenant admin consent to the helper app Microsoft Graph Sites.FullControl.All application permission before selected-sites grants can succeed."
            ),
            created_in_this_run=True,
            local_helper_artifacts_created_in_this_run=True,
        )

    application = graph_client.get_application_by_app_id(
        config.existing_helper_app_client_id
    )
    service_principal = graph_client.get_service_principal_by_app_id(
        config.existing_helper_app_client_id
    )
    helper_permissions_configured = configure_helper_app_permissions(
        graph_client=graph_client,
        helper_service_principal_id=str(service_principal["id"]),
        required_resource_access=build_helper_app_required_resource_access(),
    )
    return HelperAppSetupResult(
        create_new_helper_app=False,
        tenant_id=config.tenant_id,
        authentication_method=config.authentication_method,
        helper_app_client_id=config.existing_helper_app_client_id,
        helper_app_object_id=str(application["id"]),
        helper_service_principal_id=str(service_principal["id"]),
        helper_certificate_thumbprint=config.helper_certificate_thumbprint,
        helper_certificate_file_path=config.helper_certificate_file_path,
        helper_private_key_file_path=config.helper_certificate_file_path,
        helper_public_certificate_file_path=config.helper_certificate_file_path,
        helper_certificate_password=None,
        helper_permissions_configured=helper_permissions_configured,
        helper_owner_assignment_status=(
            "Existing helper app reuse does not change helper app ownership automatically."
        ),
        helper_admin_consent_status=(
            "Automatic helper-app admin consent succeeded for Microsoft Graph application permissions."
            if helper_permissions_configured
            else "Automatic helper-app admin consent was not fully completed. Grant tenant admin consent to the helper app Microsoft Graph Sites.FullControl.All application permission before selected-sites grants can succeed."
        ),
        created_in_this_run=False,
        local_helper_artifacts_created_in_this_run=False,
    )


def cleanup_selected_sites_helper_app(
    *,
    graph_client: GraphClient,
    helper_setup: HelperAppSetupResult,
    delete_created_helper_app: bool,
    retain_local_helper_artifacts: bool,
    dry_run: bool = False,
) -> HelperAppCleanupResult:
    """Delete a helper app created in the current run when the operator chooses cleanup."""
    if not helper_setup.created_in_this_run:
        return HelperAppCleanupResult(
            attempted=False,
            deleted=False,
            local_artifacts_deleted=False,
            message="Helper app was reused and was not eligible for automatic cleanup.",
        )
    if not delete_created_helper_app:
        local_artifacts_deleted, local_artifact_message = (
            cleanup_local_helper_artifacts(
                helper_setup=helper_setup,
                retain_local_helper_artifacts=retain_local_helper_artifacts,
                dry_run=dry_run,
            )
        )
        return HelperAppCleanupResult(
            attempted=False,
            deleted=False,
            local_artifacts_deleted=local_artifacts_deleted,
            message=(
                "Helper app was created in this run and kept for future reuse. "
                + local_artifact_message
            ),
        )
    if dry_run:
        return HelperAppCleanupResult(
            attempted=True,
            deleted=False,
            local_artifacts_deleted=False,
            message="Dry run only. Helper app cleanup was not applied.",
        )

    graph_client.delete_application(
        application_object_id=helper_setup.helper_app_object_id
    )
    local_artifacts_deleted, local_artifact_message = cleanup_local_helper_artifacts(
        helper_setup=helper_setup,
        retain_local_helper_artifacts=retain_local_helper_artifacts,
        dry_run=dry_run,
    )
    return HelperAppCleanupResult(
        attempted=True,
        deleted=True,
        local_artifacts_deleted=local_artifacts_deleted,
        message=(
            "Helper app created during this run was deleted after selected-sites grant processing. "
            + local_artifact_message
        ),
    )


def grant_selected_sites_to_targets(
    *,
    graph_client: GraphClient,
    requested_site_url: str,
    grant_targets: list[SelectedSitesGrantTarget],
    dry_run: bool = False,
) -> SelectedSitesGrantSiteResult:
    """Grant selected-site access to each target application for one site."""
    if dry_run:
        return SelectedSitesGrantSiteResult(
            requested_url=requested_site_url,
            resolved_site_id="",
            resolved_web_url=requested_site_url,
            grant_role="write",
            target_results=[
                SelectedSitesGrantAttemptResult(
                    target_label=target.target_label,
                    application_id=target.application_id,
                    application_display_name=target.application_display_name,
                    action="would grant",
                    error_message="",
                )
                for target in grant_targets
            ],
        )

    resolved_site = graph_client.resolve_sharepoint_site(site_url=requested_site_url)
    resolved_site_id = str(resolved_site.get("id", ""))
    resolved_web_url = str(resolved_site.get("webUrl") or requested_site_url)
    target_results: list[SelectedSitesGrantAttemptResult] = []

    for target in grant_targets:
        try:
            graph_client.grant_application_to_sharepoint_site(
                site_id=resolved_site_id,
                application_id=target.application_id,
                application_display_name=target.application_display_name,
                role="write",
            )
            target_results.append(
                SelectedSitesGrantAttemptResult(
                    target_label=target.target_label,
                    application_id=target.application_id,
                    application_display_name=target.application_display_name,
                    action="granted",
                    error_message="",
                )
            )
        except RuntimeError as exc:
            target_results.append(
                SelectedSitesGrantAttemptResult(
                    target_label=target.target_label,
                    application_id=target.application_id,
                    application_display_name=target.application_display_name,
                    action="failed",
                    error_message=str(exc),
                )
            )

    return SelectedSitesGrantSiteResult(
        requested_url=requested_site_url,
        resolved_site_id=resolved_site_id,
        resolved_web_url=resolved_web_url,
        grant_role="write",
        target_results=target_results,
    )
