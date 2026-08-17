import sys
from argparse import Namespace
from pathlib import Path
from typing import Callable, Optional, TextIO

from legalserver_microsoft.azure_cli_auth import (
    AzureCliContext,
    inspect_azure_cli_session,
    run_azure_cli_login,
)

from legalserver_microsoft.certificates import (
    build_terminal_manual_summary,
    redact_file_path_for_report,
    redact_secret,
    run_manual_certificate_workflow,
)
from legalserver_microsoft.helper_app import (
    HelperAppSetupResult,
    build_helper_app_auth_diagnostics,
    validate_existing_helper_app_site_access,
)
from legalserver_microsoft.cli import (
    ExistingInstallBuildResult,
    ExistingSsoInstallBuildResult,
    FullInstallBuildResult,
    InteractivePrompts,
    SsoInstallBuildResult,
    build_existing_install_request,
    build_existing_sso_install_request,
    build_full_install_request,
    build_interactive_request,
    build_sso_install_request,
    default_prompts,
    parse_args,
    prompt_mode_selection,
    render_welcome,
)
from legalserver_microsoft.models import (
    ExistingInstallRequest,
    FullInstallRequest,
    SelectedSitesHelperAppConfig,
)
from legalserver_microsoft.full_install import apply_full_install, apply_sso_install
from legalserver_microsoft.full_install import FullInstallApplyResult
from legalserver_microsoft.full_install import SsoInstallApplyResult
from legalserver_microsoft.graph_client import (
    AzureCliGraphAuthProvider,
    GraphAuthProvider,
    GraphClient,
)
from legalserver_microsoft.reporting import (
    build_full_install_report,
    build_manual_report,
    build_operator_handoff_report,
    build_report_path,
    build_sso_install_report,
    build_update_existing_report,
    write_report,
)
from legalserver_microsoft.update_existing import (
    ExistingInstallApplyResult,
    ExistingSsoInstallApplyResult,
    apply_existing_install_updates,
    apply_existing_sso_install_updates,
)
from legalserver_microsoft.models import SelectedSitesHelperAppConfig


def _get_repo_root() -> Path:
    """Return the repository root path for output-location warnings."""
    return Path(__file__).resolve().parents[1]


def _is_within_directory(*, path: Path, directory: Path) -> bool:
    """Return whether a path resolves inside the given directory."""
    try:
        path.resolve().relative_to(directory.resolve())
    except ValueError:
        return False
    return True


def _warn_if_output_dir_is_repo_local(*, output_dir: Path, output: TextIO) -> None:
    """Warn when generated artifacts will be written inside the repository workspace."""
    if not _is_within_directory(path=output_dir, directory=_get_repo_root()):
        return
    print(
        "Warning: Output is being written inside the repository workspace.",
        file=output,
    )
    print(
        "Generated certificates and reports are sensitive operational artifacts and should not be committed or shared like source files.",
        file=output,
    )
    print(file=output)


def _build_mode_confirmation(*, mode: str) -> str:
    """Build a simple operator-facing confirmation for the chosen workflow."""
    labels = {
        "certificate-only": "Generate certificates only",
        "update-existing-sharepoint": "Update existing SharePoint apps",
        "update-existing-sso": "Update the existing SSO application",
        "full-sharepoint-install": "Perform a full SharePoint install",
        "full-sso-install": "Perform a full SSO install",
        "validate-selected-sites-helper": "Validate selected-sites helper app",
    }
    return f"Selected workflow: {labels.get(mode, mode)}"


def _build_helper_validation_summary(
    *,
    helper_setup: HelperAppSetupResult,
    requested_site_url: str,
    persist_output: bool = False,
) -> str:
    """Build a focused helper-app validation summary."""
    validation = validate_existing_helper_app_site_access(
        helper_setup=helper_setup,
        requested_site_url=requested_site_url,
    )
    diagnostics = validation.diagnostics
    private_key_display = (
        redact_file_path_for_report(file_path=helper_setup.helper_private_key_file_path)
        if persist_output
        else helper_setup.helper_private_key_file_path
    )
    summary_lines = [
        "",
        "===== SELECTED-SITES HELPER VALIDATION =====",
        f"Helper App Client ID: {helper_setup.helper_app_client_id}",
        f"Tenant ID: {helper_setup.tenant_id}",
        f"Authority: {diagnostics.authority}",
        f"Thumbprint: {diagnostics.thumbprint}",
        f"Private Key Path: {private_key_display}",
        f"Requested Site URL: {requested_site_url}",
        "Token Acquisition:",
        "  - Result: "
        + ("Succeeded" if validation.token_acquisition_succeeded else "Failed"),
    ]
    if diagnostics.auth_diagnostic_message:
        summary_lines.append(f"  - Error: {diagnostics.auth_diagnostic_message}")
    summary_lines.extend(
        [
            "Site Resolution:",
            "  - Result: "
            + (
                "Succeeded"
                if validation.site_resolution_succeeded
                else (
                    "Not attempted"
                    if not validation.token_acquisition_succeeded
                    else "Failed"
                )
            ),
        ]
    )
    if validation.resolved_site_id:
        summary_lines.append(f"  - Resolved Site ID: {validation.resolved_site_id}")
    if validation.resolved_web_url:
        summary_lines.append(f"  - Resolved Web URL: {validation.resolved_web_url}")
    if validation.site_resolution_error:
        summary_lines.append(f"  - Error: {validation.site_resolution_error}")
    summary_lines.append("============================================")
    return "\n".join(summary_lines)


def _run_validate_selected_sites_helper_workflow(
    *, args: Namespace, output: TextIO
) -> str:
    """Run focused validation against an existing selected-sites helper app."""
    required_values = {
        "--helper-app-client-id": args.helper_app_client_id,
        "--helper-tenant-id": args.helper_tenant_id,
        "--helper-certificate-path": args.helper_certificate_path,
        "--helper-thumbprint": args.helper_thumbprint,
        "--selected-site-url": args.selected_site_url,
    }
    missing_flags = [flag for flag, value in required_values.items() if not value]
    if missing_flags:
        raise RuntimeError(
            "Selected-sites helper validation requires: " + ", ".join(missing_flags)
        )

    helper_setup = HelperAppSetupResult(
        create_new_helper_app=False,
        tenant_id=str(args.helper_tenant_id),
        authentication_method="file-path",
        helper_app_client_id=str(args.helper_app_client_id),
        helper_app_object_id="validation-only",
        helper_service_principal_id="validation-only",
        helper_certificate_thumbprint=str(args.helper_thumbprint),
        helper_certificate_file_path=str(args.helper_certificate_path),
        helper_private_key_file_path=str(args.helper_certificate_path),
        helper_public_certificate_file_path=str(args.helper_certificate_path),
        helper_certificate_password=None,
        helper_permissions_configured=True,
        helper_owner_assignment_status="Validation-only helper setup.",
        helper_admin_consent_status="Validation-only helper setup.",
        created_in_this_run=False,
        local_helper_artifacts_created_in_this_run=False,
    )
    diagnostics = build_helper_app_auth_diagnostics(helper_setup=helper_setup)
    print(
        "Helper auth diagnostics prepared for "
        f"client {diagnostics.client_id} using authority {diagnostics.authority}.",
        file=output,
    )
    return _build_helper_validation_summary(
        helper_setup=helper_setup,
        requested_site_url=str(args.selected_site_url),
    )


def _format_azure_cli_context(*, context: AzureCliContext) -> str:
    """Build operator-facing Azure CLI session details."""
    return "\n".join(
        [
            "Azure CLI session details:",
            f"User: {context.username}",
            f"Tenant ID: {context.tenant_id}",
            f"Tenant: {context.tenant_name}",
            f"Subscription: {context.subscription_name}",
            f"Subscription ID: {context.subscription_id}",
            f"Environment: {context.environment_name}",
        ]
    )


def _prompt_yes_no(*, prompt_text: str, output: TextIO, default: bool) -> bool:
    """Prompt for a yes or no answer using standard terminal input."""
    default_label = "Y/n" if default else "y/N"
    while True:
        response = input(f"{prompt_text} [{default_label}]: ").strip().lower()
        if not response:
            return default
        if response in {"y", "yes"}:
            return True
        if response in {"n", "no"}:
            return False
        print("Please answer yes or no.", file=output)


def _confirm_azure_cli_session(*, context: AzureCliContext, output: TextIO) -> bool:
    """Show Azure CLI session details and ask the operator to confirm them."""
    print(file=output)
    print(_format_azure_cli_context(context=context), file=output)
    return _prompt_yes_no(
        prompt_text="Use this Azure CLI session?",
        output=output,
        default=True,
    )


def _print_step(*, output: TextIO, message: str) -> None:
    """Print a concise operator-facing workflow progress message."""
    print(f"[Step] {message}", file=output)


def _print_step_result(*, output: TextIO, message: str) -> None:
    """Print a concise operator-facing workflow completion message."""
    print(f"[Done] {message}", file=output)


def _warn_if_sensitive_file_permissions_not_applied(
    *, file_path: Path | str, output: TextIO
) -> None:
    """Warn when chmod-based hardening could not be applied to a sensitive file."""
    print(
        "Warning: Could not apply owner-only file permissions to " f"{file_path}.",
        file=output,
    )
    print(
        "This can happen on mounted filesystems, including Windows host volumes used from a container.",
        file=output,
    )
    print(
        "Verify the generated artifact is stored in a location with appropriate access controls.",
        file=output,
    )


def _build_progress_reporter(*, output: TextIO) -> Callable[[str], None]:
    """Build a per-operation progress reporter for long-running workflow steps."""

    def report(message: str) -> None:
        print(f"  - {message}", file=output)

    return report


def _build_portal_app_consent_url(*, app_id: str) -> str:
    """Build the Azure portal app registration consent/configuration URL."""
    return (
        "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/"
        f"ApplicationMenuBlade/~/CallAnAPI/appId/{app_id}/isMSAApp~/false"
    )


def _describe_sharepoint_access_mode(*, access_mode: str) -> str:
    """Build an operator-facing SharePoint access mode description."""
    if access_mode == "selected-sites":
        return "Selected sites only (Sites.Selected)"
    return "Broad tenant-wide SharePoint access"


def _has_failed_selected_site_grants(
    *, selected_site_results: list[dict[str, str]]
) -> bool:
    """Return whether any selected-site grant result ended in failure."""
    return any(result.get("action") == "failed" for result in selected_site_results)


def _build_selected_sites_follow_up_lines(
    *, selected_site_results: list[dict[str, str]]
) -> list[str]:
    """Build operator guidance for partial selected-sites grant failures."""
    if not _has_failed_selected_site_grants(
        selected_site_results=selected_site_results
    ):
        return []

    return [
        "Selected-sites follow-up:",
        "  - Azure application creation and permission configuration completed, but one or more selected SharePoint site grants failed.",
        "  - The generated app IDs, certificate files, helper-app setup values, and saved report remain valid and should be preserved.",
        "  - The current automatic grant path now uses a helper Azure application with direct Microsoft Graph site-permission calls.",
        "  - Additional privileged follow-up is still required before both LegalServer SharePoint applications will have access to every requested selected site.",
    ]


def _prompt_helper_app_cleanup_if_needed(
    *, created_in_this_run: bool, output: TextIO
) -> bool:
    """Prompt whether to delete a helper app created during the current run."""
    if not created_in_this_run:
        return False
    print(
        "Selected-sites helper-app credentials carry high-privilege tenant access for this workflow.",
        file=output,
    )
    return _prompt_yes_no(
        prompt_text=(
            "Delete the helper app that was created during this workflow after grant processing completes?"
        ),
        output=output,
        default=True,
    )


def _prompt_local_helper_artifact_retention_if_needed(
    *, created_in_this_run: bool, delete_created_helper_app: bool, output: TextIO
) -> bool:
    """Prompt whether to retain local helper credential artifacts for reuse."""
    if not created_in_this_run or delete_created_helper_app:
        return False
    print(
        "Retaining helper credential artifacts keeps a high-privilege reusable credential on disk.",
        file=output,
    )
    return _prompt_yes_no(
        prompt_text=(
            "Retain local helper credential artifacts for future reuse after grant processing completes?"
        ),
        output=output,
        default=False,
    )


def _apply_helper_app_tenant_id(
    *,
    helper_config: SelectedSitesHelperAppConfig | None,
    tenant_id: str,
) -> SelectedSitesHelperAppConfig | None:
    """Return helper-app config with tenant ID sourced from the approved Azure CLI session."""
    if helper_config is None:
        return None
    return SelectedSitesHelperAppConfig(
        create_new_helper_app=helper_config.create_new_helper_app,
        tenant_id=tenant_id,
        authentication_method=helper_config.authentication_method,
        existing_helper_app_client_id=helper_config.existing_helper_app_client_id,
        helper_certificate_thumbprint=helper_config.helper_certificate_thumbprint,
        helper_certificate_file_path=helper_config.helper_certificate_file_path,
    )


def _selected_sites_will_create_helper_app(
    *, access_mode: str, create_new: bool
) -> bool:
    """Return whether the selected-sites workflow will create a new helper app."""
    return access_mode == "selected-sites" and create_new


def _build_full_install_summary(
    *,
    build_result: FullInstallBuildResult,
    apply_result: FullInstallApplyResult,
    show_full_password: bool,
) -> str:
    """Build the grouped full SharePoint install summary for terminal or persisted output."""
    consent_url = _build_portal_app_consent_url(app_id=apply_result.user_app_id)
    certificate_password = (
        apply_result.certificate_password
        if show_full_password
        else redact_secret(value=apply_result.certificate_password)
    )
    delegated_instruction_lines = (
        apply_result.delegated_consent_instructions.splitlines()
    )
    selected_site_results = apply_result.selected_sharepoint_site_grant_results
    access_mode_description = _describe_sharepoint_access_mode(
        access_mode=apply_result.sharepoint_access_mode
    )
    cer_file_display = (
        apply_result.cer_file_path
        if show_full_password
        else redact_file_path_for_report(file_path=apply_result.cer_file_path)
    )
    pfx_file_display = (
        apply_result.pfx_file_path
        if show_full_password
        else redact_file_path_for_report(file_path=apply_result.pfx_file_path)
    )
    summary_lines = [
        "",
        "===== FULL SHAREPOINT INSTALL =====",
        f"LegalServer Site: {build_result.request.ls_site}",
        f"Site Type: {apply_result.plan.site_type}",
        f"Tenant ID: {apply_result.tenant_id}",
        f"SharePoint Base URL: {apply_result.top_level_web_url}",
        f"Default SharePoint Site: {apply_result.home_default_site}",
        f"Default SharePoint Library: {apply_result.default_document_library}",
        "Azure CLI authentication succeeded.",
        "Azure Applications:",
        f"  - App-Only Application: {apply_result.plan.app_only_display_name}",
        f"  - App-Only App ID: {apply_result.app_only_app_id}",
        f"  - User Application: {apply_result.plan.user_display_name}",
        f"  - User App ID: {apply_result.user_app_id}",
        f"  - User App Consent URL: {consent_url}",
        f"  - App-Only Permissions Configured: {apply_result.app_only_permissions_configured}",
        f"  - User Permissions Configured: {apply_result.user_permissions_configured}",
        f"  - Owner Assignment Status: {apply_result.owner_assignment_status}",
        (
            "  - Dry run only. No Azure applications or permission changes were applied."
            if apply_result.dry_run
            else "  - Azure applications and service principals were created through Microsoft Graph."
        ),
        f"  - Redirect URIs: {', '.join(apply_result.plan.redirect_uris)}",
        f"  - SharePoint Access Mode: {access_mode_description}",
        "Certificate:",
        f"  - Certificate Thumbprint: {apply_result.thumbprint}",
        f"  - CER File: {cer_file_display}",
        f"  - PFX File: {pfx_file_display}",
        f"  - Certificate Password: {certificate_password}",
        "Consent:",
        f"  - Admin Consent Status: {apply_result.admin_consent_status}",
        f"  - Admin Consent Instructions: {apply_result.admin_consent_instructions}",
        f"  - Delegated Consent Status: {apply_result.delegated_consent_status}",
    ]
    if delegated_instruction_lines:
        summary_lines.append(
            f"  - Delegated Consent Instructions: {delegated_instruction_lines[0]}"
        )
        for line in delegated_instruction_lines[1:]:
            summary_lines.append(f"  - {line}")
    else:
        summary_lines.append("  - Delegated Consent Instructions: None")
    summary_lines.append(f"  - User App Consent URL: {consent_url}")
    if apply_result.sharepoint_access_mode == "selected-sites":
        summary_lines.append("Selected SharePoint Sites:")
        summary_lines.append(
            "  - Requested Sites: "
            + (
                ", ".join(apply_result.selected_sharepoint_site_urls_requested)
                if apply_result.selected_sharepoint_site_urls_requested
                else "None"
            )
        )
        summary_lines.append(
            f"  - Grant Role: {apply_result.selected_sharepoint_site_grant_role}"
        )
        summary_lines.append(
            "  - Target Applications: App-only SharePoint app and user-auth SharePoint app"
        )
        if selected_site_results:
            for site_result in selected_site_results:
                requested_url = site_result.get("requested_url", "")
                action = site_result.get("action", "")
                resolved_web_url = site_result.get("resolved_web_url", "")
                target_label = site_result.get("target_label", "")
                details = resolved_web_url or requested_url
                if target_label:
                    details = f"{details} ({target_label})"
                summary_lines.append(f"  - {action.title()}: {details}")
                error_message = site_result.get("error_message", "")
                if error_message:
                    summary_lines.append(f"    Error: {error_message}")
        else:
            summary_lines.append("  - Requested Sites: None")
        summary_lines.extend(
            _build_selected_sites_follow_up_lines(
                selected_site_results=selected_site_results
            )
        )
        summary_lines.append(
            f"  - Helper App Cleanup: {apply_result.helper_app_cleanup_message}"
        )
    summary_lines.extend(
        [
            "",
            "Next Steps:",
            f"1. Approve the User App Consent at the URL provided: {consent_url}",
            "2. Use the exported .cer and .pfx files to configure the Microsoft Azure integration in LegalServer.",
            "3. Navigate to Admin -> SharePoint Settings in LegalServer.",
            "4. Enter the User App ID, App-Only App ID, Tenant ID, SharePoint base URL, default SharePoint Site and Library.",
            "5. Enter the Public Certificate (.cer) and Private Key (.pfx) along with the password when prompted.",
            f"6. Confirm the thumbprint matches {apply_result.thumbprint}.",
            "7. Inform LegalServer Support that the integration configuration has been completed and you are ready for full enablement of the Save in SharePoint Features.",
            "8. Confirm the live and Demo redirect URIs are present where applicable.",
            f"9. Store the generated artifacts securely for {build_result.request.ls_site}.",
        ]
    )
    summary_lines.append("==============================")
    return "\n".join(summary_lines)


def _build_existing_install_summary(
    *,
    build_result: ExistingInstallBuildResult,
    apply_result: ExistingInstallApplyResult,
    tenant_id: str,
    show_full_password: bool,
) -> str:
    """Build the grouped existing SharePoint update summary for terminal or persisted output."""
    certificate_password = (
        build_result.request.password
        if show_full_password
        else redact_secret(value=build_result.request.password)
    )
    selected_site_results = apply_result.selected_sharepoint_site_grant_results
    access_mode_description = _describe_sharepoint_access_mode(
        access_mode=apply_result.sharepoint_access_mode
    )
    cer_file_display = (
        apply_result.cer_file_path
        if show_full_password
        else redact_file_path_for_report(file_path=apply_result.cer_file_path)
    )
    pfx_file_display = (
        apply_result.pfx_file_path
        if show_full_password
        else redact_file_path_for_report(file_path=apply_result.pfx_file_path)
    )
    summary_lines = [
        "",
        "===== EXISTING SHAREPOINT UPDATE =====",
        f"LegalServer Site: {build_result.request.ls_site}",
        f"Site Type: {apply_result.plan.site_type}",
        f"Tenant ID: {tenant_id}",
        "Azure CLI authentication succeeded.",
        (
            "This workflow verified and updated redirect URIs as needed, then applied the replacement certificate to the provided live and user Azure applications."
        ),
        "Azure Applications:",
        f"  - Live App ID: {build_result.request.live_app_id}",
        f"  - Live App Display Name: {apply_result.plan.live_app_display_name}",
        f"  - User App ID: {build_result.request.user_app_id}",
        f"  - User App Display Name: {apply_result.plan.user_app_display_name}",
        f"  - Expected Redirect URIs: {', '.join(apply_result.plan.expected_redirect_uris)}",
        f"  - Live App Redirect URIs Applied: {', '.join(apply_result.live_app_redirect_uris_applied)}",
        f"  - User App Redirect URIs Applied: {', '.join(apply_result.user_app_redirect_uris_applied)}",
        f"  - Live App Valid Key Credentials Before Update: {apply_result.plan.live_app_valid_key_credential_count}",
        f"  - User App Valid Key Credentials Before Update: {apply_result.plan.user_app_valid_key_credential_count}",
        f"  - Live App Key Credentials After Update: {apply_result.live_app_key_credential_count_after}",
        f"  - User App Key Credentials After Update: {apply_result.user_app_key_credential_count_after}",
        f"  - SharePoint Access Mode: {access_mode_description}",
        (
            "  - Dry run only. No Azure updates were applied."
            if apply_result.dry_run
            else "  - Redirect URIs and certificate credentials were updated through Microsoft Graph."
        ),
        "Certificate:",
        f"  - Certificate Thumbprint: {apply_result.thumbprint}",
        f"  - CER File: {cer_file_display}",
        f"  - PFX File: {pfx_file_display}",
        f"  - Certificate Password: {certificate_password}",
    ]
    if apply_result.sharepoint_access_mode == "selected-sites":
        summary_lines.append("Selected SharePoint Sites:")
        summary_lines.append(
            "  - Additional Sites Requested: "
            + (
                ", ".join(
                    apply_result.additional_selected_sharepoint_site_urls_requested
                )
                if apply_result.additional_selected_sharepoint_site_urls_requested
                else "None"
            )
        )
        summary_lines.append(
            f"  - Grant Role: {apply_result.selected_sharepoint_site_grant_role}"
        )
        summary_lines.append(
            "  - Target Applications: App-only SharePoint app and user-auth SharePoint app"
        )
        if selected_site_results:
            for site_result in selected_site_results:
                requested_url = site_result.get("requested_url", "")
                action = site_result.get("action", "")
                resolved_web_url = site_result.get("resolved_web_url", "")
                target_label = site_result.get("target_label", "")
                details = resolved_web_url or requested_url
                if target_label:
                    details = f"{details} ({target_label})"
                summary_lines.append(f"  - {action.title()}: {details}")
                error_message = site_result.get("error_message", "")
                if error_message:
                    summary_lines.append(f"    Error: {error_message}")
        else:
            summary_lines.append("  - Additional Sites Requested: None")
        summary_lines.extend(
            _build_selected_sites_follow_up_lines(
                selected_site_results=selected_site_results
            )
        )
        summary_lines.append(
            f"  - Helper App Cleanup: {apply_result.helper_app_cleanup_message}"
        )
    summary_lines.extend(
        [
            "",
            "Next Steps:",
            "1. Use the exported .cer and .pfx files to configure the Microsoft Azure integration in LegalServer.",
            "2. Navigate to Admin -> SharePoint Settings in LegalServer.",
            "3. Enter the Public Certificate (.cer) and Private Key (.pfx) along with the password when prompted.",
            f"4. Confirm the thumbprint matches {apply_result.thumbprint}.",
        ]
    )
    summary_lines.append("===================================")
    return "\n".join(summary_lines)


def _build_sso_install_summary(
    *,
    build_result: SsoInstallBuildResult,
    apply_result: SsoInstallApplyResult,
    show_full_password: bool,
) -> str:
    """Build the grouped Site SSO install summary for terminal or persisted output."""
    certificate_password = (
        apply_result.certificate_password
        if show_full_password
        else redact_secret(value=apply_result.certificate_password)
    )
    cer_file_display = (
        apply_result.cer_file_path
        if show_full_password
        else redact_file_path_for_report(file_path=apply_result.cer_file_path)
    )
    pfx_file_display = (
        apply_result.pfx_file_path
        if show_full_password
        else redact_file_path_for_report(file_path=apply_result.pfx_file_path)
    )
    summary_lines = [
        "",
        "===== LEGALSERVER SSO INSTALL =====",
        f"LegalServer Site: {build_result.request.ls_site}",
        f"Site Type: {apply_result.plan.site_type}",
        f"Tenant ID: {apply_result.tenant_id}",
        "Azure CLI authentication succeeded.",
        "Azure Application:",
        f"  - Display Name: {apply_result.plan.display_name}",
        f"  - App ID: {apply_result.app_id}",
        f"  - Redirect URIs: {', '.join(apply_result.plan.redirect_uris)}",
        "  - Required Microsoft Graph Delegated Permission: User.Read",
        f"  - Permissions Configured: {apply_result.permissions_configured}",
        f"  - Owner Assignment Status: {apply_result.owner_assignment_status}",
        (
            "  - Dry run only. No Azure application or permission changes were applied."
            if apply_result.dry_run
            else "  - Azure application and service principal were created through Microsoft Graph."
        ),
        "Certificate:",
        f"  - Certificate Thumbprint: {apply_result.thumbprint}",
        f"  - CER File: {cer_file_display}",
        f"  - PFX File: {pfx_file_display}",
        f"  - Certificate Password: {certificate_password}",
        "Consent:",
        f"  - Delegated Consent Status: {apply_result.admin_consent_status}",
        f"  - Delegated Consent Instructions: {apply_result.admin_consent_instructions}",
        "============================",
    ]
    return "\n".join(summary_lines)


def _build_existing_sso_install_summary(
    *,
    build_result: ExistingSsoInstallBuildResult,
    apply_result: ExistingSsoInstallApplyResult,
    tenant_id: str,
    show_full_password: bool,
) -> str:
    """Build the grouped existing Site SSO update summary for terminal or persisted output."""
    certificate_password = (
        build_result.request.password
        if show_full_password
        else redact_secret(value=build_result.request.password)
    )
    cer_file_display = (
        apply_result.cer_file_path
        if show_full_password
        else redact_file_path_for_report(file_path=apply_result.cer_file_path)
    )
    pfx_file_display = (
        apply_result.pfx_file_path
        if show_full_password
        else redact_file_path_for_report(file_path=apply_result.pfx_file_path)
    )
    summary_lines = [
        "",
        "===== EXISTING SITE SSO UPDATE =====",
        f"LegalServer Site: {build_result.request.ls_site}",
        f"Site Type: {apply_result.plan.site_type}",
        f"Tenant ID: {tenant_id}",
        "Azure CLI authentication succeeded.",
        "This workflow verified the fixed Site SSO redirect URI and applied the replacement certificate to the provided Site SSO Azure application.",
        "Azure Application:",
        f"  - App ID: {build_result.request.sso_app_id}",
        f"  - Display Name: {apply_result.plan.app_display_name}",
        f"  - Expected Redirect URIs: {', '.join(apply_result.plan.expected_redirect_uris)}",
        f"  - Redirect URIs Applied: {', '.join(apply_result.redirect_uris_applied)}",
        f"  - Valid Key Credentials Before Update: {apply_result.plan.valid_key_credential_count}",
        f"  - Key Credentials After Update: {apply_result.key_credential_count_after}",
        (
            "  - Dry run only. No Azure updates were applied."
            if apply_result.dry_run
            else "  - Redirect URI and certificate credentials were updated through Microsoft Graph."
        ),
        "Certificate:",
        f"  - Certificate Thumbprint: {apply_result.thumbprint}",
        f"  - CER File: {cer_file_display}",
        f"  - PFX File: {pfx_file_display}",
        f"  - Certificate Password: {certificate_password}",
        "====================================",
    ]
    return "\n".join(summary_lines)


def _prepare_azure_cli_session(*, output: TextIO) -> GraphAuthProvider:
    """Ensure an operator-approved Azure CLI session is available before Graph work."""
    inspection_result = inspect_azure_cli_session()
    if inspection_result.success:
        if inspection_result.context is None:
            raise RuntimeError(
                "Azure CLI account inspection succeeded without returning a session context."
            )
        if _confirm_azure_cli_session(context=inspection_result.context, output=output):
            return AzureCliGraphAuthProvider()

    else:
        if inspection_result.error is None:
            raise RuntimeError(
                "Azure CLI account inspection failed without returning an error message."
            )
        print("Azure CLI authentication is required for this workflow.", file=output)
        print(inspection_result.error, file=output)

        if "Azure CLI was not found on PATH." in inspection_result.error:
            raise RuntimeError(inspection_result.error)

    print("Launching Azure CLI login...", file=output)
    login_result = run_azure_cli_login()
    if not login_result.success:
        raise RuntimeError(login_result.error or "Azure CLI login failed.")
    post_login_result = inspect_azure_cli_session()
    if not post_login_result.success:
        raise RuntimeError(
            post_login_result.error
            or "Azure CLI account inspection failed after login."
        )

    if post_login_result.context is None:
        raise RuntimeError(
            "Azure CLI login completed, but no approved session context was returned."
        )
    if not _confirm_azure_cli_session(context=post_login_result.context, output=output):
        raise RuntimeError(
            "Azure CLI session was not approved. Aborting before Microsoft Graph changes."
        )
    return AzureCliGraphAuthProvider()


def _run_existing_install_workflow(
    *, prompts: InteractivePrompts, output: TextIO, dry_run: bool = False
) -> str:
    """Run the existing SharePoint update workflow."""
    build_result = build_existing_install_request(
        prompts=prompts,
        output=output,
        dry_run=dry_run,
    )
    _warn_if_output_dir_is_repo_local(
        output_dir=build_result.request.output_dir,
        output=output,
    )
    _print_step(output=output, message="Preparing Azure CLI authentication")
    auth_provider = _prepare_azure_cli_session(output=output)
    _print_step_result(output=output, message="Azure CLI authentication approved")
    graph_client = GraphClient(auth_provider=auth_provider)
    _print_step(output=output, message="Reading tenant details from Microsoft Graph")
    tenant = graph_client.get_tenant_organization()
    _print_step_result(
        output=output,
        message=f"Tenant details loaded for {tenant.get('id', 'Unknown')}",
    )
    helper_config = _apply_helper_app_tenant_id(
        helper_config=build_result.request.selected_sites_helper_app_config,
        tenant_id=str(tenant.get("id", "")),
    )
    if helper_config is not None:
        build_result = ExistingInstallBuildResult(
            request=ExistingInstallRequest(
                ls_site=build_result.request.ls_site,
                live_app_id=build_result.request.live_app_id,
                user_app_id=build_result.request.user_app_id,
                valid_years=build_result.request.valid_years,
                password=build_result.request.password,
                output_dir=build_result.request.output_dir,
                sharepoint_access_mode=build_result.request.sharepoint_access_mode,
                additional_selected_sharepoint_site_urls=build_result.request.additional_selected_sharepoint_site_urls,
                selected_sites_helper_app_config=helper_config,
                validity_policy=build_result.request.validity_policy,
            ),
            generated_password=build_result.generated_password,
            dry_run=build_result.dry_run,
        )
    _print_step(output=output, message="Loading existing Azure applications")
    live_application = graph_client.get_application_by_app_id(
        build_result.request.live_app_id
    )
    user_application = graph_client.get_application_by_app_id(
        build_result.request.user_app_id
    )
    _print_step_result(output=output, message="Existing Azure applications loaded")
    delete_created_helper_app = _prompt_helper_app_cleanup_if_needed(
        created_in_this_run=_selected_sites_will_create_helper_app(
            access_mode=build_result.request.sharepoint_access_mode,
            create_new=(
                build_result.request.selected_sites_helper_app_config is not None
                and build_result.request.selected_sites_helper_app_config.create_new_helper_app
            ),
        ),
        output=output,
    )
    retain_local_helper_artifacts = _prompt_local_helper_artifact_retention_if_needed(
        created_in_this_run=_selected_sites_will_create_helper_app(
            access_mode=build_result.request.sharepoint_access_mode,
            create_new=(
                build_result.request.selected_sites_helper_app_config is not None
                and build_result.request.selected_sites_helper_app_config.create_new_helper_app
            ),
        ),
        delete_created_helper_app=delete_created_helper_app,
        output=output,
    )
    _print_step(
        output=output,
        message=(
            "Generating certificate files and planning SharePoint Azure updates"
            if build_result.dry_run
            else "Generating certificate files and applying SharePoint Azure updates"
        ),
    )
    apply_result = apply_existing_install_updates(
        request=build_result.request,
        graph_client=graph_client,
        live_application=live_application,
        user_application=user_application,
        dry_run=build_result.dry_run,
        delete_created_helper_app=delete_created_helper_app,
        retain_local_helper_artifacts=retain_local_helper_artifacts,
        progress_reporter=_build_progress_reporter(output=output),
    )
    _print_step_result(
        output=output,
        message=(
            "Dry-run SharePoint update plan completed"
            if apply_result.dry_run
            else "SharePoint Azure application update completed"
        ),
    )
    report_summary = _build_existing_install_summary(
        build_result=build_result,
        apply_result=apply_result,
        tenant_id=tenant.get("id", "Unknown"),
        show_full_password=False,
    )
    terminal_summary = _build_existing_install_summary(
        build_result=build_result,
        apply_result=apply_result,
        tenant_id=tenant.get("id", "Unknown"),
        show_full_password=build_result.generated_password,
    )
    report_path = build_report_path(
        output_dir=build_result.request.output_dir,
        ls_site=build_result.request.ls_site,
        suffix="update_existing_report",
    )
    handoff = build_operator_handoff_report(
        title="Update Existing SharePoint Handoff",
        key_values=[
            ("LegalServer Site", build_result.request.ls_site),
            ("Tenant ID", tenant.get("id", "Unknown")),
            ("Live App ID", build_result.request.live_app_id),
            ("User App ID", build_result.request.user_app_id),
            ("Certificate Thumbprint", apply_result.thumbprint),
            (
                "CER File",
                redact_file_path_for_report(file_path=apply_result.cer_file_path),
            ),
            (
                "PFX File",
                redact_file_path_for_report(file_path=apply_result.pfx_file_path),
            ),
            (
                "Certificate Password",
                redact_secret(value=build_result.request.password),
            ),
        ],
        action_items=[
            "Verify the new certificate appears in both Azure applications.",
            "Store the new certificate files and password securely.",
            "Use the identified live and user application IDs when validating the certificate update.",
            "Update LegalServer configuration with the replacement certificate password if needed.",
        ],
    )
    written_report_path, report_permissions_applied = write_report(
        report_path=report_path,
        content=build_update_existing_report(summary=report_summary) + "\n\n" + handoff,
    )
    if not report_permissions_applied:
        _warn_if_sensitive_file_permissions_not_applied(
            file_path=written_report_path,
            output=output,
        )
    return terminal_summary + f"\nReport File: {report_path}"


def _run_existing_sso_install_workflow(
    *, prompts: InteractivePrompts, output: TextIO, dry_run: bool = False
) -> str:
    """Run the existing Site SSO update workflow."""
    build_result = build_existing_sso_install_request(
        prompts=prompts,
        output=output,
        dry_run=dry_run,
    )
    _warn_if_output_dir_is_repo_local(
        output_dir=build_result.request.output_dir,
        output=output,
    )
    _print_step(output=output, message="Preparing Azure CLI authentication")
    auth_provider = _prepare_azure_cli_session(output=output)
    _print_step_result(output=output, message="Azure CLI authentication approved")
    graph_client = GraphClient(auth_provider=auth_provider)
    _print_step(output=output, message="Reading tenant details from Microsoft Graph")
    tenant = graph_client.get_tenant_organization()
    _print_step_result(
        output=output,
        message=f"Tenant details loaded for {tenant.get('id', 'Unknown')}",
    )
    _print_step(output=output, message="Loading existing Site SSO Azure application")
    application = graph_client.get_application_by_app_id(
        build_result.request.sso_app_id
    )
    _print_step_result(
        output=output, message="Existing Site SSO Azure application loaded"
    )
    _print_step(
        output=output,
        message=(
            "Generating certificate files and planning Site SSO Azure updates"
            if build_result.dry_run
            else "Generating certificate files and applying Site SSO Azure updates"
        ),
    )
    apply_result = apply_existing_sso_install_updates(
        request=build_result.request,
        graph_client=graph_client,
        application=application,
        dry_run=build_result.dry_run,
        progress_reporter=_build_progress_reporter(output=output),
    )
    _print_step_result(
        output=output,
        message=(
            "Dry-run Site SSO update plan completed"
            if apply_result.dry_run
            else "Site SSO Azure application update completed"
        ),
    )
    report_summary = _build_existing_sso_install_summary(
        build_result=build_result,
        apply_result=apply_result,
        tenant_id=tenant.get("id", "Unknown"),
        show_full_password=False,
    )
    terminal_summary = _build_existing_sso_install_summary(
        build_result=build_result,
        apply_result=apply_result,
        tenant_id=tenant.get("id", "Unknown"),
        show_full_password=build_result.generated_password,
    )
    report_path = build_report_path(
        output_dir=build_result.request.output_dir,
        ls_site=build_result.request.ls_site,
        suffix="update_existing_sso_report",
    )
    handoff = build_operator_handoff_report(
        title="Update Existing Site SSO Handoff",
        key_values=[
            ("LegalServer Site", build_result.request.ls_site),
            ("Tenant ID", tenant.get("id", "Unknown")),
            ("Site SSO App ID", build_result.request.sso_app_id),
            ("Certificate Thumbprint", apply_result.thumbprint),
            (
                "CER File",
                redact_file_path_for_report(file_path=apply_result.cer_file_path),
            ),
            (
                "PFX File",
                redact_file_path_for_report(file_path=apply_result.pfx_file_path),
            ),
            (
                "Certificate Password",
                redact_secret(value=build_result.request.password),
            ),
        ],
        action_items=[
            "Verify the new certificate appears in the Site SSO Azure application.",
            "Verify the Site SSO redirect URI remains configured correctly.",
            "Store the new certificate files and password securely.",
            "Use the identified Site SSO application ID when validating the certificate update.",
        ],
    )
    written_report_path, report_permissions_applied = write_report(
        report_path=report_path,
        content=build_update_existing_report(summary=report_summary) + "\n\n" + handoff,
    )
    if not report_permissions_applied:
        _warn_if_sensitive_file_permissions_not_applied(
            file_path=written_report_path,
            output=output,
        )
    return terminal_summary + f"\nReport File: {report_path}"


def _run_full_install_workflow(
    *, prompts: InteractivePrompts, output: TextIO, dry_run: bool = False
) -> str:
    """Run the full SharePoint install workflow."""
    build_result = build_full_install_request(
        prompts=prompts,
        output=output,
        dry_run=dry_run,
    )
    _warn_if_output_dir_is_repo_local(
        output_dir=build_result.request.output_dir,
        output=output,
    )
    _print_step(output=output, message="Preparing Azure CLI authentication")
    auth_provider = _prepare_azure_cli_session(output=output)
    _print_step_result(output=output, message="Azure CLI authentication approved")
    graph_client = GraphClient(auth_provider=auth_provider)
    _print_step(output=output, message="Reading tenant details from Microsoft Graph")
    tenant = graph_client.get_tenant_organization()
    _print_step_result(
        output=output,
        message=f"Tenant details loaded for {tenant.get('id', 'Unknown')}",
    )
    helper_config = _apply_helper_app_tenant_id(
        helper_config=build_result.request.selected_sites_helper_app_config,
        tenant_id=str(tenant.get("id", "")),
    )
    if helper_config is not None:
        build_result = FullInstallBuildResult(
            request=FullInstallRequest(
                ls_site=build_result.request.ls_site,
                sharepoint_site_url=build_result.request.sharepoint_site_url,
                valid_years=build_result.request.valid_years,
                password=build_result.request.password,
                output_dir=build_result.request.output_dir,
                sharepoint_access_mode=build_result.request.sharepoint_access_mode,
                selected_sharepoint_site_urls=build_result.request.selected_sharepoint_site_urls,
                selected_sites_helper_app_config=helper_config,
                validity_policy=build_result.request.validity_policy,
            ),
            generated_password=build_result.generated_password,
            dry_run=build_result.dry_run,
        )
    _print_step(
        output=output,
        message=(
            "Generating certificate files and building full SharePoint install plan"
            if build_result.dry_run
            else "Generating certificate files and creating SharePoint Azure applications"
        ),
    )
    delete_created_helper_app = _prompt_helper_app_cleanup_if_needed(
        created_in_this_run=_selected_sites_will_create_helper_app(
            access_mode=build_result.request.sharepoint_access_mode,
            create_new=(
                build_result.request.selected_sites_helper_app_config is not None
                and build_result.request.selected_sites_helper_app_config.create_new_helper_app
            ),
        ),
        output=output,
    )
    retain_local_helper_artifacts = _prompt_local_helper_artifact_retention_if_needed(
        created_in_this_run=_selected_sites_will_create_helper_app(
            access_mode=build_result.request.sharepoint_access_mode,
            create_new=(
                build_result.request.selected_sites_helper_app_config is not None
                and build_result.request.selected_sites_helper_app_config.create_new_helper_app
            ),
        ),
        delete_created_helper_app=delete_created_helper_app,
        output=output,
    )
    apply_result = apply_full_install(
        request=build_result.request,
        graph_client=graph_client,
        tenant=tenant,
        dry_run=build_result.dry_run,
        delete_created_helper_app=delete_created_helper_app,
        retain_local_helper_artifacts=retain_local_helper_artifacts,
        progress_reporter=_build_progress_reporter(output=output),
    )
    _print_step_result(
        output=output,
        message=(
            "Dry-run full SharePoint install plan completed"
            if apply_result.dry_run
            else "SharePoint Azure application setup completed"
        ),
    )
    report_summary = _build_full_install_summary(
        build_result=build_result,
        apply_result=apply_result,
        show_full_password=False,
    )
    terminal_summary = _build_full_install_summary(
        build_result=build_result,
        apply_result=apply_result,
        show_full_password=build_result.generated_password,
    )
    report_path = build_report_path(
        output_dir=build_result.request.output_dir,
        ls_site=build_result.request.ls_site,
        suffix="full_install_report",
    )
    handoff = build_operator_handoff_report(
        title="Full SharePoint Install Handoff",
        key_values=[
            ("Site", build_result.request.ls_site),
            ("Registered Application ID (User Auth)", apply_result.user_app_id),
            ("Registered Application ID (App Auth)", apply_result.app_only_app_id),
            (
                "User Auth App Consent URL",
                _build_portal_app_consent_url(app_id=apply_result.user_app_id),
            ),
            ("Globally Unique Tenant ID", apply_result.tenant_id),
            ("Top Level Web / Intranet URL", apply_result.top_level_web_url),
            ("Home/default site", apply_result.home_default_site),
            ("Default Document Library", apply_result.default_document_library),
            (
                "Thumbprint of registered app public certificate",
                apply_result.thumbprint,
            ),
            ("Public Certificate Expiration", apply_result.certificate_expiration),
            (
                "Passphrase for private PKCS#12 (.pfx) certificate",
                redact_secret(value=apply_result.certificate_password),
            ),
        ],
        action_items=[
            "Approve the User App Consent at the URL provided.",
            "Use the exported .cer and .pfx files to configure the Microsoft Azure integration in LegalServer.",
            "Navigate to Admin -> SharePoint Settings in LegalServer.",
            "Enter the User App ID, App-Only App ID, Tenant ID, SharePoint base URL, default SharePoint Site and Library.",
            "Enter the Public Certificate (.cer) and Private Key (.pfx) along with the password when prompted.",
            f"Confirm the thumbprint matches {apply_result.thumbprint}.",
            "Inform LegalServer Support that the integration configuration has been completed and you are ready for full enablement of the Save in SharePoint Features.",
            "Confirm the live and Demo redirect URIs are present where applicable.",
            f"Store the generated artifacts securely for {build_result.request.ls_site}.",
        ],
    )
    written_report_path, report_permissions_applied = write_report(
        report_path=report_path,
        content=build_full_install_report(
            summary=report_summary,
            terminal_summary=report_summary,
        )
        + "\n\n"
        + handoff,
    )
    if not report_permissions_applied:
        _warn_if_sensitive_file_permissions_not_applied(
            file_path=written_report_path,
            output=output,
        )
    return terminal_summary + f"\nReport File: {report_path}"


def _run_sso_install_workflow(
    *, prompts: InteractivePrompts, output: TextIO, dry_run: bool = False
) -> str:
    """Run the full Site SSO install workflow."""
    build_result = build_sso_install_request(
        prompts=prompts,
        output=output,
        dry_run=dry_run,
    )
    _warn_if_output_dir_is_repo_local(
        output_dir=build_result.request.output_dir,
        output=output,
    )
    _print_step(output=output, message="Preparing Azure CLI authentication")
    auth_provider = _prepare_azure_cli_session(output=output)
    _print_step_result(output=output, message="Azure CLI authentication approved")
    graph_client = GraphClient(auth_provider=auth_provider)
    _print_step(output=output, message="Reading tenant details from Microsoft Graph")
    tenant = graph_client.get_tenant_organization()
    _print_step_result(
        output=output,
        message=f"Tenant details loaded for {tenant.get('id', 'Unknown')}",
    )
    _print_step(
        output=output,
        message=(
            "Generating certificate files and building Site SSO plan"
            if build_result.dry_run
            else "Generating certificate files and creating Site SSO Azure application"
        ),
    )
    apply_result = apply_sso_install(
        request=build_result.request,
        graph_client=graph_client,
        tenant=tenant,
        dry_run=build_result.dry_run,
        progress_reporter=_build_progress_reporter(output=output),
    )
    _print_step_result(
        output=output,
        message=(
            "Dry-run Site SSO plan completed"
            if apply_result.dry_run
            else "Site SSO application setup completed"
        ),
    )
    report_summary = _build_sso_install_summary(
        build_result=build_result,
        apply_result=apply_result,
        show_full_password=False,
    )
    terminal_summary = _build_sso_install_summary(
        build_result=build_result,
        apply_result=apply_result,
        show_full_password=build_result.generated_password,
    )
    report_path = build_report_path(
        output_dir=build_result.request.output_dir,
        ls_site=build_result.request.ls_site,
        suffix="sso_install_report",
    )
    handoff = build_operator_handoff_report(
        title="Site SSO Install Handoff",
        key_values=[
            ("Site", build_result.request.ls_site),
            ("Registered Application Name", apply_result.plan.display_name),
            ("Registered Application ID", apply_result.app_id),
            ("Globally Unique Tenant ID", apply_result.tenant_id),
            ("Redirect URI", apply_result.plan.redirect_uris[0]),
            (
                "Thumbprint of registered app public certificate",
                apply_result.thumbprint,
            ),
            ("Public Certificate Expiration", apply_result.certificate_expiration),
            (
                "Passphrase for private PKCS#12 (.pfx) certificate",
                redact_secret(value=apply_result.certificate_password),
            ),
        ],
        action_items=[
            "Verify the Site SSO application, service principal, and redirect URI in Azure.",
            "Complete any remaining delegated consent steps listed in the summary.",
            "Store the generated certificate files and password securely.",
            "Use the created application ID and certificate details when completing Site SSO setup.",
        ],
    )
    written_report_path, report_permissions_applied = write_report(
        report_path=report_path,
        content=build_sso_install_report(summary=report_summary) + "\n\n" + handoff,
    )
    if not report_permissions_applied:
        _warn_if_sensitive_file_permissions_not_applied(
            file_path=written_report_path,
            output=output,
        )
    return terminal_summary + f"\nReport File: {report_path}"


def run_interactive_cli(
    *,
    argv: Optional[list[str]] = None,
    prompts: InteractivePrompts | None = None,
    output: TextIO = sys.stdout,
    error_output: TextIO = sys.stderr,
) -> int:
    """Run the interactive one-command CLI for LegalServer Microsoft integrations."""
    prompt_set = prompts or default_prompts()
    try:
        render_welcome(output=output)
        print(
            "This tool will guide you through SharePoint and Site SSO Microsoft integration setup tasks.",
            file=output,
        )
        print("Press Enter to accept defaults where they are shown.", file=output)
        print("Example site names: example, example-demo, org.dev", file=output)
        print(file=output)

        args = parse_args(argv)
        if args.mode is not None:
            mode = args.mode
        else:
            mode = prompt_mode_selection(prompts=prompt_set, output=output)
        print(_build_mode_confirmation(mode=mode), file=output)
        if mode == "validate-selected-sites-helper":
            print(file=output)
            print(
                _run_validate_selected_sites_helper_workflow(
                    args=args,
                    output=output,
                ),
                file=output,
            )
            return 0
        if mode == "certificate-only":
            build_result = build_interactive_request(
                prompts=prompt_set,
                output=output,
                provided_site=args.site,
                provided_years=args.years,
                provided_output_dir=args.output_dir,
                provided_password=args.password,
                generate_password=args.generate_password,
            )
            _warn_if_output_dir_is_repo_local(
                output_dir=build_result.request.output_dir,
                output=output,
            )
            result = run_manual_certificate_workflow(
                request=build_result.request,
                generated_password=build_result.generated_password,
            )
            terminal_summary = build_terminal_manual_summary(result=result)
            report_path = build_report_path(
                output_dir=build_result.request.output_dir,
                ls_site=build_result.request.ls_site,
                suffix="certificate_report",
            )
            written_report_path, report_permissions_applied = write_report(
                report_path=report_path,
                content=build_manual_report(
                    summary=result.summary,
                    next_steps=result.next_steps,
                ),
            )
            if not report_permissions_applied:
                _warn_if_sensitive_file_permissions_not_applied(
                    file_path=written_report_path,
                    output=output,
                )
            print(file=output)
            print(terminal_summary, file=output)
            print(file=output)
            print(result.next_steps, file=output)
            print(file=output)
            print(f"Report File: {report_path}", file=output)
            return 0

        if mode == "update-existing-sharepoint":
            print(file=output)
            print(
                _run_existing_install_workflow(
                    prompts=prompt_set,
                    output=output,
                    dry_run=args.dry_run,
                ),
                file=output,
            )
            return 0

        if mode == "update-existing-sso":
            print(file=output)
            print(
                _run_existing_sso_install_workflow(
                    prompts=prompt_set,
                    output=output,
                    dry_run=args.dry_run,
                ),
                file=output,
            )
            return 0

        if mode == "full-sharepoint-install":
            print(file=output)
            print(
                _run_full_install_workflow(
                    prompts=prompt_set,
                    output=output,
                    dry_run=args.dry_run,
                ),
                file=output,
            )
            return 0

        if mode == "full-sso-install":
            print(file=output)
            print(
                _run_sso_install_workflow(
                    prompts=prompt_set,
                    output=output,
                    dry_run=args.dry_run,
                ),
                file=output,
            )
            return 0

        raise ValueError(f"Unsupported mode: {mode}")
    except KeyboardInterrupt:
        print("\nCancelled.", file=error_output)
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=error_output)
        return 1
