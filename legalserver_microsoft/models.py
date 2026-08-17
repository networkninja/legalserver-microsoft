from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from legalserver_microsoft.utils import CertificateValidityPolicy


@dataclass(frozen=True)
class SelectedSitesHelperAppConfig:
    """Represents helper-app setup details for selected-sites grant automation."""

    create_new_helper_app: bool
    tenant_id: str
    authentication_method: str
    existing_helper_app_client_id: str = ""
    helper_certificate_thumbprint: str = ""
    helper_certificate_file_path: str = ""
    generate_helper_certificate_automatically: bool = False


@dataclass(frozen=True)
class ManualCertificateRequest:
    """Represents the inputs required for the manual certificate workflow."""

    ls_site: str
    valid_years: int
    password: str
    output_dir: Path
    validity_policy: CertificateValidityPolicy = CertificateValidityPolicy()


@dataclass(frozen=True)
class ManualCertificateResult:
    """Represents the generated artifacts and summary for the manual workflow."""

    ls_site: str
    site_type: str
    cert_path: Path
    cer_file_path: Path
    pfx_file_path: Path
    password: str
    thumbprint: str
    expires_at: datetime
    common_name: str
    generated_password: bool
    summary: str
    config_block: str
    next_steps: str


@dataclass(frozen=True)
class ExistingInstallRequest:
    """Represents the inputs for updating an existing Azure installation."""

    ls_site: str
    live_app_id: str
    user_app_id: str
    valid_years: int
    password: str
    output_dir: Path
    sharepoint_access_mode: str = "broad"
    additional_selected_sharepoint_site_urls: list[str] | None = None
    selected_sites_helper_app_config: SelectedSitesHelperAppConfig | None = None
    validity_policy: CertificateValidityPolicy = CertificateValidityPolicy()


@dataclass(frozen=True)
class ExistingSsoInstallRequest:
    """Represents the inputs for updating an existing Site SSO installation."""

    ls_site: str
    sso_app_id: str
    valid_years: int
    password: str
    output_dir: Path
    validity_policy: CertificateValidityPolicy = CertificateValidityPolicy()


@dataclass(frozen=True)
class FullInstallRequest:
    """Represents the inputs for a full new Azure-backed installation."""

    ls_site: str
    sharepoint_site_url: str
    valid_years: int
    password: str
    output_dir: Path
    sharepoint_access_mode: str = "broad"
    selected_sharepoint_site_urls: list[str] | None = None
    selected_sites_helper_app_config: SelectedSitesHelperAppConfig | None = None
    validity_policy: CertificateValidityPolicy = CertificateValidityPolicy()


@dataclass(frozen=True)
class SsoInstallRequest:
    """Represents the inputs for the SSO Azure-backed installation."""

    ls_site: str
    valid_years: int
    password: str
    output_dir: Path
    validity_policy: CertificateValidityPolicy = CertificateValidityPolicy()
