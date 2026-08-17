from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from legalserver_microsoft.reporting import sanitize_site_name_for_filename
from legalserver_microsoft.utils import (
    apply_sensitive_file_permissions,
    CertificateValidityPolicy,
    build_certificate_expiration,
    determine_site_type,
    get_unique_file_path,
    normalize_utc_datetime,
    validate_password_complexity,
)
from legalserver_microsoft.models import (
    ManualCertificateRequest,
    ManualCertificateResult,
)


def redact_secret(*, value: str) -> str:
    """Return a redacted display value for persisted secret output.

    Values of four characters or fewer are returned fully masked with no suffix,
    since appending the full value would expose the entire secret. This function
    is intended for passwords that meet the 12-character minimum enforced by
    validate_password_complexity; callers passing shorter values receive a fully
    masked output.
    """
    if len(value) <= 4:
        return "********"
    return "********" + value[-4:]


def redact_file_path_for_report(*, file_path: str | Path) -> str:
    """Return a filename-only display value for persisted report output."""
    return Path(file_path).name


def generate_cert(
    common_name: str,
    years: int,
    *,
    validity_policy: CertificateValidityPolicy = CertificateValidityPolicy(),
    start_date: datetime | None = None,
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a self-signed certificate for the manual SharePoint workflow."""
    end_date = build_certificate_expiration(
        valid_years=years,
        validity_policy=validity_policy,
        start_date=start_date,
    )
    normalized_start = normalize_utc_datetime(start_date)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(normalized_start - timedelta(days=1))
        .not_valid_after(end_date)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def export_pfx(
    *,
    key: rsa.RSAPrivateKey,
    cert: x509.Certificate,
    password: str,
    path: Path,
) -> bool:
    """Export a private key and certificate to a password-protected PFX file."""
    pfx_data = pkcs12.serialize_key_and_certificates(
        b"LegalServer Certificate",
        key,
        cert,
        None,
        serialization.BestAvailableEncryption(password.encode("utf-8")),
    )
    path.write_bytes(pfx_data)
    return apply_sensitive_file_permissions(file_path=path)


def export_cer(*, cert: x509.Certificate, path: Path) -> bool:
    """Export a certificate to DER-encoded CER format."""
    path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    return apply_sensitive_file_permissions(file_path=path)


def get_thumbprint(cert: x509.Certificate) -> str:
    """Return the SHA-1 thumbprint used in operator-facing summaries."""
    return str(cert.fingerprint(hashes.SHA1()).hex().upper())  # nosec


def build_manual_instructions(*, ls_site: str, thumbprint: str) -> str:
    """Build the operator next steps for the manual certificate workflow."""
    return "\n".join(
        [
            "",
            "Next Steps:",
            "1. Use the exported .cer and .pfx files to configure the Microsoft Azure integration in LegalServer.",
            "2. Navigate to Admin -> SharePoint Settings or Admin -> Single Sign On (SSO) in LegalServer.",
            "3. Enter the Public Certificate (.cer) and Private Key (.pfx) along with the password when prompted.",
            f"4. Confirm the thumbprint matches {thumbprint}.",
            "5. Upload the Public Certificate (.cer) to the related Azure app registrations.",
            "6. Confirm the live and Demo redirect URIs are present where applicable.",
            f"7. Store the generated artifacts securely for {ls_site}.",
        ]
    )


def build_manual_config_block(*, result: ManualCertificateResult) -> str:
    """Build a copy/paste-ready configuration block for operators."""
    return "\n".join(
        [
            "",
            "===== LEGALSERVER CONFIG BLOCK =====",
            f"LegalServer Site: {result.ls_site}",
            f"Site Type: {result.site_type}",
            "Certificate Details:",
            f"  - Thumbprint: {result.thumbprint}",
            f"  - Expiration Date: {result.expires_at.isoformat()}",
            f"CER File: {redact_file_path_for_report(file_path=result.cer_file_path)}",
            f"PFX File: {redact_file_path_for_report(file_path=result.pfx_file_path)}",
            f"Certificate Password: {redact_secret(value=result.password)}",
            "====================================",
        ]
    )


def build_manual_summary(*, result: ManualCertificateResult) -> str:
    """Build a text summary matching the operator-focused PowerShell output."""
    return "\n".join(
        [
            "",
            "===== SUMMARY =====",
            f"Certificate Details for '{result.ls_site}'",
            f"Site Type: {result.site_type}",
            "Certificate Details:",
            f"  - Thumbprint: {result.thumbprint}",
            f"  - Expiration Date: {result.expires_at.isoformat()}",
            f"  - CER: {redact_file_path_for_report(file_path=result.cer_file_path)}",
            f"  - PFX: {redact_file_path_for_report(file_path=result.pfx_file_path)}",
            f"  - Password: {redact_secret(value=result.password)}",
            "  - Certificate generated for manual Microsoft Azure integration workflow.",
        ]
    )


def build_terminal_manual_summary(*, result: ManualCertificateResult) -> str:
    """Build the live terminal summary for the manual certificate workflow."""
    summary_lines = [
        "",
        "===== SUMMARY =====",
        f"Certificate Details for '{result.ls_site}'",
        f"Site Type: {result.site_type}",
        "Certificate Details:",
        f"  - Thumbprint: {result.thumbprint}",
        f"  - Expiration Date: {result.expires_at.isoformat()}",
        f"  - CER: {result.cer_file_path}",
        f"  - PFX: {result.pfx_file_path}",
    ]
    if result.generated_password:
        summary_lines.extend(
            [
                f"  - Password: {result.password}",
                "    THIS IS THE ONLY TIME YOU WILL SEE THE FULL PASSWORD. BE SURE TO COPY IT TO A SECURE PLACE.",
            ]
        )
    else:
        summary_lines.append(f"  - Password: {redact_secret(value=result.password)}")
    summary_lines.append(
        "  - Certificate generated for manual Microsoft Azure integration workflow."
    )
    return "\n".join(summary_lines)


def run_manual_certificate_workflow(
    *,
    request: ManualCertificateRequest,
    generated_password: bool = False,
) -> ManualCertificateResult:
    """Run the manual certificate workflow represented by the PowerShell script."""
    if not request.ls_site.strip():
        raise ValueError("A LegalServer site abbreviation is required.")
    if not validate_password_complexity(request.password):
        raise ValueError("Password does not meet complexity requirements.")

    cert_path = request.output_dir / "SharePoint_Certificates"
    cert_path.mkdir(parents=True, exist_ok=True)

    site_type = determine_site_type(request.ls_site)
    cert_base_name = sanitize_site_name_for_filename(ls_site=request.ls_site)
    cer_file_path = get_unique_file_path(
        cert_path / f"{cert_base_name}_certificate_cer.cer"
    )
    pfx_file_path = get_unique_file_path(
        cert_path / f"{cert_base_name}_certificate_pfx.pfx"
    )

    key, cert = generate_cert(
        request.ls_site,
        request.valid_years,
        validity_policy=request.validity_policy,
    )
    export_cer(cert=cert, path=cer_file_path)
    export_pfx(
        key=key,
        cert=cert,
        password=request.password,
        path=pfx_file_path,
    )

    thumbprint = get_thumbprint(cert)
    next_steps = build_manual_instructions(
        ls_site=request.ls_site,
        thumbprint=thumbprint,
    )
    result = ManualCertificateResult(
        ls_site=request.ls_site,
        site_type=site_type,
        cert_path=cert_path,
        cer_file_path=cer_file_path,
        pfx_file_path=pfx_file_path,
        password=request.password,
        thumbprint=thumbprint,
        expires_at=cert.not_valid_after_utc,
        common_name=request.ls_site,
        generated_password=generated_password,
        summary="",
        config_block="",
        next_steps=next_steps,
    )
    summary = build_manual_summary(result=result)
    config_block = build_manual_config_block(result=result)
    return replace(
        result,
        summary=summary,
        config_block=config_block,
    )
