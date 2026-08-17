from pathlib import Path
import re

from legalserver_microsoft.utils import (
    apply_sensitive_file_permissions,
    get_unique_file_path,
)


def sanitize_site_name_for_filename(*, ls_site: str) -> str:
    """Return a filesystem-safe filename stem derived from a LegalServer site name.

    Any character that is not alphanumeric, a hyphen, or an underscore is
    replaced with a hyphen. Leading hyphens are stripped. A final explicit
    validation confirms no path-separator characters survive, so the result is
    always safe to join directly with a base Path.
    """
    sanitized = re.sub(r"[^a-zA-Z0-9_-]", "-", ls_site.strip())
    sanitized = sanitized.lstrip("-")
    result = sanitized or "site"
    if "/" in result or "\\" in result:
        raise ValueError(
            f"sanitize_site_name_for_filename produced an unsafe stem: {result!r}"
        )
    return result


def build_report_path(*, output_dir: Path, ls_site: str, suffix: str) -> Path:
    """Build a unique report file path for a workflow output.

    Raises ``ValueError`` if the resolved report path would fall outside the
    intended ``output_dir`` root, providing a final confinement check against
    unexpected path components.
    """
    reports_dir = output_dir / "SharePoint_Certificates"
    reports_dir.mkdir(parents=True, exist_ok=True)
    base_name = sanitize_site_name_for_filename(ls_site=ls_site)
    candidate = get_unique_file_path(reports_dir / f"{base_name}_{suffix}.txt")
    try:
        candidate.resolve().relative_to(reports_dir.resolve())
    except ValueError as exc:
        raise ValueError(
            f"Resolved report path {candidate} is outside the expected output "
            f"directory {reports_dir}."
        ) from exc
    return candidate


def write_report(*, report_path: Path, content: str) -> tuple[Path, bool]:
    """Write a workflow report to disk and return the final path."""
    report_path.write_text(content, encoding="utf-8")
    permissions_applied = apply_sensitive_file_permissions(file_path=report_path)
    return report_path, permissions_applied


def build_manual_report(*, summary: str, next_steps: str) -> str:
    """Build the exported report content for certificate-only runs."""
    return "\n\n".join([summary, next_steps])


def build_update_existing_report(*, summary: str) -> str:
    """Build the exported report content for update-existing runs."""
    return summary


def build_full_install_report(
    *, summary: str, terminal_summary: str | None = None
) -> str:
    """Build the exported report content for full-install runs."""
    return terminal_summary or summary


def build_sso_install_report(*, summary: str) -> str:
    """Build the exported report content for Site SSO install runs."""
    return summary


def build_operator_handoff_report(
    *,
    title: str,
    key_values: list[tuple[str, str]],
    action_items: list[str],
) -> str:
    """Build a cleaner support-staff handoff artifact."""
    key_value_lines = [f"{label}: {value}" for label, value in key_values]
    action_lines = [
        f"{index}. {item}" for index, item in enumerate(action_items, start=1)
    ]
    return "\n\n".join(
        [
            title,
            "Key Values\n" + "\n".join(key_value_lines),
            "Action Items\n" + "\n".join(action_lines),
        ]
    )
