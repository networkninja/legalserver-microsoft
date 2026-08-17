import posixpath
import re
import secrets
import string
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import unquote, urlparse

PASSWORD_SPECIAL_CHARACTERS = "!@#$%^&*()_+-=[]{}|;:,.<>?"  # nosec
DEFAULT_KEY_CREDENTIAL_VALIDITY_DAYS = 1095
CERTIFICATE_END_DATE_SAFETY_BUFFER_DAYS = 5
SENSITIVE_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR


def normalize_utc_datetime(value: datetime | None) -> datetime:
    """Normalize an optional datetime value to a timezone-aware UTC datetime."""
    normalized_value = value or datetime.now(timezone.utc)
    if normalized_value.tzinfo is None:
        return normalized_value.replace(tzinfo=timezone.utc)
    return normalized_value.astimezone(timezone.utc)


@dataclass(frozen=True)
class CertificateValidityPolicy:
    """Represents the maximum allowed certificate validity for a tenant."""

    max_days: int = DEFAULT_KEY_CREDENTIAL_VALIDITY_DAYS
    source: str = "ServiceDefault"


def determine_site_type(ls_site: str) -> str:
    """Determine the site type from the LegalServer site name."""
    ls_site_lower = ls_site.lower()
    if ls_site_lower.endswith("-demo"):
        return "Demo"
    if ".dev" in ls_site_lower:
        return "Dev"
    return "Production"


def is_valid_sharepoint_url(url: str) -> bool:
    """Validate that a URL matches the expected SharePoint library format."""
    pattern = (
        r"^https?://[a-zA-Z0-9.-]+\.sharepoint\.com"
        r"(/sites/[a-zA-Z0-9-]+)?"
        r"(/[^/]+)*/(?:Shared\s*Documents|[^/]+)/Forms/AllItems\.aspx$"
    )
    return bool(re.match(pattern, url, re.IGNORECASE))


def normalize_sharepoint_site_url(url: str) -> str:
    """Normalize a SharePoint site URL for selected-sites comparisons and Graph use."""
    parsed = urlparse(url.strip())
    if parsed.scheme.lower() != "https":
        raise ValueError("SharePoint site URL must use HTTPS.")
    if not parsed.netloc or not parsed.netloc.lower().endswith(".sharepoint.com"):
        raise ValueError("SharePoint site URL must use a sharepoint.com hostname.")
    if parsed.params or parsed.query or parsed.fragment:
        raise ValueError(
            "SharePoint site URL must not include parameters, query strings, or fragments."
        )

    normalized_path = posixpath.normpath(unquote(parsed.path or "/"))
    if normalized_path == ".":
        normalized_path = "/"
    if not normalized_path.startswith("/"):
        normalized_path = f"/{normalized_path}"
    normalized_path = normalized_path.rstrip("/") or "/"

    if normalized_path == "/":
        raise ValueError("SharePoint site URL must include a site path.")

    path_parts = [part for part in normalized_path.split("/") if part]
    if not path_parts:
        raise ValueError("SharePoint site URL must include a site path.")

    leading_segment = path_parts[0].lower()
    if leading_segment in {"forms", "lists"}:
        raise ValueError(
            "SharePoint site URL must identify a site, not a library path."
        )
    if leading_segment == "sites" and len(path_parts) < 2:
        raise ValueError("SharePoint site URL must include a site name after /sites/.")

    return f"https://{parsed.netloc.lower()}{normalized_path}"


def is_valid_sharepoint_site_url(url: str) -> bool:
    """Return whether a URL is a valid SharePoint site URL for selected-sites mode."""
    try:
        normalize_sharepoint_site_url(url)
    except ValueError:
        return False
    return True


def convert_sharepoint_url(url: str) -> Dict[str, str]:
    """Extract SharePoint subsite, library, and tenant metadata from a URL."""
    if not is_valid_sharepoint_url(url):
        raise ValueError("Invalid SharePoint URL structure.")

    parsed = urlparse(url)
    domain = parsed.netloc
    path_parts = parsed.path.strip("/").split("/")

    try:
        forms_index = next(
            index for index, part in enumerate(path_parts) if part.lower() == "forms"
        )
    except StopIteration as exc:
        raise ValueError("Forms directory not found.") from exc

    library = f"/{path_parts[forms_index - 1]}"
    subsite = "/"

    if "sites" in path_parts:
        sites_index = path_parts.index("sites")
        if forms_index - 1 > sites_index + 1:
            subsite = (
                f"/sites/{'/'.join(path_parts[sites_index + 1 : forms_index - 1])}"
            )
        else:
            subsite = "/sites"

    return {
        "Subsite": subsite,
        "Library": library,
        "Domain": domain,
        "TenantName": domain.split(".")[0],
    }


def get_unique_file_path(file_path: Path) -> Path:
    """Return a unique file path by appending an incrementing suffix."""
    if not file_path.exists():
        return file_path

    stem = file_path.stem
    suffix = file_path.suffix
    match = re.search(r"_(?P<num>\d+)$", stem)
    if match:
        counter = int(match.group("num")) + 1
        stem = re.sub(r"_\d+$", "", stem)
    else:
        counter = 1

    while True:
        new_path = file_path.parent / f"{stem}_{counter}{suffix}"
        if not new_path.exists():
            return new_path
        counter += 1


def apply_sensitive_file_permissions(*, file_path: Path) -> bool:
    """Apply owner-only read/write permissions to a sensitive generated file."""
    try:
        file_path.chmod(SENSITIVE_FILE_MODE)
    except OSError:
        # Some mounted filesystems may not honor chmod from the container.
        return False
    return True


def validate_password_complexity(password: str) -> bool:
    """Return whether a password meets the manual workflow requirements."""
    return bool(
        len(password) >= 12
        and any(character.isupper() for character in password)
        and any(character.islower() for character in password)
        and any(character.isdigit() for character in password)
        and any(character in PASSWORD_SPECIAL_CHARACTERS for character in password)
    )


def generate_random_password(length: int = 20) -> str:
    """Generate a random password that satisfies the workflow complexity rules."""
    if length < 4:
        raise ValueError("Password length must be at least 4 characters.")

    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    numbers = string.digits
    special = PASSWORD_SPECIAL_CHARACTERS
    all_characters = uppercase + lowercase + numbers + special

    password_characters = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(numbers),
        secrets.choice(special),
    ]
    password_characters.extend(
        secrets.choice(all_characters) for _ in range(length - 4)
    )
    secrets.SystemRandom().shuffle(password_characters)
    return "".join(password_characters)


def get_max_valid_years(validity_policy: CertificateValidityPolicy) -> int:
    """Convert a day-based validity policy into the maximum supported whole years."""
    if validity_policy.max_days < 365:
        raise ValueError(
            "Tenant policy limits key credential validity to less than one year. "
            "This workflow currently supports only year-based validity periods."
        )
    return max(1, validity_policy.max_days // 365)


def build_certificate_expiration(
    *,
    valid_years: int,
    validity_policy: CertificateValidityPolicy,
    start_date: Optional[datetime] = None,
) -> datetime:
    """Calculate a certificate expiration date that respects tenant limits."""
    if valid_years <= 0:
        raise ValueError("Certificate validity must be greater than zero years.")

    normalized_start = normalize_utc_datetime(start_date)

    max_valid_years = get_max_valid_years(validity_policy)
    if valid_years > max_valid_years:
        raise ValueError(
            "Requested validity exceeds tenant limit of "
            f"{validity_policy.max_days} days (~{max_valid_years} years)."
        )

    requested_end_date = normalized_start + timedelta(
        days=(365 * valid_years) - CERTIFICATE_END_DATE_SAFETY_BUFFER_DAYS
    )
    max_end_date = normalized_start + timedelta(days=validity_policy.max_days)
    if requested_end_date > max_end_date:
        raise ValueError(
            "Requested validity exceeds tenant limit of "
            f"{validity_policy.max_days} days (~{max_valid_years} years)."
        )
    return requested_end_date
