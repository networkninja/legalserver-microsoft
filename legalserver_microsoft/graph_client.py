from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Optional, Protocol, cast
from urllib.parse import quote, urlparse

import msal
import requests
from azure.identity import AzureCliCredential
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

if TYPE_CHECKING:
    from azure.identity import AzureCliCredential as AzureCliCredentialType
    from requests import Response


GRAPH_SCOPES = [
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
]

DEVICE_CODE_CLIENT_ID = "04f0c124-f2bc-4f1f-b2f5-3c6f9f0f8b7d"
GRAPH_AUTHORITY = "https://login.microsoftonline.com/organizations"
TOKEN_EXPIRY_SAFETY_BUFFER_SECONDS = 60
GRAPH_TOKEN_SCOPE = "https://graph.microsoft.com/.default"  # nosec
_ALLOWED_HTTP_METHODS = frozenset({"get", "patch", "post", "delete"})


def _normalize_authority_tenant_id(*, tenant_id: str) -> str:
    """Normalize a tenant identifier before building an MSAL authority URL."""
    normalized = tenant_id.strip().strip("/")
    if normalized.startswith("https://"):
        normalized = normalized.removeprefix("https://")
        normalized = normalized.split("/", 1)[1] if "/" in normalized else ""
    elif normalized.startswith("http://"):
        normalized = normalized.removeprefix("http://")
        normalized = normalized.split("/", 1)[1] if "/" in normalized else ""
    normalized = normalized.strip().strip("/")
    if not normalized:
        raise RuntimeError(
            "Helper application authentication requires a non-empty tenant ID."
        )
    return normalized


def _extract_graph_error_details(*, response: "Response") -> str:
    """Return the most useful available Microsoft Graph error details."""
    response_text = str(response.text)
    try:
        payload = response.json()
    except ValueError:
        return response_text.strip()

    if not isinstance(payload, dict):
        return response_text.strip()

    error_payload = payload.get("error")
    if isinstance(error_payload, dict):
        message = error_payload.get("message")
        code = error_payload.get("code")
        if isinstance(code, str) and isinstance(message, str):
            return f"{code}: {message}"
        if isinstance(message, str):
            return message

    return response_text.strip()


@dataclass
class GraphAccessToken:
    """Represents an authenticated Graph access token."""

    access_token: str
    expires_in: int
    acquired_at: datetime

    def is_expired(self) -> bool:
        """Return whether the token should be refreshed before reuse."""
        expires_at = self.acquired_at + timedelta(seconds=self.expires_in)
        refresh_at = expires_at - timedelta(seconds=TOKEN_EXPIRY_SAFETY_BUFFER_SECONDS)
        return datetime.now(timezone.utc) >= refresh_at


@dataclass(frozen=True)
class HelperAppAuthDiagnostics:
    """Represents non-secret helper-app certificate authentication diagnostics."""

    authority: str
    client_id: str
    thumbprint: str
    token_acquisition_succeeded: bool
    auth_diagnostic_message: str


class GraphAuthProvider(Protocol):
    """Represents a strategy that can acquire a Microsoft Graph access token."""

    def acquire_token(self) -> GraphAccessToken:
        """Return a fresh Microsoft Graph access token."""
        ...


class DeviceCodeGraphAuthProvider:
    """Acquire Graph tokens using MSAL Device Code Flow."""

    def __init__(
        self,
        *,
        client_id: str = DEVICE_CODE_CLIENT_ID,
        authority: str = GRAPH_AUTHORITY,
    ) -> None:
        """Initialize the underlying MSAL public client application."""
        self._client_id = client_id
        self._authority = authority
        self._app = msal.PublicClientApplication(
            client_id=self._client_id,
            authority=self._authority,
        )

    def acquire_token(self) -> GraphAccessToken:
        """Start Device Code Flow and return a Graph access token."""
        flow = self._app.initiate_device_flow(scopes=GRAPH_SCOPES)
        if "user_code" not in flow:
            error_details = (
                flow.get("error_description") or flow.get("error") or str(flow)
            )
            raise RuntimeError(f"Failed to start device code flow: {error_details}")

        print(flow["message"])
        result = self._app.acquire_token_by_device_flow(flow)
        if "access_token" not in result:
            raise RuntimeError(
                result.get("error_description", "Authentication failed.")
            )

        return GraphAccessToken(
            access_token=result["access_token"],
            expires_in=int(result.get("expires_in", 0)),
            acquired_at=datetime.now(timezone.utc),
        )


class AzureCliGraphAuthProvider:
    """Acquire Graph tokens using the current Azure CLI login context."""

    def __init__(self, *, credential: "AzureCliCredentialType | None" = None) -> None:
        """Initialize the Azure CLI-backed credential used for Graph tokens."""
        self._credential = credential or AzureCliCredential()

    def acquire_token(self) -> GraphAccessToken:
        """Return a Microsoft Graph access token from the Azure CLI credential."""
        try:
            access_token = self._credential.get_token(GRAPH_TOKEN_SCOPE)
        except Exception as exc:
            # Broad catch is intentional: AzureCliCredential.get_token() can raise
            # azure.core.exceptions.ClientAuthenticationError and other third-party
            # exception types that are not RuntimeError.
            raise RuntimeError(
                f"Failed to acquire Microsoft Graph token from Azure CLI credential: {exc}"
            ) from exc

        expires_on = getattr(access_token, "expires_on", None)
        if not isinstance(expires_on, (int, float)):
            raise RuntimeError(
                "Azure CLI credential returned a token without a valid expiry timestamp."
            )

        acquired_at = datetime.now(timezone.utc)
        expires_in = max(0, int(expires_on - acquired_at.timestamp()))
        return GraphAccessToken(
            access_token=access_token.token,
            expires_in=expires_in,
            acquired_at=acquired_at,
        )


class ClientCertificateGraphAuthProvider:
    """Acquire Graph tokens using app-only certificate-based authentication."""

    def __init__(
        self,
        *,
        client_id: str,
        tenant_id: str,
        certificate_path: str,
        thumbprint: str,
        certificate_password: str | None = None,
        authority_base_url: str = "https://login.microsoftonline.com",
        private_key_loader: Callable[[str, str | None], str] | None = None,
    ) -> None:
        """Initialize the certificate-backed MSAL confidential client."""
        self._client_id = client_id
        self._tenant_id = _normalize_authority_tenant_id(tenant_id=tenant_id)
        self._certificate_path = certificate_path
        self._thumbprint = thumbprint
        self._certificate_password = certificate_password
        self._authority = f"{authority_base_url.rstrip('/')}/{self._tenant_id}"
        self._private_key_loader = private_key_loader or _load_private_key_text

    def acquire_token(self) -> GraphAccessToken:
        """Return an app-only Microsoft Graph access token."""
        private_key = self._private_key_loader(
            self._certificate_path,
            self._certificate_password,
        )
        app = msal.ConfidentialClientApplication(
            client_id=self._client_id,
            authority=self._authority,
            client_credential={
                "private_key": private_key,
                "thumbprint": self._thumbprint,
            },
        )
        result = app.acquire_token_for_client(scopes=[GRAPH_TOKEN_SCOPE])
        if "access_token" not in result:
            error_details = (
                result.get("error_description") or result.get("error") or str(result)
            )
            raise RuntimeError(
                "Failed to acquire Microsoft Graph token from helper application "
                f"certificate auth using authority {self._authority}: {error_details}"
            )

        return GraphAccessToken(
            access_token=str(result["access_token"]),
            expires_in=int(result.get("expires_in", 0)),
            acquired_at=datetime.now(timezone.utc),
        )

    def build_diagnostics(self) -> HelperAppAuthDiagnostics:
        """Attempt token acquisition and return non-secret helper-app auth diagnostics."""
        try:
            self.acquire_token()
        except RuntimeError as exc:
            return HelperAppAuthDiagnostics(
                authority=self._authority,
                client_id=self._client_id,
                thumbprint=self._thumbprint,
                token_acquisition_succeeded=False,
                auth_diagnostic_message=str(exc),
            )

        return HelperAppAuthDiagnostics(
            authority=self._authority,
            client_id=self._client_id,
            thumbprint=self._thumbprint,
            token_acquisition_succeeded=True,
            auth_diagnostic_message="",
        )


def _load_private_key_text(
    certificate_path: str, certificate_password: str | None = None
) -> str:
    """Load certificate private key text from PEM or PKCS#12 for app auth."""
    certificate_file = Path(certificate_path)
    if certificate_file.suffix.lower() == ".pfx":
        try:
            pfx_data = certificate_file.read_bytes()
            password_bytes = (
                certificate_password.encode("utf-8") if certificate_password else None
            )
            private_key, _, _ = pkcs12.load_key_and_certificates(
                pfx_data,
                password_bytes,
            )
        except OSError as exc:
            raise RuntimeError(
                f"Failed to read helper certificate PKCS#12 file: {exc}"
            ) from exc
        except ValueError as exc:
            raise RuntimeError(
                f"Failed to load helper certificate PKCS#12 file: {exc}"
            ) from exc
        if private_key is None:
            raise RuntimeError(
                "Helper certificate PKCS#12 file did not contain a private key."
            )
        # MSAL's ConfidentialClientApplication requires the private key as a plain
        # PEM string. NoEncryption() is therefore intentional here — the decrypted
        # key material is short-lived in memory for the duration of the token
        # acquisition call. MSAL does not expose an API to accept an opaque key
        # object, so this plaintext intermediate cannot be avoided with the current
        # library version.
        private_key_bytes: bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return cast(str, private_key_bytes.decode("utf-8"))
    try:
        return certificate_file.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(
            f"Failed to read helper certificate private key file: {exc}"
        ) from exc


class GraphClient:
    """Minimal Microsoft Graph client scaffold with pluggable authentication."""

    def __init__(
        self,
        *,
        client_id: str = DEVICE_CODE_CLIENT_ID,
        authority: str = GRAPH_AUTHORITY,
        auth_provider: GraphAuthProvider | None = None,
    ) -> None:
        """Initialize the Microsoft Graph client and authentication provider."""
        self._client_id = client_id
        self._authority = authority
        self._auth_provider = auth_provider or DeviceCodeGraphAuthProvider(
            client_id=self._client_id,
            authority=self._authority,
        )
        self._token: Optional[GraphAccessToken] = None

    def _build_graph_url(self, endpoint: str) -> str:
        """Build a validated Microsoft Graph URL for a relative endpoint."""
        normalized_endpoint = endpoint.strip().lstrip("/")
        if not normalized_endpoint:
            raise ValueError("Graph endpoint must not be empty.")
        return f"https://graph.microsoft.com/v1.0/{normalized_endpoint}"

    def _request_json(
        self,
        *,
        method: str,
        endpoint: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Perform a Graph request and return a parsed JSON object when present."""
        token = self.get_access_token()
        headers = {"Authorization": f"Bearer {token.access_token}"}
        if payload is not None:
            headers["Content-Type"] = "application/json"

        normalized_method = method.lower()
        if normalized_method not in _ALLOWED_HTTP_METHODS:
            raise ValueError(
                f"Unsupported HTTP method: {method!r}. "
                f"Allowed methods: {sorted(_ALLOWED_HTTP_METHODS)}"
            )
        request_func = getattr(requests, normalized_method)
        graph_url = self._build_graph_url(endpoint)
        response: Response | None = None
        try:
            response = request_func(
                graph_url,
                headers=headers,
                json=payload,
                timeout=30,
            )
            if response is None:
                raise RuntimeError(
                    f"Microsoft Graph {method.upper()} {endpoint} returned no HTTP response."
                )
            response.raise_for_status()
        except requests.RequestException as exc:
            http_response = getattr(exc, "response", None) or response
            error_details = ""
            if http_response is not None:
                error_details = _extract_graph_error_details(response=http_response)
            suffix = f" Details: {error_details}" if error_details else ""
            raise RuntimeError(
                f"Microsoft Graph {method.upper()} {endpoint} failed: {exc}{suffix}"
            ) from exc

        if not response.content:
            return {}

        try:
            data = response.json()
        except ValueError as exc:
            raise RuntimeError(
                f"Microsoft Graph {method.upper()} {endpoint} returned invalid JSON."
            ) from exc

        if not isinstance(data, dict):
            raise RuntimeError(
                f"Microsoft Graph {method.upper()} {endpoint} returned a non-object JSON payload."
            )
        return data

    def authenticate_with_device_code(self) -> GraphAccessToken:
        """Start Device Code Flow and return a Graph access token."""
        self._token = self._auth_provider.acquire_token()
        return self._token

    def get_access_token(self) -> GraphAccessToken:
        """Return the cached token or authenticate if needed."""
        if self._token is not None and not self._token.is_expired():
            return self._token
        return self.authenticate_with_device_code()

    def get_json(self, endpoint: str) -> dict:
        """Perform a GET request against Microsoft Graph and return JSON."""
        return self._request_json(method="get", endpoint=endpoint)

    def patch_json(self, endpoint: str, payload: dict[str, Any]) -> None:
        """Perform a PATCH request against Microsoft Graph."""
        self._request_json(method="patch", endpoint=endpoint, payload=payload)

    def post_json(self, endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Perform a POST request against Microsoft Graph and return JSON."""
        return self._request_json(method="post", endpoint=endpoint, payload=payload)

    def delete_json(self, endpoint: str) -> None:
        """Perform a DELETE request against Microsoft Graph."""
        self._request_json(method="delete", endpoint=endpoint)

    def get_tenant_organization(self) -> dict:
        """Return the tenant organization payload from Microsoft Graph."""
        data = self.get_json("organization")
        values = data.get("value", [])
        if not values:
            raise RuntimeError("No tenant organization data was returned.")
        organization = values[0]
        if not isinstance(organization, dict):
            raise RuntimeError("Tenant organization payload was not a JSON object.")
        return organization

    def get_me(self) -> dict[str, Any]:
        """Return the current authenticated user profile."""
        return self.get_json("me")

    def get_application_by_app_id(self, app_id: str) -> dict[str, Any]:
        """Return an application payload by Azure application ID."""
        filter_value = quote(f"appId eq '{app_id}'")
        data = self.get_json(f"applications?$filter={filter_value}")
        values = data.get("value", [])
        if not values:
            raise RuntimeError(f"No application found for App ID {app_id}.")
        application = values[0]
        if not isinstance(application, dict):
            raise RuntimeError("Application lookup returned a non-object JSON payload.")
        return application

    def get_service_principal_by_app_id(self, app_id: str) -> dict[str, Any]:
        """Return a service principal payload by Azure application ID."""
        filter_value = quote(f"appId eq '{app_id}'")
        data = self.get_json(f"servicePrincipals?$filter={filter_value}")
        values = data.get("value", [])
        if not values:
            raise RuntimeError(f"No service principal found for App ID {app_id}.")
        service_principal = values[0]
        if not isinstance(service_principal, dict):
            raise RuntimeError(
                "Service principal lookup returned a non-object JSON payload."
            )
        return service_principal

    def update_application_web_config(
        self,
        *,
        application_object_id: str,
        home_page_url: str,
        redirect_uris: list[str],
    ) -> None:
        """Update the web configuration for an Azure application."""
        self.patch_json(
            f"applications/{application_object_id}",
            {
                "web": {
                    "homePageUrl": home_page_url,
                    "redirectUris": redirect_uris,
                }
            },
        )

    def update_application_key_credentials(
        self,
        *,
        application_object_id: str,
        key_credentials: list[dict[str, Any]],
    ) -> None:
        """Replace the application key credentials collection."""
        self.patch_json(
            f"applications/{application_object_id}",
            {"keyCredentials": key_credentials},
        )

    def update_application_required_resource_access(
        self,
        *,
        application_object_id: str,
        required_resource_access: list[dict[str, Any]],
    ) -> None:
        """Update the required resource access collection for an application."""
        self.patch_json(
            f"applications/{application_object_id}",
            {"requiredResourceAccess": required_resource_access},
        )

    def create_application(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Create an Azure application registration."""
        return self.post_json("applications", payload)

    def create_service_principal(self, *, app_id: str) -> dict[str, Any]:
        """Create a service principal for an application."""
        return self.post_json("servicePrincipals", {"appId": app_id})

    def create_service_principal_app_role_assignment(
        self,
        *,
        service_principal_id: str,
        principal_id: str,
        resource_id: str,
        app_role_id: str,
    ) -> dict[str, Any]:
        """Create an app role assignment for a service principal."""
        return self.post_json(
            f"servicePrincipals/{service_principal_id}/appRoleAssignments",
            {
                "principalId": principal_id,
                "resourceId": resource_id,
                "appRoleId": app_role_id,
            },
        )

    def resolve_sharepoint_site(self, *, site_url: str) -> dict[str, Any]:
        """Resolve a SharePoint site by normalized site URL."""
        parsed = urlparse(site_url)
        site_path = parsed.path or "/"
        return self.get_json(f"sites/{parsed.netloc}:{site_path}")

    def grant_application_to_sharepoint_site(
        self,
        *,
        site_id: str,
        application_id: str,
        application_display_name: str,
        role: str,
    ) -> dict[str, Any]:
        """Grant an application a role on a specific SharePoint site."""
        return self.post_json(
            f"sites/{site_id}/permissions",
            {
                "roles": [role],
                "grantedToIdentities": [
                    {
                        "application": {
                            "id": application_id,
                            "displayName": application_display_name,
                        }
                    }
                ],
            },
        )

    def add_application_owner(
        self,
        *,
        application_object_id: str,
        owner_directory_object_id: str,
    ) -> None:
        """Add an owner to an application registration."""
        self.post_json(
            f"applications/{application_object_id}/owners/$ref",
            {
                "@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{owner_directory_object_id}"
            },
        )

    def delete_application(self, *, application_object_id: str) -> None:
        """Delete an Azure application registration by object ID."""
        self.delete_json(f"applications/{application_object_id}")
