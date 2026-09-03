# LegalServer SharePoint Integration Tool

`legalserver_microsoft` is a Python Command Line Interface (CLI) for setting up
and maintaining the Microsoft Azure elements required for LegalServer's
SharePoint integration and LegalServer's Azure Single Sign On (SSO).

It is designed to guide an operator through certificate generation, Azure app
registration setup, certificate rotation, and integration handoff reporting
without requiring them to work through each Azure step manually.

The Azure OpenAI setup script configures endpoints for LegalServer's AI
integration. There is a separate detailed Readme file for the Azure OpenAI setup
script in the `azure_openai/` directory.

## What This Package Does

This package helps you:

- generate certificate packages for LegalServer Microsoft integrations
- create Azure app registration configurations for new SharePoint installs
- rotate certificates on existing SharePoint integration app registrations
- create and update the LegalServer SSO Azure app registration
- validate an existing selected-sites helper app for SharePoint site access
- setup and audit Microsoft Azure OpenAI endpoints and model deployments for LegalServer ML features
- produce operator reports with masked persisted secrets and follow-up details

This package does not manage SharePoint content, LegalServer application data,
or unrelated Azure resources.

## Repository Layout

- `legalserver_microsoft/`: Python package and CLI workflows
- `azure_openai/`: Azure OpenAI discovery, quota audit, and model deployment automation tool (`Setup-LegalServerAzureOpenAI.ps1`)
- `run-container.sh`: one-shot container launcher for Bash shells
- `run-container.ps1`: one-shot container launcher for PowerShell
- `run-container-reuse.sh`: reusable container shell launcher for Bash shells
- `run-container-reuse.ps1`: reusable container shell launcher for PowerShell
- `docker-compose.yml`: container definition used by the helper scripts
- `CHANGELOG.md`: release history and notable changes

## Recommended Way To Run

The easiest and most reliable way to run the tool is through the included
Docker helper scripts.

### One-Shot Run

Use this when you want the CLI to start immediately and the container removed
after the run finishes.

On macOS or Linux:

```bash
./run-container.sh
```

On Windows PowerShell:

```powershell
./run-container.ps1
```

These helpers run the equivalent of:

```bash
docker compose run --build --rm legalserver_microsoft
```

### Reusable Container Session

Use this when you want to stay inside the container and run the CLI multiple
times in the same session. This is typically not needed unless you are setting
up both SharePoint and SSO at the same time.

On macOS or Linux:

```bash
./run-container-reuse.sh
```

On Windows PowerShell:

```powershell
./run-container-reuse.ps1
```

These helpers open a shell inside the service container. From there, launch the
CLI as needed:

```bash
python -m legalserver_microsoft
```

The reusable helpers are equivalent to:

```bash
docker compose run legalserver_microsoft bash
```

## Running The CLI Directly

If you already have Python 3.11+, Azure CLI, and the package dependencies
available locally, you can run the CLI without Docker:

```bash
python -m legalserver_microsoft
```

The CLI is interactive by default, but it also accepts flags for scripted or
repeatable runs.

Additional CLI documentation appears later in this ReadMe.

## Workflow Summary

### `certificate-only`

Generates a new certificate package and report without making Azure changes.

### `update-existing-sharepoint`

Updates an existing SharePoint integration by adding a new certificate,
verifying expected configuration, and cleaning up expired certificate entries.
Existing certificates are not affected.

### `update-existing-sso`

Updates the existing `Site SSO` Azure app registration by rotating the
certificate and verifying the expected redirect URI. Existing certificates are
not affected.

### `full-sharepoint-install`

Creates a new Azure setup for the LegalServer SharePoint integration, including
certificate generation, app configuration, permissions work, site-selected
configuration support, and handoff data.

### `full-sso-install`

Creates the LegalServer `Site SSO` Azure app registration and configures the
required Microsoft Graph delegated permission for the fixed redirect URI.

### `validate-selected-sites-helper`

Tests an existing selected-sites helper app by checking certificate-based token
acquisition and SharePoint site resolution through Microsoft Graph.

## Output And Reports

By default, the tool writes generated artifacts into a
`SharePoint_Certificates` output area under the selected output directory.

Typical outputs include:

- `.pfx` certificate files
- `.cer` certificate files
- report files with setup details and follow-up steps
- certificate thumbprint and expiration information

When output is written inside the repository workspace, the CLI warns because
these artifacts are sensitive operational files and should not be committed.

## Security Notes

- Persisted reports mask secret values instead of writing plaintext passwords
- Certificate passwords shown during a live run are intended for terminal use
  only
- Prefer `LS_CERT_PASSWORD` over `--password` for scripted runs because command
  line arguments may appear in process listings
- This tool is intended to call Microsoft services needed for the integration;
  it is not a general Azure administration tool

## Container Notes

- The repository is mounted into `/workspace` inside the container
- Files created in the container remain available in the repository workspace on
  the host machine
- One-shot container runs are ephemeral because they use `--rm`
- Reusable container sessions keep Azure CLI sign-in state only for that live
  container session

## Requirements

For container usage:

- Docker
- Docker Compose support

For direct local usage:

- Python 3.11+
- Azure CLI
- dependencies from `pyproject.toml` or `requirements.txt`

## Dependency Files

- `requirements.txt`: runtime dependencies needed to use the package and run the
  CLI workflows
- `requirements-dev.txt`: developer tooling used for local formatting, type
  checking, security scanning, and repository maintenance

Typical local development setup:

```bash
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```

## CLI documentation

### CLI Usage

Basic usage:

```bash
python -m legalserver_microsoft --mode <workflow>
```

Supported workflow modes:

- `certificate-only`
- `update-existing-sharepoint`
- `update-existing-sso`
- `full-sharepoint-install`
- `full-sso-install`
- `validate-selected-sites-helper`

Common arguments:

- `--mode`: workflow to run
- `--site`: LegalServer site abbreviation
- `--years`: certificate validity period in years
- `--output-dir`: directory where output artifacts are created
- `--generate-password`: generate a certificate password automatically
- `--password`: supply a certificate password directly
- `--dry-run`: preview Azure-backed changes without applying them

Helper validation arguments:

- `--helper-app-client-id`
- `--helper-tenant-id`
- `--helper-certificate-path`
- `--helper-thumbprint`
- `--selected-site-url`

Environment variable support:

- `LS_CERT_PASSWORD`: lower-exposure alternative to passing `--password` on the
  command line

### CLI Launch Examples

Start the interactive CLI:

```bash
python -m legalserver_microsoft
```

Generate certificate artifacts only:

```bash
python -m legalserver_microsoft --mode certificate-only \
  --site example-demo \
  --years 1 \
  --generate-password
```

Preview a full SharePoint install without applying Azure changes:

```bash
python -m legalserver_microsoft --mode full-sharepoint-install --dry-run
```

Preview a full Site SSO install without applying Azure changes:

```bash
python -m legalserver_microsoft --mode full-sso-install --dry-run
```

Validate an existing selected-sites helper app:

```bash
python -m legalserver_microsoft --mode validate-selected-sites-helper \
  --helper-app-client-id <app-id> \
  --helper-tenant-id <tenant-id> \
  --helper-certificate-path /workspace/helper.pfx \
  --helper-thumbprint <thumbprint> \
  --selected-site-url https://tenant.sharepoint.com/sites/example
```

## Changelog

Release history is maintained in `CHANGELOG.md`.
