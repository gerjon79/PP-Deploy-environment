
# Power Platform OTAP Provisioning & DLP

PowerShell scripts to provision a standardized OTAP (Dev, Test, Prod) setup for Microsoft Power Platform, including Dataverse, Entra ID security groups, tenant isolation, Managed Environments, and opinionated DLP policies.

Follows Microsoft's recommended ALM and governance guidance for Power Platform.

## Scripts

- `Provision-PowerPlatform-OTAP.ps1`  
  End‑to‑end provisioning script for environments, Dataverse databases, environment‑level security groups, tenant isolation, Managed Environments governance, Solution Checker enforcement, backup retention, and DLP policy stubs.

- `Provision-Powerplatform-DLP.ps1`  
  Classifies all DLP policies created/stubbed by the OTAP script into Business / Non‑Business / Blocked connector groups and creates an additional strict policy for the default environment.

## Prerequisites

- PowerShell 7.x (recommended) or Windows PowerShell 5.1.
- Power Platform PowerShell modules:
  - `Microsoft.PowerApps.Administration.PowerShell`
  - `Microsoft.PowerApps.PowerShell`
- Microsoft Graph modules:
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Groups`
- Permissions:
  - Power Platform admin / tenant admin.
  - Rights to create environments, Dataverse databases, security groups, and DLP policies.
- Licensing:
  - Managed Environments requires **Power Platform Premium** or a per-app plan for users in the Test and Prod environments.

Install the modules (run once per machine):

```powershell
Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser -AllowClobber -Force
Install-Module Microsoft.PowerApps.PowerShell                -Scope CurrentUser -AllowClobber -Force
Install-Module Microsoft.Graph.Authentication                -Scope CurrentUser -AllowClobber -Force
Install-Module Microsoft.Graph.Groups                        -Scope CurrentUser -AllowClobber -Force
```

## Execution order

1. `Provision-PowerPlatform-OTAP.ps1`  
   Creates environments with Dataverse, enables Managed Environments and governance settings, configures tenant isolation, creates security groups, and scaffolds empty DLP policies.

2. `Provision-Powerplatform-DLP.ps1`  
   Applies connector classification and finalizes DLP policies for all environments.

## OTAP environments

The OTAP provisioning script creates a three-tier set of Power Platform environments with Dataverse and associated Entra ID security groups, per Microsoft's ALM guidance.

### Environments and purpose

| Name    | Display name        | Type       | Managed Env | Solution Checker | Backup retention | Purpose                              | Solutions model             |
|---------|---------------------|------------|-------------|------------------|------------------|--------------------------------------|-----------------------------|
| AI-DEV  | AI Agents Dev  | Sandbox    | No          | Off              | 7 days (default) | Development                          | Unmanaged solutions (build) |
| AI-TEST | AI Agents Test | Sandbox    | Yes         | Warn             | 7 days (default) | Test + User Acceptance Testing       | Managed solutions           |
| AI-PROD | AI Agents Prod | Production | Yes         | Block            | 28 days          | Production workloads                 | Managed only (no unmanaged) |

> **Test + UAT combined:** Microsoft's ALM guidance allows combining Test and UAT into a single stage for most organisations. If your compliance requirements mandate a separate UAT sign-off environment, duplicate the `AI-TEST` entry in `$envDefinitions` and adjust accordingly.

> **Per-maker Dev environments:** For larger teams, Microsoft recommends provisioning one personal Dev environment per maker rather than a shared `AI-DEV`. Provision those individually or via Power Platform Pipelines. The shared `AI-DEV` environment is a pragmatic default for smaller teams.

All environments are provisioned with a Dataverse database. The script polls the environment state and only provisions Dataverse when the platform reports the environment as ready.

### Managed Environments

Managed Environments (enabled on Test and Prod) provide:

- **Sharing limits** — restrict canvas app sharing to security groups.
- **Maker welcome content** — customise the onboarding experience for new makers.
- **Weekly admin digest** — automated email summary of environment activity.
- **Solution Checker enforcement** — block or warn on solution imports with high-severity issues.
- **IP firewall and customer-managed keys support** (additional configuration required).

### Solution Checker enforcement

| Environment | Level  | Behaviour                                                        |
|-------------|--------|------------------------------------------------------------------|
| AI-DEV      | None   | No enforcement; makers can import freely.                        |
| AI-TEST     | Warn   | Checker runs on import; issues are flagged but import proceeds.  |
| AI-PROD     | Block  | Import is blocked if the checker finds high-severity issues.     |

### Backup retention

| Environment | Retention  |
|-------------|------------|
| AI-DEV      | 7 days (platform default) |
| AI-TEST     | 7 days (platform default) |
| AI-PROD     | 28 days (maximum)         |

### Region / location

By default, environments are created in the region specified by the `-Region` parameter (default: `europe`).

`-Region` must match a location supported by `New-AdminPowerAppEnvironment` in your tenant (for example `europe`, `westeurope`, `northeurope`, etc.).

### Language and currency

The `-Language` (default: `English`) and `-Currency` (default: `EUR`) parameters control the Dataverse database locale. See [Microsoft language collation docs](https://learn.microsoft.com/en-us/power-platform/admin/language-collations) for supported values.

### Environment access model

For each environment, the script creates an Entra ID security group and assigns it as **Environment Maker** on the corresponding environment.

- AI-DEV  → `SG-AI-DEV-Makers`
- AI-TEST → `SG-AI-TEST-Makers`
- AI-PROD → `SG-AI-PROD-Makers`

Grant maker access by adding users to these groups in Entra ID instead of assigning permissions directly in Power Platform.

The default environment is not structurally modified, but the script logs it and treats it as a "Personal productivity" environment so OTAP workloads stay in the dedicated environments.

### Tenant isolation

The OTAP script enforces tenant isolation:

- Checks the current tenant isolation policy via `Get-PowerAppTenantIsolationPolicy`.
- If isolation is disabled, enables it via `Set-PowerAppTenantIsolationPolicy`, blocking all cross-tenant connector connections by default.
- Optional: specific partner tenants can be whitelisted by adding their tenant IDs to `$allowedTenantIds`.

This prevents data exfiltration via connectors to or from external tenants unless explicitly allowed.

## DLP policy design

This repository includes an opinionated baseline for Power Platform DLP policies, separating **business**, **non‑business**, and **blocked** connectors per environment stage.

### Policy overview

| Policy name        | Scope       | Purpose                                                              |
|--------------------|-------------|----------------------------------------------------------------------|
| DLP-Tenant-Base    | Tenant-wide | Global baseline; blocks high-risk consumer/third-party connectors.  |
| DLP-Default-Strict | Default env | Microsoft 365 only; no Dataverse/Dynamics.                          |
| DLP-AI-DEV         | AI-DEV      | Permissive; allows dev tooling (e.g. GitHub) in addition to base.  |
| DLP-AI-TEST        | AI-TEST     | Standard; Microsoft 365 and Dataverse, no dev tooling.             |
| DLP-AI-PROD        | AI-PROD     | Strict; Microsoft 365 and Dataverse only, all else blocked.        |

### Connector classification model

- **Business** — Allowed for business data (core Microsoft 365, Dataverse/Dynamics, Azure, security connectors like Defender and Purview, Power BI, Power Platform admin connectors).
- **Non‑Business** — Allowed for non-business data; used for development scenarios in Dev.
- **Blocked** — Explicitly disallowed (high-risk consumer services: Dropbox, Box, Gmail, consumer Outlook/OneDrive, Twitter, Facebook, Slack, Trello, etc.).

Unlisted connectors default to:

- `DLP-Tenant-Base`, TEST, PROD: `blockedGroup` — all unlisted connectors are blocked, including future connectors.
- `DLP-AI-DEV`: `nonBusinessDataGroup` — unlisted connectors allowed for non-business data only.

### How the DLP script works

- Loads all existing DLP policies into a cache to avoid duplicate creation.
- Ensures each named policy exists and is scoped to the correct environment via `New-AdminDlpPolicy` and `Set-DlpPolicy`.
- Applies connector group classification via `Set-DlpPolicy` (V1).
- Supports a `-DryRun` switch to preview changes without committing.

## Usage

### Provision OTAP environments

```powershell
.\Provision-PowerPlatform-OTAP.ps1 `
  -TenantId  "<your-tenant-id>" `
  -Region    "europe" `
  -Language  "English" `
  -Currency  "EUR"
```

Key parameters:

| Parameter        | Required | Default   | Description                                                |
|------------------|----------|-----------|------------------------------------------------------------|
| `-TenantId`      | Yes      | —         | Azure AD tenant ID.                                        |
| `-Region`        | No       | `europe`  | Power Platform region for environment creation.            |
| `-Language`      | No       | `English` | Dataverse database language.                               |
| `-Currency`      | No       | `EUR`     | Dataverse database currency (ISO 4217 code).               |
| `-DryRun`        | No       | `$false`  | Log actions only; no changes are made.                     |
| `-ApplicationId` | No       | —         | Service principal app ID for unattended/CI-CD runs.        |
| `-ClientSecret`  | No       | —         | Service principal secret for unattended/CI-CD runs.        |

### Apply DLP policies

```powershell
.\Provision-Powerplatform-DLP.ps1 `
  -TenantId "<your-tenant-id>"
```

Key parameters:

| Parameter        | Required | Default  | Description                                                |
|------------------|----------|----------|------------------------------------------------------------|
| `-TenantId`      | Yes      | —        | Azure AD tenant ID (must match OTAP script).               |
| `-DryRun`        | No       | `$false` | Preview classification changes without applying them.      |
| `-ApplicationId` | No       | —        | Service principal app ID for unattended/CI-CD runs.        |
| `-ClientSecret`  | No       | —        | Service principal secret for unattended/CI-CD runs.        |

## Authentication

Both scripts support:

- **Interactive sign-in** using `Add-PowerAppsAccount` and `Connect-MgGraph` when no service principal is supplied.
- **Non-interactive (service principal)** via `-ApplicationId` and `-ClientSecret` for automation and pipelines.

Ensure the identity (user or service principal) has the required admin permissions in both Power Platform and Entra ID.

## Output and logging

Pipe output to `Tee-Object` to capture a log file:

```powershell
.\Provision-PowerPlatform-OTAP.ps1 -TenantId "<id>" | Tee-Object -FilePath .\otap-provision.log
.\Provision-Powerplatform-DLP.ps1  -TenantId "<id>" | Tee-Object -FilePath .\dlp-classification.log
```

## Disclaimer

These scripts are provided as-is, without warranty. Test them in a non-production tenant or sandbox environment before using in production and review all connector lists and environment definitions against your organisation's policies.
