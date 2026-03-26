
# Power Platform OTAP Provisioning & DLP

PowerShell scripts to provision a standardized OTAP (Dev, Test, UAT, Prod) setup for Microsoft Power Platform, including Dataverse, Entra ID security groups, tenant isolation, and opinionated DLP policies.

## Scripts

- `Provision-PowerPlatform-OTAP.ps1`  
  End‑to‑end provisioning script for OTAP environments, Dataverse databases, environment‑level security groups, tenant isolation, and DLP policy stubs.

- `Provision-Powerplatform-DLP.ps1`  
  Classifies all DLP policies created/stubbed by the OTAP script into Business / Non‑Business / Blocked connector groups and creates an additional strict policy for the default environment.

## Prerequisites

- PowerShell 7.x (recommended) or Windows PowerShell 5.1.
- Power Platform PowerShell modules:
  - `Microsoft.PowerApps.Administration.PowerShell`
  - `Microsoft.PowerApps.PowerShell`
- Microsoft Graph modules:
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Groups` (for security group management).
- Permissions:
  - Power Platform admin / tenant admin.
  - Rights to create environments, Dataverse databases, security groups, and DLP policies.

Install the modules (run once per machine):

```powershell
Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser -AllowClobber -Force
Install-Module Microsoft.PowerApps.PowerShell                -Scope CurrentUser -AllowClobber -Force
Install-Module Microsoft.Graph.Authentication                -Scope CurrentUser -AllowClobber -Force
Install-Module Microsoft.Graph.Groups                        -Scope CurrentUser -AllowClobber -Force
```

## Execution order

1. `Provision-PowerPlatform-OTAP.ps1`  
   - Creates OTAP environments with Dataverse, configures tenant isolation, creates security groups, and scaffolds empty DLP policies.

2. `Provision-Powerplatform-DLP.ps1`  
   - Applies connector classification and finalizes DLP policies for all environments.

## OTAP environments

The OTAP provisioning script creates a standard set of Power Platform environments with Dataverse and associated Entra ID security groups.

### Environments and purpose

| Name    | Display name         | Type       | Purpose                                | Solutions model              |
|---------|----------------------|------------|----------------------------------------|------------------------------|
| PP-DEV  | Power Platform Dev   | Sandbox    | Development                            | Unmanaged solutions (build)  |
| PP-TEST | Power Platform Test  | Sandbox    | Test / QA                              | Managed solutions            |
| PP-UAT  | Power Platform UAT   | Sandbox    | User Acceptance Testing                | Managed solutions            |
| PP-PROD | Power Platform Prod  | Production | Production workloads                   | Managed only (no unmanaged)  |

All OTAP environments are created with a Dataverse database once the environment reaches a ready state. The script polls the environment state and only provisions Dataverse when the platform reports the environment as ready to avoid partial or failed setups.

### Region / location

By default, environments are created in the region specified by the `-Region` parameter (default: `europe`).

```powershell
.\Provision-PowerPlatform-OTAP.ps1 `
  -TenantId "<your-tenant-id>" `
  -Region "europe"
```

`-Region` must match a location supported by `New-AdminPowerAppEnvironment` in your tenant (for example `europe`, `westeurope`, `northeurope`, etc.).

### Environment access model

For each environment, the script creates an Entra ID security group and assigns it as **Environment Maker** on the corresponding environment.

- PP-DEV → `SG-PP-DEV-Makers`  
- PP-TEST → `SG-PP-TEST-Makers`  
- PP-UAT → `SG-PP-UAT-Makers`  
- PP-PROD → `SG-PP-PROD-Makers`

Grant maker access by adding users to these groups in Entra ID instead of assigning permissions directly in Power Platform.

The default environment is not structurally modified, but the script logs it and treats it as a “Personal productivity” environment so OTAP workloads stay in the dedicated Dev/Test/UAT/Prod environments.

### Tenant isolation

The OTAP script enforces tenant isolation:

- Checks the current tenant isolation policy via `Get-PowerAppTenantIsolationPolicy`.
- If isolation is disabled, it enables it with `Set-PowerAppTenantIsolationPolicy`, blocking all cross‑tenant connector connections by default.
- Optional: specific partner tenants can be whitelisted by adding their tenant IDs to `$allowedTenantIds` for controlled inbound/outbound connections.

This prevents data exfiltration via connectors to or from external tenants unless explicitly allowed.

## DLP policy design

This repository includes an opinionated baseline for Power Platform DLP policies, focusing on separating **business**, **non‑business**, and **blocked** connectors per environment stage.

### Policy overview

The DLP script manages the following policies:

- `DLP-Tenant-Base` – Tenant‑wide baseline policy (stub created by OTAP script, classified here).
- `DLP-Default-Strict` – Strict policy scoped to the default environment; Microsoft 365 only (no Dataverse/Dynamics).
- `DLP-PP-DEV` – Permissive policy for Dev; allows Microsoft 365, Dataverse, and selected developer connectors (e.g. GitHub).
- `DLP-PP-TEST` – Standard policy for Test; Microsoft 365 and Dataverse, no dev tooling.
- `DLP-PP-UAT` – Strict, production‑like policy for UAT; aligned with Prod.
- `DLP-PP-PROD` – Strict policy for Prod; Microsoft 365 and Dataverse only, consumer and most third‑party services blocked by default.

### Connector classification model

Connectors are grouped into:

- **Business** – Allowed for business data (core Microsoft 365, Dataverse/Dynamics, Azure, security connectors like Defender and Purview, Power BI, Power Platform admin connectors, etc.).
- **Non‑Business** – Allowed for non‑business data; used primarily for development scenarios in Dev (for example certain developer tools).
- **Blocked** – Explicitly disallowed for all environments (high‑risk consumer and collaboration services such as Dropbox, Box, Gmail, consumer Outlook/OneDrive, Twitter, Facebook, Slack, Trello).

Unlisted connectors are placed into a default group per policy:

- `DLP-Tenant-Base`, TEST, UAT, PROD: `blockedGroup` – all unlisted connectors are blocked, including new connectors added in the future.
- `DLP-PP-DEV`: `nonBusinessDataGroup` – unlisted connectors are allowed only for non‑business data in Dev.

### Environment‑specific behavior

| Environment | Policy name        | Business connectors                                       | Default group                 | Typical use                                                                 |
|------------|--------------------|-----------------------------------------------------------|-------------------------------|------------------------------------------------------------------------------|
| Tenant     | DLP-Tenant-Base    | Core Microsoft 365, Dataverse, Dynamics, Azure, security | `blockedGroup`                | Global baseline; blocks high‑risk consumer/third‑party connectors.          |
| Default    | DLP-Default-Strict | Subset of Microsoft 365 (no Dataverse/Dynamics)          | `blockedGroup`                | Safe default environment for light productivity scenarios.                  |
| Dev        | DLP-PP-DEV         | Tenant base + dev‑only (e.g. GitHub)                     | `nonBusinessDataGroup`        | Experimentation and POCs with extra dev tooling, still blocking consumers.  |
| Test       | DLP-PP-TEST        | Tenant base (no dev‑only connectors)                     | `blockedGroup`                | Functional / integration testing close to production controls.              |
| UAT        | DLP-PP-UAT         | Tenant base                                              | `blockedGroup`                | User acceptance with near‑prod data protections.                            |
| Prod       | DLP-PP-PROD        | Tenant base                                              | `blockedGroup`                | Live production; most restrictive, blocks all non‑approved connectors.      |

### How the DLP script works

- Loads all existing DLP policies into a cache to avoid duplicate creation and inconsistent reads.
- Ensures each named policy exists and is scoped to the correct environment (where applicable) using `New-AdminDlpPolicy` and `Set-DlpPolicy`.
- Applies connector group classification via `Set-DlpPolicy` (V1), because it is the only cmdlet that supports direct connector group manipulation.
- Supports a `-DryRun` switch to show what would change without committing any updates.

## Usage

### Provision OTAP environments

```powershell
.\Provision-PowerPlatform-OTAP.ps1 `
  -TenantId "<your-tenant-id>" `
  -Region "europe"
```

Key parameters (update to match your usage):

- `-TenantId` – Azure AD tenant ID.
- `-Region` – Power Platform region (default `europe`).
- `-DryRun` – Optional; if specified, the script only logs actions without making changes.
- `-ApplicationId`, `-ClientSecret` – Optional service principal credentials for unattended/CI/CD runs.

### Apply DLP policies

```powershell
.\Provision-Powerplatform-DLP.ps1 `
  -TenantId "<your-tenant-id>"
```

Key parameters:

- `-TenantId` – Azure AD tenant ID (must match OTAP script).
- `-DryRun` – Optional; preview classification changes without applying them.
- `-ApplicationId`, `-ClientSecret` – Optional service principal credentials for unattended/CI/CD runs.

## Authentication

Both scripts support:

- Interactive sign‑in using `Add-PowerAppsAccount` and `Connect-MgGraph` when no service principal is supplied.
- Non‑interactive authentication via service principal (`-ApplicationId` and `-ClientSecret`) for automation and pipelines.

Ensure the identity (user or service principal) has the required admin permissions in both Power Platform and Entra ID.

## Output and logging

- OTAP script:
  - Writes progress and status for environment creation, Dataverse provisioning, tenant isolation, security group creation, and DLP stub creation.
- DLP script:
  - Logs classification actions per policy (business/non‑business/blocked connectors and default group).

You can pipe the output to `Tee-Object` to capture logs:

```powershell
.\Provision-PowerPlatform-OTAP.ps1 ... | Tee-Object -FilePath .\otap-provision.log
.\Provision-Powerplatform-DLP.ps1 ... | Tee-Object -FilePath .\dlp-classification.log
```

## Disclaimer

These scripts are provided as‑is, without warranty. Test them in a non‑production tenant or sandbox environment before using in production and review all connector lists and environment definitions against your organisation’s policies.
