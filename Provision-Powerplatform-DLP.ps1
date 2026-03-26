<#
.SYNOPSIS
Baseline DLP connector classification for all Power Platform policies.

.DESCRIPTION
This script owns ALL DLP connector group classification. It must be run AFTER
Provision-PowerPlatform-OTAP.ps1, which creates the empty policy stubs this
script populates.

Policies classified by this script:
  - DLP-Tenant-Base       : tenant-wide baseline (stub created by OTAP script).
  - DLP-Default-Strict    : strict policy for the default environment (created here).
  - DLP-PP-DEV            : permissive, allows developer connectors (stub by OTAP).
  - DLP-PP-TEST           : standard, same as tenant base (stub by OTAP).
  - DLP-PP-UAT            : strict, production-like (stub by OTAP).
  - DLP-PP-PROD           : strict, mirrors tenant base (stub by OTAP).

Review all connector lists before running in production.

Prerequisites (run once per machine):
    Install-Module -Name Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser -AllowClobber -Force
    Install-Module -Name Microsoft.PowerApps.PowerShell                -Scope CurrentUser -AllowClobber -Force

Provision-PowerPlatform-OTAP.ps1   →  run FIRST
  ✅ Environments, Dataverse, Security Groups
  ✅ Empty DLP policy stubs (no connector rules)

Provision-Powerplatform-DLP.ps1    →  run SECOND
  ✅ All connector classification (Business / NonBusiness / Blocked)
  ✅ DLP-Default-Strict (created + classified here)
  ✅ DLP-Tenant-Base, DLP-PP-DEV/TEST/UAT/PROD (classified here)

#>

param(
    # TenantId is required so the script always targets the correct tenant,
    # matching the authentication contract of Provision-PowerPlatform-OTAP.ps1.
    [Parameter(Mandatory = $true)]
    [string] $TenantId,

    # Renamed from $WhatIf to $DryRun to avoid conflict with PowerShell's
    # built-in -WhatIf common parameter.
    [Parameter(Mandatory = $false)]
    [switch] $DryRun,

    # Optional service principal credentials for unattended/CI-CD runs.
    [Parameter(Mandatory = $false)]
    [string] $ApplicationId,

    [Parameter(Mandatory = $false)]
    [string] $ClientSecret
)

# ---------------------------------------------------------------------------
# 1. Import modules
# ---------------------------------------------------------------------------
Import-Module Microsoft.PowerApps.Administration.PowerShell -ErrorAction Stop
Import-Module Microsoft.PowerApps.PowerShell                -ErrorAction Stop

# ---------------------------------------------------------------------------
# 2. Authenticate — mirrors OTAP script auth pattern
# ---------------------------------------------------------------------------
Write-Host "Authenticating to Power Platform..." -ForegroundColor Cyan

if ($ApplicationId -and $ClientSecret) {
    Add-PowerAppsAccount -TenantId $TenantId -ApplicationId $ApplicationId -ClientSecret $ClientSecret | Out-Null
} else {
    Add-PowerAppsAccount -TenantId $TenantId | Out-Null
}

if ($DryRun) {
    Write-Warning "Running in DryRun mode - no changes will be committed."
}

# Load all existing DLP policies into a script-scoped cache once.
# All helpers read from and refresh this cache instead of calling
# Get-DlpPolicy repeatedly, which prevents duplicate creation caused
# by stale/inconsistent API responses between calls.
Write-Host "Loading existing DLP policies..." -ForegroundColor Cyan
$script:dlpPolicyCache = Get-DlpPolicy
Write-Host "  Found $($script:dlpPolicyCache.Count) existing policy/policies." -ForegroundColor Gray

# ---------------------------------------------------------------------------
# Helper: respect -DryRun and surface errors consistently
# ---------------------------------------------------------------------------
function Invoke-IfNotDryRun {
    param([scriptblock] $ScriptBlock)

    if (-not $DryRun) {
        try {
            & $ScriptBlock
        } catch {
            Write-Warning "Command failed: $_"
        }
    } else {
        Write-Host "[DryRun] " -NoNewline
        Write-Host $ScriptBlock.ToString().Trim() -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------------------
# Helper: apply Business / NonBusiness / Blocked connector groups to a policy
#
# NOTE: Set-DlpPolicy is the V1 cmdlet. It is used here intentionally because
# it is the only PowerShell cmdlet that supports direct connector group
# manipulation via the properties object. Set-AdminDlpPolicy (V2) handles
# environment scoping only and does not replace this functionality.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Helper: get a DLP policy by display name, creating it if missing.
# If $EnvironmentName is supplied the policy is scoped to that environment.
# Returns the policy object, or $null on failure / DryRun.
# ---------------------------------------------------------------------------
function Get-OrCreateDlpPolicy {
    param(
        [string] $DisplayName,
        [string] $EnvironmentName = $null
    )

    # Use the shared cache; trim and case-insensitive match to avoid false misses.
    $policy = $script:dlpPolicyCache | Where-Object { $_.DisplayName.Trim() -ieq $DisplayName.Trim() }
    if ($policy) {
        Write-Host "  Policy '$DisplayName' already exists." -ForegroundColor Yellow
        return $policy
    }

    Write-Host "  Policy '$DisplayName' not found - creating stub..." -ForegroundColor Yellow
    if ($DryRun) {
        Write-Host "[DryRun] New-AdminDlpPolicy -DisplayName '$DisplayName'" -ForegroundColor Gray
        return $null
    }

    try {
        $result = New-AdminDlpPolicy -DisplayName $DisplayName -ErrorAction Stop
        if (-not $result) { throw "New-AdminDlpPolicy returned no result." }
        Write-Host "  Created policy stub '$DisplayName'." -ForegroundColor Green

        # Refresh cache so the new policy is visible for the scope step and
        # for any subsequent existence checks in this script run.
        $script:dlpPolicyCache = Get-DlpPolicy

        if ($EnvironmentName) {
            $policyObj = $script:dlpPolicyCache | Where-Object { $_.DisplayName.Trim() -ieq $DisplayName.Trim() }
            if ($policyObj) {
                $upd = $policyObj.properties
                $upd.environmentType = 'SingleEnvironment'
                $upd.environments    = @([PSCustomObject]@{ id = $EnvironmentName })
                Set-DlpPolicy -PolicyName $policyObj.name -UpdatedPolicy $upd -ErrorAction Stop | Out-Null
                Write-Host "  Scoped '$DisplayName' to environment $EnvironmentName." -ForegroundColor Green
                $script:dlpPolicyCache = Get-DlpPolicy
            }
        }
    } catch {
        Write-Warning "Failed to create/scope policy '$DisplayName': $_"
        return $null
    }

    return $script:dlpPolicyCache | Where-Object { $_.DisplayName.Trim() -ieq $DisplayName.Trim() }
}

function Set-PolicyConnectorGroups {
    param(
        [string]   $PolicyDisplayName,
        [string[]] $BusinessConnectors,
        [string[]] $NonBusinessConnectors,
        [string[]] $BlockedConnectors,

        # Controls where connectors land that are not explicitly listed above.
        # 'blockedGroup'         = all unlisted (third-party) connectors are BLOCKED.
        # 'nonBusinessDataGroup' = all unlisted connectors are Non-Business (DEV only).
        [ValidateSet('blockedGroup','nonBusinessDataGroup')]
        [string]   $DefaultGroup = 'nonBusinessDataGroup'
    )

    $policy = $script:dlpPolicyCache | Where-Object { $_.DisplayName.Trim() -ieq $PolicyDisplayName.Trim() }
    if (-not $policy) {
        Write-Warning "Policy '$PolicyDisplayName' not found. Skipping classification."
        return
    }

    Write-Host "  Classifying connectors for '$PolicyDisplayName' (default group: $DefaultGroup)..." -ForegroundColor Cyan

    if ($DryRun) {
        Write-Host "[DryRun] Set-DlpPolicy '$PolicyDisplayName'" -ForegroundColor Gray
        Write-Host "  Business     : $($BusinessConnectors -join ', ')" -ForegroundColor Gray
        Write-Host "  NonBusiness  : $($NonBusinessConnectors -join ', ')" -ForegroundColor Gray
        Write-Host "  Blocked      : $($BlockedConnectors -join ', ')" -ForegroundColor Gray
        Write-Host "  Default group: $DefaultGroup (all unlisted connectors go here)" -ForegroundColor Gray
        return
    }

    $updated = $policy.properties

    # Reset all groups before re-applying
    $updated.connectorGroups.businessDataGroup    = @()
    $updated.connectorGroups.nonBusinessDataGroup = @()
    $updated.connectorGroups.blockedGroup         = @()

    function Add-Connector([ref]$group, [string[]]$apis) {
        foreach ($api in $apis) {
            if ([string]::IsNullOrWhiteSpace($api)) { continue }
            $group.Value += @{ id = $api }
        }
    }

    Add-Connector ([ref]$updated.connectorGroups.businessDataGroup)    $BusinessConnectors
    Add-Connector ([ref]$updated.connectorGroups.nonBusinessDataGroup)  $NonBusinessConnectors
    Add-Connector ([ref]$updated.connectorGroups.blockedGroup)          $BlockedConnectors

    # Any connector not explicitly listed above lands in the default group.
    # Setting this to 'blockedGroup' automatically blocks ALL third-party
    # connectors, including any new ones added to the platform in future.
    $updated.defaultGroupId = $DefaultGroup

    try {
        Set-DlpPolicy -PolicyName $policy.name -UpdatedPolicy $updated | Out-Null
        Write-Host "  Done." -ForegroundColor Green
    } catch {
        Write-Warning "Failed to classify policy '$PolicyDisplayName': $_"
    }
}

# ---------------------------------------------------------------------------
# Shared connector lists
# ---------------------------------------------------------------------------

# All Microsoft first-party connectors — allowed as Business in every environment.
# Organised by product family. Review and comment out any your org does not use.
$coreBusinessConnectors = @(

    # --- Microsoft 365 / Productivity ---
    "shared_sharepointonline",              # SharePoint Online
    "shared_office365",                     # Office 365 Users
    "shared_office365groups",               # Microsoft 365 Groups
    "shared_office365outlook",              # Outlook (Office 365)
    "shared_onedriveforbusiness",           # OneDrive for Business
    "shared_teams",                         # Microsoft Teams
    "shared_excelonlinebusiness",           # Excel Online (Business)
    "shared_wordonlinebusiness",            # Word Online (Business)
    "shared_powerpointonlinebusiness",      # PowerPoint Online (Business)
    "shared_onenote",                       # OneNote
    "shared_microsoftforms",                # Microsoft Forms
    "shared_planner",                       # Microsoft Planner
    "shared_todo",                          # Microsoft To Do
    "shared_yammer",                        # Viva Engage (Yammer)
    "shared_microsoftbookings",             # Microsoft Bookings
    "shared_microsoftlists",                # Microsoft Lists
    "shared_approvals",                     # Microsoft Approvals
    "shared_officescripts",                 # Office Scripts
    "shared_visio",                         # Microsoft Visio
    "shared_project",                       # Microsoft Project
    "shared_skypeforbusiness",              # Skype for Business Online
    "shared_kaizala",                       # Microsoft Kaizala

    # --- Dataverse / Dynamics 365 ---
    "shared_commondataservice",             # Dataverse (legacy connector name)
    "shared_commondataserviceforapps",      # Dataverse
    "shared_dynamicscrmonline",             # Dynamics 365
    "shared_dynamicscrm",                   # Dynamics CRM
    "shared_dynamicsax",                    # Dynamics AX
    "shared_dynamicsaxoperations",          # Dynamics 365 Finance & Operations
    "shared_d365businesscentral",           # Dynamics 365 Business Central

    # --- Power Platform ---
    "shared_powerbi",                       # Power BI
    "shared_powervirtualagents",            # Copilot Studio (Power Virtual Agents)
    "shared_powerautomatemanagement",       # Power Automate Management
    "shared_powerappsforappmakers",         # Power Apps for App Makers
    "shared_powerappsnotification",         # Power Apps Notification
    "shared_powerplatformforadmins",        # Power Platform for Admins

    # --- Azure Platform ---
    "shared_azuread",                       # Azure Active Directory
    "shared_azureblob",                     # Azure Blob Storage
    "shared_azurequeuestorage",             # Azure Queue Storage
    "shared_azuretablestorage",             # Azure Table Storage
    "shared_azurefunctions",                # Azure Functions
    "shared_azureeventhubs",                # Azure Event Hubs
    "shared_azureeventgrid",                # Azure Event Grid
    "shared_azureservicebus",               # Azure Service Bus
    "shared_azureautomation",               # Azure Automation
    "shared_azuredatafactory",              # Azure Data Factory
    "shared_azuredatalake",                 # Azure Data Lake
    "shared_azureloganalytics",             # Azure Log Analytics
    "shared_azuremonitor",                  # Azure Monitor
    "shared_keyvault",                      # Azure Key Vault
    "shared_sql",                           # SQL Server / Azure SQL
    "shared_azureopenai",                   # Azure OpenAI
    "shared_azuredevops",                   # Azure DevOps

    # --- Azure AI / Cognitive Services ---
    "shared_cognitiveservicestextanalytics",    # Azure Text Analytics
    "shared_cognitiveservicescomputervision",   # Azure Computer Vision
    "shared_cognitiveservicescontentmoderator", # Azure Content Moderator
    "shared_cognitiveservicesspeech",           # Azure Speech Services
    "shared_bingmaps",                          # Bing Maps
    "shared_bingsearch",                        # Bing Search

    # --- Microsoft Security ---
    "shared_microsoftdefenderatp",          # Microsoft Defender for Endpoint
    "shared_azuresentinel",                 # Microsoft Sentinel
    "shared_microsoftpurviewinformationprotection",  # Microsoft Purview

    # --- Notifications / Misc Microsoft ---
    "shared_notifications",                 # Microsoft Notifications
    "shared_microsofttranslator",           # Microsoft Translator
    "shared_microsoftsearch"                # Microsoft Search
)

# Extra connectors permitted in DEV only — non-Microsoft developer tooling.
$devOnlyConnectors = @(
    "shared_github"                         # GitHub (Microsoft-owned, dev tool only)
)

# High-risk consumer connectors — blocked in all environments.
$blockedConnectors = @(
    "shared_dropbox",
    "shared_box",
    "shared_gmail",
    "shared_googlecontacts",
    "shared_googlecalendar",
    "shared_twitter",
    "shared_facebook",
    "shared_onedrive",                  # Consumer OneDrive (not ODB)
    "shared_outlook.com",               # Consumer Outlook
    "shared_slack",
    "shared_trello"
)

# ---------------------------------------------------------------------------
# 3. DLP-Tenant-Base — classify only (stub created by OTAP script)
# ---------------------------------------------------------------------------
Write-Host "`nClassifying DLP-Tenant-Base..." -ForegroundColor Cyan

$tenantPolicyName = 'DLP-Tenant-Base'
# Ensure the stub exists (created by OTAP script; created here if missing).
$null = Get-OrCreateDlpPolicy -DisplayName $tenantPolicyName

Set-PolicyConnectorGroups `
    -PolicyDisplayName    $tenantPolicyName `
    -BusinessConnectors   $coreBusinessConnectors `
    -NonBusinessConnectors @() `
    -BlockedConnectors    $blockedConnectors `
    -DefaultGroup         'blockedGroup'

# ---------------------------------------------------------------------------
# 4. DLP-Default-Strict — created and classified here (exclusive to this script)
#    Applies to the default environment only. Stricter than tenant base:
#    no Dataverse/Dynamics, only core M365.
# ---------------------------------------------------------------------------
Write-Host "`nEnsuring DLP-Default-Strict exists for the default environment..." -ForegroundColor Cyan

$defaultEnv = Get-AdminPowerAppEnvironment | Where-Object { $_.IsDefault -eq $true }

if (-not $defaultEnv) {
    Write-Warning "Default environment not found. Skipping DLP-Default-Strict."
} else {
    $defaultPolicyName = 'DLP-Default-Strict'
    # Ensure stub exists and is scoped to the default environment.
    # Get-OrCreateDlpPolicy handles creation + scoping via Set-DlpPolicy (V1).
    $null = Get-OrCreateDlpPolicy -DisplayName $defaultPolicyName -EnvironmentName $defaultEnv.EnvironmentName

    # Classify: M365 only, no Dataverse/Dynamics, block all consumer services.
    $defaultBusinessConnectors = @(
        "shared_sharepointonline",
        "shared_office365",
        "shared_office365groups",
        "shared_office365outlook",
        "shared_onedriveforbusiness",
        "shared_teams",
        "shared_excelonlinebusiness"
    )

    Set-PolicyConnectorGroups `
        -PolicyDisplayName    $defaultPolicyName `
        -BusinessConnectors   $defaultBusinessConnectors `
        -NonBusinessConnectors @() `
        -BlockedConnectors    $blockedConnectors `
        -DefaultGroup         'blockedGroup'
}

# ---------------------------------------------------------------------------
# 5. OTAP per-environment DLP policies — classify only (stubs by OTAP script)
#
#    Strictness ladder:
#      DEV  (Permissive) : core M365 + Dataverse + developer connectors
#      TEST (Standard)   : core M365 + Dataverse, no dev tools
#      UAT  (Strict)     : core M365 + Dataverse, mirrors Prod
#      PROD (Strict)     : core M365 + Dataverse only, most locked down
# ---------------------------------------------------------------------------
Write-Host "`nClassifying OTAP per-environment DLP policies..." -ForegroundColor Cyan

# Fetch current environments so we can resolve EnvironmentName for scoping.
$currentEnvs = Get-AdminPowerAppEnvironment

$otapPolicies = @(
    @{
        PolicyName     = 'DLP-PP-DEV'
        Label          = 'DEV  (Permissive)'
        EnvDisplayName = 'Power Platform Dev'
        Business       = $coreBusinessConnectors + $devOnlyConnectors
        NonBusiness    = @()
        Blocked        = $blockedConnectors
        DefaultGroup   = 'nonBusinessDataGroup'   # Unlisted connectors are Non-Business in DEV
    },
    @{
        PolicyName     = 'DLP-PP-TEST'
        Label          = 'TEST (Standard)'
        EnvDisplayName = 'Power Platform Test'
        Business       = $coreBusinessConnectors
        NonBusiness    = @()
        Blocked        = $blockedConnectors
        DefaultGroup   = 'blockedGroup'            # All third-party connectors blocked
    },
    @{
        PolicyName     = 'DLP-PP-UAT'
        Label          = 'UAT  (Strict)'
        EnvDisplayName = 'Power Platform UAT'
        Business       = $coreBusinessConnectors
        NonBusiness    = @()
        Blocked        = $blockedConnectors
        DefaultGroup   = 'blockedGroup'            # All third-party connectors blocked
    },
    @{
        PolicyName     = 'DLP-PP-PROD'
        Label          = 'PROD (Strict)'
        EnvDisplayName = 'Power Platform Prod'
        Business       = $coreBusinessConnectors
        NonBusiness    = @()
        Blocked        = $blockedConnectors
        DefaultGroup   = 'blockedGroup'            # All third-party connectors blocked
    }
)

foreach ($entry in $otapPolicies) {
    Write-Host "`n$($entry.Label) -> $($entry.PolicyName)" -ForegroundColor Cyan

    # Resolve the environment this policy should be scoped to,
    # so Get-OrCreateDlpPolicy can scope it if the stub is missing.
    $scopeEnv = $currentEnvs | Where-Object { $_.DisplayName -eq $entry.EnvDisplayName }
    $scopeEnvName = if ($scopeEnv) { $scopeEnv.EnvironmentName } else { $null }

    $null = Get-OrCreateDlpPolicy -DisplayName $entry.PolicyName -EnvironmentName $scopeEnvName

    Set-PolicyConnectorGroups `
        -PolicyDisplayName     $entry.PolicyName `
        -BusinessConnectors    $entry.Business `
        -NonBusinessConnectors $entry.NonBusiness `
        -BlockedConnectors     $entry.Blocked `
        -DefaultGroup          $entry.DefaultGroup
}

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
Write-Host "`nDLP classification complete$(if ($DryRun) { ' (DryRun - no changes were applied)' })." -ForegroundColor Cyan
Write-Host "Review all policies in: Power Platform Admin Center > Policies > Data policies." -ForegroundColor Gray
Write-Host "Adjust connector lists per environment as your organisation's requirements evolve." -ForegroundColor Gray
