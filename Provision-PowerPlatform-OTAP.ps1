<#
.SYNOPSIS
End-to-end provisioning script for a Power Platform OTAP setup (Dev, Test, Prod) including DLP scaffolding.

.DESCRIPTION
This script uses the Microsoft.PowerApps.Administration.PowerShell module to:
- Restrict environment creation to admins.
- Enable tenant isolation to block all cross-tenant connector connections.
- Create Dev, Test (Test+UAT combined) and Prod environments with Dataverse.
- Enable Managed Environments on Test and Prod (Microsoft-recommended governance tier).
- Set 28-day backup retention on Prod.
- Enable Solution Checker enforcement (Warn on Test, Block on Prod).
- (Optionally) tag/describe the Default environment as Personal Productivity.
- Create one Azure AD security group per environment (via Microsoft.Graph).
- Assign each security group to its environment as EnvironmentMaker.
- Create EMPTY DLP policy stubs (DLP-Tenant-Base + one per environment).
  Connector group classification is owned by Provision-PowerPlatform-DLP.ps1.
  Run that script AFTER this one to apply Business/NonBusiness/Blocked rules.

Environment topology (aligns with Microsoft ALM guidance):
  PP-DEV   — Sandbox. Unmanaged solutions. Shared dev environment.
             NOTE: For larger teams Microsoft recommends one personal Dev environment
             per maker. Provision those individually or via Power Platform Pipelines.
  PP-TEST  — Sandbox + Managed Environment. Managed solutions. Combined Test + UAT
             stage (sufficient for most organisations; split if compliance requires
             a separate UAT sign-off environment).
  PP-PROD  — Production + Managed Environment. Managed solutions only.
             28-day backup retention. Solution Checker set to Block.

Tenant isolation (section 5):
  Checks Get-PowerAppTenantIsolationPolicy. If isolation is disabled it is
  enabled via Set-PowerAppTenantIsolationPolicy. This prevents Power Platform
  connectors from authenticating to or from any external tenant, enforcing a
  hard boundary for all inbound and outbound cross-tenant connections.
  To whitelist a specific partner tenant, add its GUID to $allowedTenantIds.

You MUST review and adapt:
- Region and data-residency requirements (default: europe).
- Language and currency for Dataverse databases.
- Security role assignments beyond environment-level permissions.
- $allowedTenantIds if cross-tenant connections to specific partners are required.

Prerequisites (run once per machine):
    Install-Module -Name Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser -AllowClobber -Force
    Install-Module -Name Microsoft.PowerApps.PowerShell                -Scope CurrentUser -AllowClobber -Force
    Install-Module -Name Microsoft.Graph.Groups                        -Scope CurrentUser -AllowClobber -Force
    Install-Module -Name Microsoft.Graph.Authentication                -Scope CurrentUser -AllowClobber -Force

Based on Microsoft docs for environment management and DLP PowerShell.

Provision-PowerPlatform-OTAP.ps1   →  run FIRST
  ✅ Environments, Dataverse, Security Groups
  ✅ Managed Environments on Test and Prod
  ✅ 28-day backup retention on Prod
  ✅ Solution Checker enforcement (Warn on Test, Block on Prod)
  ✅ Tenant isolation (cross-tenant connections blocked)
  ✅ Empty DLP policy stubs (no connector rules)

Provision-Powerplatform-DLP.ps1    →  run SECOND
  ✅ All connector classification (Business / NonBusiness / Blocked)
  ✅ DLP-Default-Strict (created + classified here)
  ✅ DLP-Tenant-Base, DLP-PP-DEV/TEST/PROD (classified here)

#>

param(
    [Parameter(Mandatory = $true)]
    [string] $TenantId,

    [Parameter(Mandatory = $false)]
    [string] $Region = 'europe',

    # Language for Dataverse databases. 1033 = English, 1043 = Dutch.
    # See: https://learn.microsoft.com/en-us/power-platform/admin/language-collations
    [Parameter(Mandatory = $false)]
    [string] $Language = 'English',

    # ISO 4217 currency code for Dataverse databases.
    [Parameter(Mandatory = $false)]
    [string] $Currency = 'EUR',

    # Renamed from $WhatIf to $DryRun to avoid conflict with
    # PowerShell's built-in -WhatIf common parameter.
    [Parameter(Mandatory = $false)]
    [switch] $DryRun,

    # Optional service principal credentials for unattended/CI-CD runs.
    [Parameter(Mandatory = $false)]
    [string] $ApplicationId,

    [Parameter(Mandatory = $false)]
    [string] $ClientSecret
)

# ---------------------------------------------------------------------------
# 1. Import required modules
# ---------------------------------------------------------------------------
Import-Module Microsoft.PowerApps.Administration.PowerShell -ErrorAction Stop
Import-Module Microsoft.PowerApps.PowerShell                -ErrorAction Stop
Import-Module Microsoft.Graph.Authentication                -ErrorAction Stop
Import-Module Microsoft.Graph.Groups                        -ErrorAction Stop

if ($DryRun) {
    Write-Warning "Running in DryRun mode - no changes will be committed."
}

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
# 2. Authenticate to Power Platform
# ---------------------------------------------------------------------------
Write-Host "Authenticating to Power Platform..." -ForegroundColor Cyan

if ($ApplicationId -and $ClientSecret) {
    Add-PowerAppsAccount -TenantId $TenantId -ApplicationId $ApplicationId -ClientSecret $ClientSecret | Out-Null
} else {
    Add-PowerAppsAccount -TenantId $TenantId | Out-Null
}

# ---------------------------------------------------------------------------
# 3. Authenticate to Microsoft Graph (for security group management)
# ---------------------------------------------------------------------------
Write-Host "Authenticating to Microsoft Graph..." -ForegroundColor Cyan

if ($ApplicationId -and $ClientSecret) {
    $secureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
    $spCredential  = New-Object System.Management.Automation.PSCredential($ApplicationId, $secureSecret)
    Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $spCredential -NoWelcome | Out-Null
} else {
    # Interactive: requires Group.ReadWrite.All consent.
    Connect-MgGraph -TenantId $TenantId -Scopes "Group.ReadWrite.All" -NoWelcome | Out-Null
}

# ---------------------------------------------------------------------------
# 4. Restrict environment creation to admins (tenant setting)
# ---------------------------------------------------------------------------
Write-Host "Restricting environment creation to admins..." -ForegroundColor Cyan

$tenantSettings = @{ DisableEnvironmentCreationByNonAdminUsers = $true }
Invoke-IfNotDryRun { Set-TenantSettings -RequestBody $tenantSettings }

# ---------------------------------------------------------------------------
# 5. Tenant isolation — block all cross-tenant connector connections
#
# When enabled, Power Platform connectors cannot authenticate inbound or
# outbound to any tenant other than this one. This prevents data exfiltration
# via connectors to external tenants (e.g. a personal Azure AD tenant).
#
# To allow specific partner tenants, add their GUIDs here:
$allowedTenantIds = @(
    # '<partner-tenant-guid-1>',
    # '<partner-tenant-guid-2>'
)
# ---------------------------------------------------------------------------
Write-Host "Checking tenant isolation policy..." -ForegroundColor Cyan

if (-not $DryRun) {
    try {
        $isolationPolicy = Get-PowerAppTenantIsolationPolicy -TenantId $TenantId -ErrorAction Stop

        if ($isolationPolicy.properties.isDisabled -eq $false) {
            Write-Host "  Tenant isolation is already enabled." -ForegroundColor Yellow
        } else {
            Write-Host "  Tenant isolation is disabled - enabling now..." -ForegroundColor Green

            # Build the allowed tenants list (empty = no exceptions, all external tenants blocked).
            $allowedList = @()
            foreach ($tid in $allowedTenantIds) {
                $allowedList += @{ tenantId = $tid; inbound = $true; outbound = $true }
            }

            $newPolicy = [PSCustomObject]@{
                properties = @{
                    isDisabled     = $false
                    allowedTenants = $allowedList
                }
            }

            Set-PowerAppTenantIsolationPolicy -TenantId $TenantId -TenantIsolationPolicy $newPolicy -ErrorAction Stop | Out-Null
            Write-Host "  Tenant isolation enabled. Cross-tenant connections are now blocked." -ForegroundColor Green

            if ($allowedTenantIds.Count -gt 0) {
                Write-Host "  Whitelisted tenants: $($allowedTenantIds -join ', ')" -ForegroundColor Gray
            }
        }
    } catch {
        Write-Warning "Failed to check or set tenant isolation policy: $_"
    }
} else {
    Write-Host "[DryRun] Get-PowerAppTenantIsolationPolicy -TenantId $TenantId" -ForegroundColor Gray
    Write-Host "[DryRun] Set-PowerAppTenantIsolationPolicy -TenantId $TenantId -Policy (isDisabled=false)" -ForegroundColor Gray
}

# ---------------------------------------------------------------------------
# 6. Define target environments
#
# Three-tier topology per Microsoft ALM guidance:
#   Dev  — Sandbox, unmanaged solutions, shared maker environment.
#   Test — Sandbox + Managed Environment, managed solutions, combined Test+UAT.
#   Prod — Production + Managed Environment, managed solutions only.
#
# ManagedEnvironment : whether to enable the Managed Environments governance
#                      tier (requires Power Platform Premium or per-app plan).
# SolutionChecker    : 'None' | 'Warn' | 'Block' — enforced on solution import.
#                      'Block' prevents import if checker finds high-severity issues.
# BackupRetentionDays: 7 (default) up to 28. Only meaningful on Production.
# SecurityGroupName  : the Entra ID group that will be created and assigned.
# ---------------------------------------------------------------------------
$envDefinitions = @(
    @{
        Name                = 'PP-DEV'
        DisplayName         = 'Power Platform Dev'
        Type                = 'Sandbox'
        Purpose             = 'Development (unmanaged solutions)'
        ManagedEnvironment  = $false
        SolutionChecker     = 'None'
        BackupRetentionDays = $null
        SecurityGroupName   = 'SG-PP-DEV-Makers'
    },
    @{
        Name                = 'PP-TEST'
        DisplayName         = 'Power Platform Test'
        Type                = 'Sandbox'
        Purpose             = 'Test and User Acceptance Testing (managed solutions)'
        ManagedEnvironment  = $true
        SolutionChecker     = 'Warn'
        BackupRetentionDays = $null
        SecurityGroupName   = 'SG-PP-TEST-Makers'
    },
    @{
        Name                = 'PP-PROD'
        DisplayName         = 'Power Platform Prod'
        Type                = 'Production'
        Purpose             = 'Production (managed solutions only)'
        ManagedEnvironment  = $true
        SolutionChecker     = 'Block'
        BackupRetentionDays = 28
        SecurityGroupName   = 'SG-PP-PROD-Makers'
    }
)

# ---------------------------------------------------------------------------
# 7. Ensure environments exist
# ---------------------------------------------------------------------------
Write-Host "Ensuring environments exist..." -ForegroundColor Cyan

$currentEnvs = Get-AdminPowerAppEnvironment

# Track which environments were newly created so the polling loop below
# only waits for those — not for ones that failed (e.g. capacity errors).
$newlyCreatedEnvDisplayNames = @()

foreach ($env in $envDefinitions) {
    $existing = $currentEnvs | Where-Object { $_.DisplayName -eq $env.DisplayName }
    if ($existing) {
        Write-Host "Environment '$($env.DisplayName)' already exists (EnvironmentName = $($existing.EnvironmentName))." -ForegroundColor Yellow
        continue
    }

    Write-Host "Creating environment '$($env.DisplayName)'..." -ForegroundColor Green
    if ($DryRun) {
        Write-Host "[DryRun] New-AdminPowerAppEnvironment -DisplayName '$($env.DisplayName)' -EnvironmentSku $($env.Type) -Location $Region" -ForegroundColor Gray
    } else {
        $created = New-AdminPowerAppEnvironment `
            -DisplayName    $env.DisplayName `
            -EnvironmentSku $env.Type `
            -Location       $Region `
            -Description    $env.Purpose `
            -ErrorVariable  envCreateError `
            -ErrorAction    Continue

        if ($envCreateError) {
            Write-Warning "Error creating '$($env.DisplayName)': $envCreateError"
        } elseif ($created) {
            Write-Host "  Created '$($env.DisplayName)' (EnvironmentName: $($created.EnvironmentName))" -ForegroundColor Green
            $newlyCreatedEnvDisplayNames += $env.DisplayName
        } else {
            Write-Warning "No result returned for '$($env.DisplayName)' - environment may not have been created."
        }
    }
}

# ---------------------------------------------------------------------------
# 8. (Optional) Tag/describe the Default environment as Personal Productivity
# ---------------------------------------------------------------------------
Write-Host "Tagging default environment (if found) as Personal Productivity..." -ForegroundColor Cyan
$defaultEnv = $currentEnvs | Where-Object { $_.IsDefault -eq $true }
if ($defaultEnv) {
    Write-Host "Default environment: $($defaultEnv.DisplayName) ($($defaultEnv.EnvironmentName))" -ForegroundColor Yellow
    # There is no rename cmdlet today; align naming manually via the Admin Center.
} else {
    Write-Host "No default environment detected." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 9. Create Dataverse databases for each environment (if missing)
# ---------------------------------------------------------------------------
Write-Host "Ensuring Dataverse databases exist for environments..." -ForegroundColor Cyan

$currentEnvs = Get-AdminPowerAppEnvironment

foreach ($env in $envDefinitions) {
    $target = $currentEnvs | Where-Object { $_.DisplayName -eq $env.DisplayName }
    if (-not $target) { continue }

    if ($target.LinkedEnvironmentMetadata -and $target.LinkedEnvironmentMetadata.InstanceUrl) {
        Write-Host "Environment '$($env.DisplayName)' already has Dataverse." -ForegroundColor Yellow
        continue
    }

    Write-Host "Creating Dataverse for '$($env.DisplayName)'..." -ForegroundColor Green

    # Poll until the environment is ready before provisioning Dataverse.
    if (-not $DryRun) {
        Write-Host "Waiting for environment '$($env.DisplayName)' to become ready..." -ForegroundColor Cyan
        $maxWaitSeconds = 600
        $waited         = 0
        $readyStates    = @('Succeeded', 'Ready', 'NotSpecified')

        $target = Get-AdminPowerAppEnvironment -EnvironmentName $target.EnvironmentName

        function Get-EnvReadyState([object]$envObj) {
            $s = $envObj.Properties.States.Management.Id
            if ($s) { return $s }
            $s = $envObj.Properties.provisioningState
            if ($s) { return $s }
            return 'Succeeded'
        }

        while ((Get-EnvReadyState $target) -notin $readyStates -and $waited -lt $maxWaitSeconds) {
            $currentState = Get-EnvReadyState $target
            Write-Host "  ...state: '$currentState' - waiting ($waited s elapsed)" -ForegroundColor Gray
            Start-Sleep -Seconds 15
            $waited += 15
            $target = Get-AdminPowerAppEnvironment -EnvironmentName $target.EnvironmentName
        }

        $finalState = Get-EnvReadyState $target
        if ($waited -ge $maxWaitSeconds) {
            Write-Warning "Environment '$($env.DisplayName)' did not reach a ready state within $maxWaitSeconds seconds (last state: '$finalState'). Skipping Dataverse provisioning."
            continue
        }

        Write-Host "Environment '$($env.DisplayName)' is ready (state: '$finalState'). Provisioning Dataverse..." -ForegroundColor Green
        try {
            New-AdminPowerAppCdsDatabase `
                -EnvironmentName $target.EnvironmentName `
                -LanguageName    $Language `
                -CurrencyName    $Currency | Out-Null
        } catch {
            Write-Warning "Failed to create Dataverse for '$($env.DisplayName)': $_"
        }
    } else {
        Write-Host "[DryRun] New-AdminPowerAppCdsDatabase -EnvironmentName $($target.EnvironmentName) -LanguageName $Language -CurrencyName $Currency" -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------------------
# 10. Apply Managed Environments, Solution Checker, and backup retention
#
# Managed Environments is Microsoft's recommended governance tier for
# non-development environments. It enables:
#   - Maker welcome content / onboarding control
#   - Sharing limits (restrict canvas app sharing)
#   - Weekly admin digest emails
#   - Solution Checker enforcement on import
#   - IP firewall and customer-managed keys support
#
# Requires Power Platform Premium or per-app plan on users in the environment.
# ---------------------------------------------------------------------------
Write-Host "Applying Managed Environments and governance settings..." -ForegroundColor Cyan

$currentEnvs = Get-AdminPowerAppEnvironment

foreach ($env in $envDefinitions) {
    $envObj = $currentEnvs | Where-Object { $_.DisplayName -eq $env.DisplayName }
    if (-not $envObj) {
        Write-Warning "Environment '$($env.DisplayName)' not found; skipping governance settings."
        continue
    }

    # --- Managed Environments + Solution Checker (single cmdlet call) ---
    if ($env.ManagedEnvironment) {
        Write-Host "Enabling Managed Environment on '$($env.DisplayName)' (Solution Checker: $($env.SolutionChecker))..." -ForegroundColor Green
        if (-not $DryRun) {
            try {
                # protectionLevel 'Standard' activates the Managed Environments tier.
                # solutionCheckerMode controls enforcement on solution import.
                $govConfig = [PSCustomObject]@{
                    protectionLevel     = 'Standard'
                    solutionCheckerMode = $env.SolutionChecker.ToLower()  # 'none' | 'warn' | 'block'
                }
                Set-AdminPowerAppEnvironmentGovernanceConfiguration `
                    -EnvironmentName              $envObj.EnvironmentName `
                    -UpdatedGovernanceConfiguration $govConfig `
                    -ErrorAction Stop | Out-Null
                Write-Host "  Managed Environment enabled (Solution Checker: $($env.SolutionChecker)) on '$($env.DisplayName)'." -ForegroundColor Green
            } catch {
                Write-Warning "Failed to enable Managed Environment on '$($env.DisplayName)': $_"
            }
        } else {
            Write-Host "[DryRun] Set-AdminPowerAppEnvironmentGovernanceConfiguration -EnvironmentName $($envObj.EnvironmentName) -UpdatedGovernanceConfiguration @{protectionLevel='Standard'; solutionCheckerMode='$($env.SolutionChecker.ToLower())'}" -ForegroundColor Gray
        }
    }

    # --- Backup retention (Production only) ---
    if ($env.BackupRetentionDays) {
        Write-Host "Setting backup retention to $($env.BackupRetentionDays) days on '$($env.DisplayName)'..." -ForegroundColor Green
        if (-not $DryRun) {
            try {
                Set-AdminPowerAppEnvironmentBackupRetentionPeriod `
                    -EnvironmentName              $envObj.EnvironmentName `
                    -NewBackupRetentionPeriodInDays $env.BackupRetentionDays `
                    -ErrorAction Stop | Out-Null
                Write-Host "  Backup retention set to $($env.BackupRetentionDays) days on '$($env.DisplayName)'." -ForegroundColor Green
            } catch {
                Write-Warning "Failed to set backup retention on '$($env.DisplayName)': $_"
            }
        } else {
            Write-Host "[DryRun] Set-AdminPowerAppEnvironmentBackupRetentionPeriod -EnvironmentName $($envObj.EnvironmentName) -NewBackupRetentionPeriodInDays $($env.BackupRetentionDays)" -ForegroundColor Gray
        }
    }
}

# ---------------------------------------------------------------------------
# 11. Create Azure AD security groups and assign them to their environments
#    One group per environment: SG-PP-DEV-Makers, SG-PP-TEST-Makers, etc.
#    Add people to these groups in Entra ID to grant environment access.
# ---------------------------------------------------------------------------
Write-Host "Ensuring Azure AD security groups exist and are assigned to environments..." -ForegroundColor Cyan

# Only poll for environments that were NEWLY created this run.
if ($newlyCreatedEnvDisplayNames.Count -gt 0) {
    Write-Host "Waiting for newly created environments to become visible..." -ForegroundColor Cyan
    $maxEnvWait = 900
    $envWaited  = 0
    do {
        $currentEnvs = Get-AdminPowerAppEnvironment
        $stillMissing = $newlyCreatedEnvDisplayNames | Where-Object {
            $dn = $_
            -not ($currentEnvs | Where-Object { $_.DisplayName -eq $dn })
        }
        if ($stillMissing) {
            Write-Host "  Still waiting for: $($stillMissing -join ', ') ($envWaited s elapsed)" -ForegroundColor Gray
            Start-Sleep -Seconds 15
            $envWaited += 15
        }
    } while ($stillMissing -and $envWaited -lt $maxEnvWait)

    if ($stillMissing) {
        Write-Warning "The following environments did not appear within $maxEnvWait seconds and will be skipped: $($stillMissing -join ', ')"
    }
} else {
    Write-Host "No new environments created this run - skipping visibility wait." -ForegroundColor Gray
    $currentEnvs = Get-AdminPowerAppEnvironment
}

foreach ($env in $envDefinitions) {
    $groupName = $env.SecurityGroupName
    $envObj    = $currentEnvs | Where-Object { $_.DisplayName -eq $env.DisplayName }

    if (-not $envObj) {
        Write-Warning "Environment '$($env.DisplayName)' not found; skipping security group assignment."
        continue
    }

    # --- Create the security group if it does not exist yet ---
    $existingGroup = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue |
                     Select-Object -First 1

    $groupId = $null

    if ($existingGroup) {
        Write-Host "Security group '$groupName' already exists (Id = $($existingGroup.Id))." -ForegroundColor Yellow
        $groupId = $existingGroup.Id
    } else {
        Write-Host "Creating security group '$groupName'..." -ForegroundColor Green
        if (-not $DryRun) {
            try {
                $newGroup = New-MgGroup `
                    -DisplayName       $groupName `
                    -MailNickname      $groupName `
                    -Description       "Members of this group have maker access to the $($env.DisplayName) Power Platform environment." `
                    -SecurityEnabled:$true `
                    -MailEnabled:$false `
                    -GroupTypes        @()

                $groupId = $newGroup.Id
                Write-Host "  Created group '$groupName' with Id = $groupId" -ForegroundColor Green
            } catch {
                Write-Warning "Failed to create security group '$groupName': $_"
                continue
            }
        } else {
            Write-Host "[DryRun] New-MgGroup -DisplayName '$groupName' -SecurityEnabled `$true -MailEnabled `$false" -ForegroundColor Gray
        }
    }

    # --- Assign the group to the environment as EnvironmentMaker ---
    if ($groupId -or $DryRun) {
        Write-Host "Assigning '$groupName' as EnvironmentMaker on '$($env.DisplayName)'..." -ForegroundColor Green
        if (-not $DryRun) {
            try {
                $token   = Get-JwtToken -Audience 'https://management.azure.com/'
                $headers = @{
                    'Authorization' = "Bearer $token"
                    'Content-Type'  = 'application/json'
                }
                $body = @{
                    add = @(
                        @{
                            roleDefinitionId = "/providers/Microsoft.BusinessAppPlatform/environments/$($envObj.EnvironmentName)/roleDefinitions/environmentmaker"
                            objectId         = $groupId
                            principalType    = 'Group'
                            tenantId         = $TenantId
                        }
                    )
                } | ConvertTo-Json -Depth 5

                $uri = "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/environments/$($envObj.EnvironmentName)/modifyRoleAssignments?api-version=2016-11-01"
                Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -Body $body | Out-Null
                Write-Host "  Assigned '$groupName' as EnvironmentMaker on '$($env.DisplayName)'." -ForegroundColor Green
            } catch {
                Write-Warning "Failed to assign group '$groupName' to environment '$($env.DisplayName)': $_"
            }
        } else {
            Write-Host "[DryRun] POST modifyRoleAssignments: $groupName -> EnvironmentMaker on $($envObj.EnvironmentName)" -ForegroundColor Gray
        }
    }
}

# ---------------------------------------------------------------------------
# 12. DLP policy STUBS only (tenant base + one per environment)
#     This section creates empty, unclassified policy shells so that named
#     policy objects exist before Provision-PowerPlatform-DLP.ps1 runs.
#     ALL connector group classification (Business/NonBusiness/Blocked) is
#     owned exclusively by Provision-PowerPlatform-DLP.ps1 — do not add
#     connector logic here.
# NOTE: Get-DlpPolicy / New-AdminDlpPolicy are V1 cmdlets. Microsoft has
# V2 equivalents (Get-AdminDlpPolicy, New-DlpPolicy). These V1 cmdlets still
# work but consider migrating to V2 when upgrading the module.
# ---------------------------------------------------------------------------
Write-Host "Creating DLP policy scaffolding..." -ForegroundColor Cyan

$dlpPolicyCache = Get-DlpPolicy

function Find-DlpPolicyInCache {
    param([string] $Name)
    return $dlpPolicyCache | Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ieq $Name.Trim() }
}

# Tenant-wide base policy stub
$tenantBasePolicyName = 'DLP-Tenant-Base'
if (Find-DlpPolicyInCache $tenantBasePolicyName) {
    Write-Host "DLP policy '$tenantBasePolicyName' already exists." -ForegroundColor Yellow
} else {
    Write-Host "Creating tenant-wide base DLP policy '$tenantBasePolicyName'..." -ForegroundColor Green
    if (-not $DryRun) {
        $result = New-AdminDlpPolicy -DisplayName $tenantBasePolicyName -ErrorVariable dlpError -ErrorAction Continue
        if ($dlpError)   { Write-Warning "Failed to create '$tenantBasePolicyName': $dlpError" }
        elseif ($result) { Write-Host "  Created '$tenantBasePolicyName'." -ForegroundColor Green }
        else             { Write-Warning "No result returned for '$tenantBasePolicyName' - may not have been created." }
        $dlpPolicyCache = Get-DlpPolicy
    } else {
        Write-Host "[DryRun] New-AdminDlpPolicy -DisplayName '$tenantBasePolicyName'" -ForegroundColor Gray
    }
}

# Environment-scoped policy stubs
foreach ($env in $envDefinitions) {
    $policyName = "DLP-$($env.Name)"

    if (Find-DlpPolicyInCache $policyName) {
        Write-Host "DLP policy '$policyName' already exists." -ForegroundColor Yellow
        continue
    }

    $envObj = $currentEnvs | Where-Object { $_.DisplayName -eq $env.DisplayName }
    if (-not $envObj) {
        Write-Host "Environment for policy '$policyName' not found; skipping." -ForegroundColor Yellow
        continue
    }

    Write-Host "Creating environment DLP policy stub '$policyName'..." -ForegroundColor Green

    if (-not $DryRun) {
        try {
            $result = New-AdminDlpPolicy -DisplayName $policyName -ErrorAction Stop
            if (-not $result) { throw "New-AdminDlpPolicy returned no result." }
            Write-Host "  Created stub '$policyName'." -ForegroundColor Green

            $dlpPolicyCache = Get-DlpPolicy
            $policyObj = Find-DlpPolicyInCache $policyName

            if ($policyObj) {
                $updated = $policyObj.properties
                $updated.environmentType = 'SingleEnvironment'
                $updated.environments    = @([PSCustomObject]@{ id = $envObj.EnvironmentName })
                Set-DlpPolicy -PolicyName $policyObj.name -UpdatedPolicy $updated -ErrorAction Stop | Out-Null
                Write-Host "  Scoped '$policyName' to $($envObj.EnvironmentName)." -ForegroundColor Green
            }
        } catch {
            Write-Warning "Failed to create or scope DLP policy '$policyName': $_"
        }
        $dlpPolicyCache = Get-DlpPolicy
    } else {
        Write-Host "[DryRun] New-AdminDlpPolicy -DisplayName $policyName" -ForegroundColor Gray
        Write-Host "[DryRun] Set-DlpPolicy scope -> $($envObj.EnvironmentName)" -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
Write-Host "`nScaffolding complete. Next steps:" -ForegroundColor Cyan
Write-Host "1) Run Provision-PowerPlatform-DLP.ps1 to apply connector classifications to all DLP policy stubs." -ForegroundColor Yellow
Write-Host "2) In the Power Platform admin center, rename the default environment and adjust descriptions." -ForegroundColor Gray
Write-Host "3) Configure security roles inside each environment (Dataverse roles, maker vs runtime, etc.)." -ForegroundColor Gray
Write-Host "4) Hook up your ALM pipelines (pipelines app or Azure DevOps) using the environments just created." -ForegroundColor Gray
Write-Host "5) Consider provisioning individual Dev environments per maker for larger teams (Microsoft recommendation)." -ForegroundColor Gray
Write-Host "6) Add users to the Entra ID security groups created by this script:" -ForegroundColor Gray

foreach ($env in $envDefinitions) {
    Write-Host "   - $($env.SecurityGroupName)  →  $($env.DisplayName)" -ForegroundColor Gray
}
