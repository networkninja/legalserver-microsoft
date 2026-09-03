<#
.SYNOPSIS
    Automates inspection, multi-region quota discovery, deployment, capacity maximization, cleanup,
    and LegalServer configuration handoff for Microsoft Azure OpenAI services.

.DESCRIPTION
    This script assists LegalServer clients, site administrators, and onboarding engineers
    in discovering, verifying, deploying, or deleting Azure OpenAI models across one
    or multiple Azure accounts and regions.

    Key Features:
    1. Maximum Rate Limit Allocation (Max TPM / RPM):
       - Automatically provisions deployments with 100% of the MAXIMUM available Tokens-Per-Minute (TPM)
         or Requests-Per-Minute (RPM) in the target region (e.g. 2M TPM for GPT models, 350k TPM
         for embeddings, 3 RPM for Whisper).
       - Automatically upscales existing deployments to the maximum available capacity if quota remains.
    2. Multi-Region Auto-Routing (-AutoRouteRegions):
       - If a target account's region does not support a specific model (e.g. Whisper in 'eastus'),
         the script automatically searches other accounts in your subscription (e.g. 'northcentralus'
         or 'eastus2') and deploys/reuses there so the single command succeeds for all 4 models.
    3. Safe Deployment Deletion & Cleanup (-DeleteDeploymentNames):
       - Allows removing test deployments from an explicitly specified account to free up quota or reset state.
    4. Exact LegalServer Handoff Table:
       - Displays complete copy-paste lookup rows mapping each model to its specific Azure endpoint and key.

.PARAMETER SubscriptionId
    Azure Subscription ID. If omitted, uses active context or presents available subscriptions.

.PARAMETER TenantId
    Azure Entra ID Tenant ID. If specified, switches context to designated tenant.

.PARAMETER ResourceGroupName
    Name of the Resource Group containing the primary Azure OpenAI account.

.PARAMETER AccountName
    Name of the primary Azure OpenAI account to target.

.PARAMETER AutoRouteRegions
    Switch parameter (Default: True). When a model is unsupported in the primary account's region,
    automatically routes that model's deployment to another account in your subscription that supports it.

.PARAMETER MaximizeCapacity
    Switch parameter (Default: True). Automatically sizes deployments and upscales existing
    models to 100% maximum available regional quota limit.

.PARAMETER DeleteDeploymentNames
    Array of deployment names to delete from the target account (requires explicit -ResourceGroupName and -AccountName).

.PARAMETER StandardCompletionModel
    Model name for Standard Completions and Vision (default: 'gpt-5.4').

.PARAMETER StandardCompletionVersion
    Model version for Standard Completions (default: auto-detected from region).

.PARAMETER FastCompletionModel
    Model name for Fast Completions and Vision (default: 'gpt-5.4-mini').

.PARAMETER FastCompletionVersion
    Model version for Fast Completions (default: auto-detected from region).

.PARAMETER EmbeddingModel
    Model name for Embeddings (default: 'text-embedding-3-small').

.PARAMETER EmbeddingVersion
    Model version for Embeddings (default: auto-detected from region).

.PARAMETER AudioModel
    Model name for Audio Speech-to-Text (default: 'whisper').

.PARAMETER AudioVersion
    Model version for Audio (default: auto-detected from region).

.PARAMETER AuditOnly
    Switch parameter. Performs a read-only audit without making changes.

.PARAMETER RevealApiKey
    Switch parameter. Displays full unmasked API keys in the handoff report.

.PARAMETER ApiVersion
    Default Azure OpenAI REST API version recommended for LegalServer (default: '2024-10-21').
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $false)]
    [string]$AccountName,

    [Parameter(Mandatory = $false)]
    [string]$Location,

    [Parameter(Mandatory = $false)]
    [switch]$ScanAllAccounts,

    [Parameter(Mandatory = $false)]
    [switch]$AutoRouteRegions = $true,

    [Parameter(Mandatory = $false)]
    [switch]$MaximizeCapacity = $true,

    [Parameter(Mandatory = $false)]
    [string[]]$DeleteDeploymentNames,

    [Parameter(Mandatory = $false)]
    [string]$StandardCompletionModel = "gpt-5.4",

    [Parameter(Mandatory = $false)]
    [string]$StandardCompletionVersion,

    [Parameter(Mandatory = $false)]
    [string]$FastCompletionModel = "gpt-5.4-mini",

    [Parameter(Mandatory = $false)]
    [string]$FastCompletionVersion,

    [Parameter(Mandatory = $false)]
    [string]$EmbeddingModel = "text-embedding-3-small",

    [Parameter(Mandatory = $false)]
    [string]$EmbeddingVersion,

    [Parameter(Mandatory = $false)]
    [string]$AudioModel = "whisper",

    [Parameter(Mandatory = $false)]
    [string]$AudioVersion,

    [Parameter(Mandatory = $false)]
    [string]$ApiVersion = "2024-10-21",

    [Parameter(Mandatory = $false)]
    [switch]$AuditOnly,

    [Parameter(Mandatory = $false)]
    [switch]$RevealApiKey
)

$ErrorActionPreference = "Stop"

function Write-SectionHeader {
    param([string]$Title)
    Write-Host "`n================================================================================" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK]   $Message" -ForegroundColor Green
}

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Gray
}

function Write-WarnMsg {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-ErrorMsg {
    param([string]$Message)
    Write-Host "[ERR]  $Message" -ForegroundColor Red
}

function Get-AccountEndpoint {
    param($AccountObj)
    if ($AccountObj.PSObject.Properties['Endpoint'] -and $AccountObj.Endpoint) {
        return $AccountObj.Endpoint
    } elseif ($AccountObj.Properties -and $AccountObj.Properties.PSObject.Properties['Endpoint']) {
        return $AccountObj.Properties.Endpoint
    }
    return "https://$($AccountObj.AccountName).openai.azure.com/"
}

function Get-AccountApiKeySafely {
    param($Rg, $Name)
    try {
        $keys = Get-AzCognitiveServicesAccountKey -ResourceGroupName $Rg -AccountName $Name -ErrorAction Stop
        if ($keys -and $keys.Key1) { return $keys.Key1 }
    } catch {
        return $null
    }
    return $null
}

# ==============================================================================
# 1. AZURE CONTEXT & AUTHENTICATION
# ==============================================================================
Write-SectionHeader "1. AZURE AUTHENTICATION & CONTEXT"

$currentContext = Get-AzContext -ErrorAction SilentlyContinue

if (-not $currentContext) {
    Write-Info "No active Azure session found. Initiating login..."
    if ($TenantId) {
        Connect-AzAccount -Tenant $TenantId | Out-Null
    } else {
        Connect-AzAccount | Out-Null
    }
    $currentContext = Get-AzContext
}

if ($TenantId -and $currentContext.Tenant -and $currentContext.Tenant.Id -ne $TenantId) {
    Write-Info "Switching context to requested Tenant: $TenantId"
    Connect-AzAccount -Tenant $TenantId | Out-Null
    $currentContext = Get-AzContext
}

if ($SubscriptionId) {
    Write-Info "Setting context to Subscription: $SubscriptionId"
    if ($TenantId) {
        Set-AzContext -Subscription $SubscriptionId -Tenant $TenantId | Out-Null
    } else {
        Set-AzContext -Subscription $SubscriptionId | Out-Null
    }
    $currentContext = Get-AzContext
} elseif (-not $currentContext.Subscription) {
    $subs = Get-AzSubscription -ErrorAction SilentlyContinue
    if (-not $subs -or $subs.Count -eq 0) {
        Write-ErrorMsg "No Azure Subscriptions accessible with current credentials."
        exit 1
    } elseif ($subs.Count -eq 1) {
        Set-AzContext -Subscription $subs[0].Id | Out-Null
        $currentContext = Get-AzContext
    } else {
        Write-Host "`nAvailable Subscriptions:" -ForegroundColor Yellow
        for ($i = 0; $i -lt $subs.Count; $i++) {
            Write-Host "  [$i] $($subs[$i].Name) ($($subs[$i].Id))"
        }
        $validSelection = $false
        $subIndex = 0
        while (-not $validSelection) {
            $inputVal = Read-Host "Select subscription number [0-$($subs.Count - 1)] (or 'q' to quit)"
            if ($inputVal -eq 'q') { Write-WarnMsg "Operation aborted by user."; exit 0 }
            if ($inputVal -match '^\d+$' -and [int]$inputVal -ge 0 -and [int]$inputVal -lt $subs.Count) {
                $subIndex = [int]$inputVal
                $validSelection = $true
            }
        }
        Set-AzContext -Subscription $subs[$subIndex].Id | Out-Null
        $currentContext = Get-AzContext
    }
}

Write-Success "Active Subscription : $($currentContext.Subscription.Name) ($($currentContext.Subscription.Id))"
Write-Success "Active Tenant       : $($currentContext.Tenant.Id)"

# ==============================================================================
# 2. DISCOVERY & ACCOUNT SELECTION
# ==============================================================================
Write-SectionHeader "2. AZURE OPENAI ACCOUNTS DISCOVERY"

$accountsRaw = Get-AzCognitiveServicesAccount -ErrorAction SilentlyContinue
$allOpenAiAccounts = @()

if ($accountsRaw) {
    foreach ($acc in $accountsRaw) {
        $accType = $null
        if ($acc.PSObject.Properties['AccountType']) { $accType = $acc.AccountType }
        elseif ($acc.PSObject.Properties['Kind']) { $accType = $acc.Kind }
        $accEndpoint = Get-AccountEndpoint -AccountObj $acc
        if (-not $accType -or $accType -in @('OpenAI', 'AIServices', 'CognitiveServices') -or ($accEndpoint -like "*openai.azure.com*")) {
            $allOpenAiAccounts += $acc
        }
    }
}

if (-not $allOpenAiAccounts -or $allOpenAiAccounts.Count -eq 0) {
    Write-ErrorMsg "No Azure OpenAI / Cognitive Services accounts found in this subscription."
    exit 1
}

Write-Host "Discovered $($allOpenAiAccounts.Count) Azure OpenAI accounts across subscription:" -ForegroundColor Yellow
for ($i = 0; $i -lt $allOpenAiAccounts.Count; $i++) {
    Write-Host "  [$i] $($allOpenAiAccounts[$i].AccountName) (RG: $($allOpenAiAccounts[$i].ResourceGroupName), Region: $($allOpenAiAccounts[$i].Location))"
}

# Determine Primary Target Account
$primaryAccount = $null

if ($AccountName -and $ResourceGroupName) {
    $primaryAccount = $allOpenAiAccounts | Where-Object { 
        $_.AccountName -eq $AccountName -and $_.ResourceGroupName -eq $ResourceGroupName 
    } | Select-Object -First 1
} elseif ($AccountName) {
    $primaryAccount = $allOpenAiAccounts | Where-Object { $_.AccountName -eq $AccountName } | Select-Object -First 1
} elseif ($allOpenAiAccounts.Count -eq 1) {
    $primaryAccount = $allOpenAiAccounts[0]
} elseif (-not $ScanAllAccounts) {
    Write-Host "`nSelect primary account:" -ForegroundColor Yellow
    for ($i = 0; $i -lt $allOpenAiAccounts.Count; $i++) {
        Write-Host "  [$i] $($allOpenAiAccounts[$i].AccountName) ($($allOpenAiAccounts[$i].Location))"
    }
    $accIndex = 0
    $validSelection = $false
    while (-not $validSelection) {
        $inputVal = Read-Host "Select account number [0-$($allOpenAiAccounts.Count - 1)]"
        if ($inputVal -match '^\d+$' -and [int]$inputVal -ge 0 -and [int]$inputVal -lt $allOpenAiAccounts.Count) {
            $accIndex = [int]$inputVal
            $validSelection = $true
        }
    }
    $primaryAccount = $allOpenAiAccounts[$accIndex]
}

if ($primaryAccount) {
    Write-Success "Primary Target Account : $($primaryAccount.AccountName) ($($primaryAccount.Location))"
}

# ==============================================================================
# 3. DEPLOYMENT DELETION / CLEANUP (If Requested)
# ==============================================================================
if ($DeleteDeploymentNames -and $DeleteDeploymentNames.Count -gt 0) {
    Write-SectionHeader "3. DEPLOYMENT CLEANUP"

    if ($AuditOnly) {
        Write-ErrorMsg "Cannot execute deployment deletion when -AuditOnly switch is enabled."
        exit 1
    }

    if (-not $AccountName -or -not $ResourceGroupName -or -not $primaryAccount) {
        Write-ErrorMsg "Deletion requires explicitly specifying both -ResourceGroupName and -AccountName to prevent unintended resource removal across accounts."
        exit 1
    }

    $targetForDelete = $primaryAccount
    
    foreach ($depToDelete in $DeleteDeploymentNames) {
        Write-Info "Removing deployment '$depToDelete' from '$($targetForDelete.AccountName)' ($($targetForDelete.Location))..."
        try {
            if ($PSCmdlet.ShouldProcess("Account '$($targetForDelete.AccountName)' ($($targetForDelete.Location))", "Delete deployment '$depToDelete'")) {
                Remove-AzCognitiveServicesAccountDeployment `
                    -ResourceGroupName $targetForDelete.ResourceGroupName `
                    -AccountName $targetForDelete.AccountName `
                    -Name $depToDelete `
                    -ErrorAction Stop | Out-Null
                Write-Success "Deployment '$depToDelete' successfully deleted."
            }
        } catch {
            Write-WarnMsg "Could not delete '$depToDelete': $($_.Exception.Message)"
        }
    }
    Write-Host "`nCleanup step complete. Exiting." -ForegroundColor Green
    return
}

# ==============================================================================
# 4. INVENTORY EXISTING DEPLOYMENTS & REGIONAL CATALOGS
# ==============================================================================
Write-SectionHeader "3. EXISTING DEPLOYMENTS & QUOTA INVENTORY"

$allDiscoveredDeployments = @()
$regionalQuotaCache  = @{}
$regionalModelsCache = @{}
$accountKeysCache    = @{}

# Pre-cache regional models & quotas for all accounts
foreach ($acc in $allOpenAiAccounts) {
    $loc = $acc.Location
    if (-not $regionalModelsCache.ContainsKey($loc)) {
        $regionalModelsCache[$loc] = Get-AzCognitiveServicesModel -Location $loc -ErrorAction SilentlyContinue
    }
    if (-not $regionalQuotaCache.ContainsKey($loc)) {
        $regionalQuotaCache[$loc] = Get-AzCognitiveServicesUsage -Location $loc -ErrorAction SilentlyContinue
    }
    $apiKey = Get-AccountApiKeySafely -Rg $acc.ResourceGroupName -Name $acc.AccountName
    if ($apiKey) {
        $accountKeysCache[$acc.AccountName] = $apiKey
    }

    # Fetch Deployments
    $depsRaw = Get-AzCognitiveServicesAccountDeployment -ResourceGroupName $acc.ResourceGroupName -AccountName $acc.AccountName -ErrorAction SilentlyContinue
    if ($depsRaw) {
        foreach ($d in $depsRaw) {
            $mName = if ($d.Properties -and $d.Properties.Model) { $d.Properties.Model.Name } else { "" }
            $mVer  = if ($d.Properties -and $d.Properties.Model) { $d.Properties.Model.Version } else { "" }
            $sName = if ($d.Sku) { $d.Sku.Name } else { "" }
            $sCap  = if ($d.Sku) { $d.Sku.Capacity } else { 0 }
            $pState= if ($d.Properties) { $d.Properties.ProvisioningState } else { "" }

            $allDiscoveredDeployments += [PSCustomObject]@{
                AccountName       = $acc.AccountName
                ResourceGroupName = $acc.ResourceGroupName
                Location          = $loc
                EndpointUri       = Get-AccountEndpoint -AccountObj $acc
                DeploymentName    = $d.Name
                ModelName         = $mName
                ModelVersion      = $mVer
                SkuName           = $sName
                CapacityKTPM      = $sCap
                ProvisioningState = $pState
            }
        }
    }
}

if ($allDiscoveredDeployments.Count -gt 0) {
    Write-Host "`nAll Existing Model Deployments Discovered Across Subscription:" -ForegroundColor Yellow
    $allDiscoveredDeployments | Select-Object AccountName, Location, DeploymentName, ModelName, ModelVersion, SkuName, CapacityKTPM, ProvisioningState | Format-Table -AutoSize
} else {
    Write-Info "No existing model deployments found across subscription accounts."
}

# ==============================================================================
# 5. REGIONAL COMPATIBILITY & SAFE QUOTA HELPERS
# ==============================================================================

function Get-RegionalModelCompatibility {
    param(
        [string]$TargetModel,
        [string]$ExplicitVersion,
        [string]$PreferredSku,
        [string]$FallbackSku,
        [string]$TargetLocation,
        $ModelsCache
    )

    $result = [PSCustomObject]@{
        IsSupported     = $false
        ResolvedVersion = $null
        SelectedSku     = $PreferredSku
        SupportedSkus   = @()
        Message         = ""
    }

    $cleanTarget = $TargetModel.Trim()

    if ($ModelsCache -and $ModelsCache.ContainsKey($TargetLocation)) {
        $catalog = $ModelsCache[$TargetLocation]
        if ($catalog) {
            # Exact match first to avoid prefix collisions like gpt-5.4 vs gpt-5.4-mini
            $matches = @($catalog | Where-Object {
                $mObj = if ($_.ModelProperty) { $_.ModelProperty } elseif ($_.Model) { $_.Model } else { $_ }
                $n = if ($mObj.Name) { $mObj.Name } else { "" }
                $n.Trim() -eq $cleanTarget
            })

            if ($matches.Count -gt 0) {
                $skusFound = @()
                foreach ($m in $matches) {
                    $mObj = if ($m.ModelProperty) { $m.ModelProperty } elseif ($m.Model) { $m.Model } else { $m }
                    $mSkus = if ($mObj.Skus) { $mObj.Skus } else { @() }
                    foreach ($s in $mSkus) {
                        $sName = if ($s.Name) { $s.Name } else { "$s" }
                        if ($sName -and $sName -notin $skusFound) { $skusFound += $sName }
                    }
                }
                $result.SupportedSkus = $skusFound

                $chosenSku = $null
                if ($PreferredSku -in $skusFound) {
                    $chosenSku = $PreferredSku
                } elseif ($FallbackSku -in $skusFound) {
                    $chosenSku = $FallbackSku
                } elseif ($skusFound.Count -gt 0) {
                    $chosenSku = $skusFound[0]
                }
                $result.SelectedSku = $chosenSku

                if ($ExplicitVersion -and $ExplicitVersion -ne "default" -and $ExplicitVersion -ne "") {
                    $verMatch = $matches | Where-Object {
                        $mObj = if ($_.ModelProperty) { $_.ModelProperty } elseif ($_.Model) { $_.Model } else { $_ }
                        $mObj.Version -eq $ExplicitVersion
                    } | Select-Object -First 1

                    if ($verMatch) {
                        $result.ResolvedVersion = $ExplicitVersion
                        $result.IsSupported = $true
                        return $result
                    } else {
                        $availVers = ($matches | ForEach-Object { $mObj = if ($_.ModelProperty) { $_.ModelProperty } else { $_ }; $mObj.Version }) -join ', '
                        $result.Message = "Model '$cleanTarget' is in '$TargetLocation' but version '$ExplicitVersion' was not found (Available versions: $availVers)."
                        return $result
                    }
                }

                $defMatch = $matches | Where-Object { 
                    $mObj = if ($_.ModelProperty) { $_.ModelProperty } elseif ($_.Model) { $_.Model } else { $_ }
                    $mObj.IsDefaultVersion -eq $true
                } | Select-Object -First 1

                if ($defMatch) {
                    $mObj = if ($defMatch.ModelProperty) { $defMatch.ModelProperty } elseif ($defMatch.Model) { $defMatch.Model } else { $defMatch }
                    $v = $mObj.Version
                    if ($v) { $result.ResolvedVersion = $v; $result.IsSupported = $true; return $result }
                }

                $sorted = $matches | Sort-Object { 
                    $mObj = if ($_.ModelProperty) { $_.ModelProperty } elseif ($_.Model) { $_.Model } else { $_ }
                    $mObj.Version 
                } -Descending
                $top = $sorted[0]
                $mObjTop = if ($top.ModelProperty) { $top.ModelProperty } elseif ($top.Model) { $top.Model } else { $top }
                $v = $mObjTop.Version
                if ($v) { 
                    $result.ResolvedVersion = $v
                    $result.IsSupported = $true
                    return $result
                }
            }
        }
    }

    if ($cleanTarget -like "*embedding*") {
        $result.ResolvedVersion = "1"
        $result.SelectedSku = "Standard"
        $result.IsSupported = $true
        return $result
    }
    if ($cleanTarget -eq "whisper") {
        if ($TargetLocation -in @('eastus2', 'northcentralus', 'swedencentral', 'westeurope', 'southindia', 'norwayeast')) {
            $result.ResolvedVersion = "001"
            $result.SelectedSku = "Standard"
            $result.IsSupported = $true
            return $result
        } else {
            $result.Message = "Whisper is not supported in region '$TargetLocation' (Supported regions: eastus2, northcentralus, swedencentral, westeurope)."
            return $result
        }
    }

    if ($cleanTarget -like "gpt-*") {
        $result.ResolvedVersion = if ($ExplicitVersion) { $ExplicitVersion } else { "2026-07-09" }
        $result.SelectedSku = $PreferredSku
        $result.IsSupported = $true
        return $result
    }

    $result.Message = "Model '$cleanTarget' could not be resolved in region '$TargetLocation'."
    return $result
}

function Get-SafeQuotaStatus {
    param(
        [string]$TargetModel,
        [string]$TargetSku,
        $UsageList
    )
    if (-not $UsageList) {
        return [PSCustomObject]@{ State = "Unknown"; RemainingKTPM = 0; LimitKTPM = 0; CurrentKTPM = 0; MatchedQuota = "None" }
    }

    $cleanModel = $TargetModel.Trim()

    # Exact model matching in quota table to avoid prefix collision (e.g. gpt-5.4 vs gpt-5.4-mini)
    $matches = @($UsageList | Where-Object { 
        $val = $_.Name.Value
        $locVal = $_.Name.LocalizedValue
        
        $modelMatches = $false
        if ($val -like "*.$cleanModel" -or $val -like "*.$cleanModel.*" -or $val -like "*$cleanModel -*" -or $locVal -like "* - $cleanModel*" -or $locVal -like "* $cleanModel *") {
            if ($cleanModel -notlike "*-mini" -and ($val -like "*$cleanModel-mini*" -or $locVal -like "*$cleanModel-mini*")) {
                $modelMatches = $false
            } elseif ($cleanModel -notlike "*-nano" -and ($val -like "*$cleanModel-nano*" -or $locVal -like "*$cleanModel-nano*")) {
                $modelMatches = $false
            } elseif ($cleanModel -notlike "*-pro" -and ($val -like "*$cleanModel-pro*" -or $locVal -like "*$cleanModel-pro*")) {
                $modelMatches = $false
            } elseif ($cleanModel -notlike "*-chat" -and ($val -like "*$cleanModel-chat*" -or $locVal -like "*$cleanModel-chat*")) {
                $modelMatches = $false
            } elseif ($cleanModel -notlike "*-codex" -and ($val -like "*$cleanModel-codex*" -or $locVal -like "*$cleanModel-codex*")) {
                $modelMatches = $false
            } else {
                $modelMatches = $true
            }
        }

        $skuMatches = ($TargetSku -eq "" -or $val -like "*$TargetSku*" -or $locVal -like "*$TargetSku*")
        $modelMatches -and $skuMatches
    })

    if ($matches.Count -eq 0) {
        $matches = @($UsageList | Where-Object { 
            ($_.Name.Value -like "*$cleanModel*" -or $_.Name.LocalizedValue -like "*$cleanModel*") -and
            ($TargetSku -eq "" -or $_.Name.Value -like "*$TargetSku*" -or $_.Name.LocalizedValue -like "*$TargetSku*")
        })
    }

    if ($matches.Count -gt 0) {
        $firstMatch = $matches[0]
        $remaining = [Math]::Max(0, [int]($firstMatch.Limit - $firstMatch.CurrentValue))
        return [PSCustomObject]@{
            State          = $(if ($remaining -gt 0) { "Known" } else { "Zero" })
            RemainingKTPM  = $remaining
            LimitKTPM      = [int]$firstMatch.Limit
            CurrentKTPM    = [int]$firstMatch.CurrentValue
            MatchedQuota   = $firstMatch.Name.LocalizedValue
        }
    }
    return [PSCustomObject]@{ State = "Unknown"; RemainingKTPM = 0; LimitKTPM = 0; CurrentKTPM = 0; MatchedQuota = "No specific quota row found" }
}

# ==============================================================================
# 6. TARGET MODEL SUITE SPECIFICATION
# ==============================================================================
$targetSuite = @(
    @{
        Key                 = "standard_completion"
        Purpose             = "Standard Completions & Vision"
        LegalServerTier     = "Standard"
        LegalServerTypes    = "Completions, Vision"
        ModelName           = $StandardCompletionModel
        ModelVersion        = $StandardCompletionVersion
        DefaultDeployName   = $StandardCompletionModel
        PreferredSku        = "GlobalStandard"
        FallbackSku         = "Standard"
        DefaultCapacityKTPM = 2000
    },
    @{
        Key                 = "fast_completion"
        Purpose             = "Fast Completions & Vision"
        LegalServerTier     = "Fast"
        LegalServerTypes    = "Completions, Vision"
        ModelName           = $FastCompletionModel
        ModelVersion        = $FastCompletionVersion
        DefaultDeployName   = $FastCompletionModel
        PreferredSku        = "GlobalStandard"
        FallbackSku         = "Standard"
        DefaultCapacityKTPM = 2000
    },
    @{
        Key                 = "embedding"
        Purpose             = "Text Embeddings"
        LegalServerTier     = "Standard"
        LegalServerTypes    = "Embedding"
        ModelName           = $EmbeddingModel
        ModelVersion        = $EmbeddingVersion
        DefaultDeployName   = $EmbeddingModel
        PreferredSku        = "Standard"
        FallbackSku         = "Standard"
        DefaultCapacityKTPM = 350
    },
    @{
        Key                 = "audio"
        Purpose             = "Speech-to-Text (Transcription)"
        LegalServerTier     = "Standard"
        LegalServerTypes    = "Audio"
        ModelName           = $AudioModel
        ModelVersion        = $AudioVersion
        DefaultDeployName   = $AudioModel
        PreferredSku        = "Standard"
        FallbackSku         = "Standard"
        DefaultCapacityKTPM = 3
    }
)

# ==============================================================================
# 7. MODEL RESOLUTION, DEPLOYMENT & CAPACITY MAXIMIZATION
# ==============================================================================
Write-SectionHeader "4. LEGALSERVER MODEL RESOLUTION & DEPLOYMENT"

$finalLegalServerConfigs = @()
$hasFailures = $false

foreach ($spec in $targetSuite) {
    Write-Host "`nResolving Model: $($spec.Purpose) (Required Model: $($spec.ModelName))..." -ForegroundColor Cyan

    # 1. First check if model is deployed on the primary target account, then scan other accounts
    $existing = $null
    if ($primaryAccount) {
        $existing = $allDiscoveredDeployments | Where-Object { 
            $_.AccountName -eq $primaryAccount.AccountName -and $_.ModelName -eq $spec.ModelName 
        } | Select-Object -First 1
    }
    if (-not $existing) {
        $existing = $allDiscoveredDeployments | Where-Object { 
            $_.ModelName -eq $spec.ModelName 
        } | Select-Object -First 1
    }

    if ($existing) {
        $locUsages = $regionalQuotaCache[$existing.Location]
        $qEval = Get-SafeQuotaStatus -TargetModel $existing.ModelName -TargetSku $existing.SkuName -UsageList $locUsages

        if ($MaximizeCapacity -and -not $AuditOnly -and $qEval.State -eq "Known" -and $qEval.RemainingKTPM -gt 0) {
            $newMaxCapacity = $existing.CapacityKTPM + $qEval.RemainingKTPM
            Write-Info "Upscaling existing deployment '$($existing.DeploymentName)' on '$($existing.AccountName)' to max available capacity: ${newMaxCapacity}k TPM (currently $($existing.CapacityKTPM)k TPM)..."

            $depProps = @{
                Model = @{
                    Format  = "OpenAI"
                    Name    = $existing.ModelName
                    Version = $existing.ModelVersion
                }
            }
            $skuProps = @{
                Name     = $existing.SkuName
                Capacity = [int]$newMaxCapacity
            }

            try {
                if ($PSCmdlet.ShouldProcess("Account '$($existing.AccountName)'", "Upscale deployment '$($existing.DeploymentName)' to ${newMaxCapacity}k TPM")) {
                    New-AzCognitiveServicesAccountDeployment `
                        -ResourceGroupName $existing.ResourceGroupName `
                        -AccountName $existing.AccountName `
                        -Name $existing.DeploymentName `
                        -Properties $depProps `
                        -Sku $skuProps `
                        -ErrorAction Stop | Out-Null
                    Write-Success "Deployment '$($existing.DeploymentName)' successfully upscaled to ${newMaxCapacity}k TPM."
                    $existing.CapacityKTPM = $newMaxCapacity
                }
            } catch {
                Write-WarnMsg "Could not upscale '$($existing.DeploymentName)': $($_.Exception.Message)"
            }
        } else {
            Write-Success "Reusing existing deployment on '$($existing.AccountName)' ($($existing.Location)): '$($existing.DeploymentName)' (Capacity: $($existing.CapacityKTPM)k TPM)"
        }
        
        $keyVal = if ($accountKeysCache.ContainsKey($existing.AccountName)) { $accountKeysCache[$existing.AccountName] } else { $null }

        $finalLegalServerConfigs += [PSCustomObject]@{
            Purpose            = $spec.Purpose
            LegalServerTier    = $spec.LegalServerTier
            LegalServerTypes   = $spec.LegalServerTypes
            VendorModelID      = $existing.ModelName
            DeploymentName     = $existing.DeploymentName
            EndpointUri        = $existing.EndpointUri
            AccountName        = $existing.AccountName
            Location           = $existing.Location
            ApiKey             = $keyVal
            ApiVersion         = $ApiVersion
            CapacityKTPM       = $existing.CapacityKTPM
            Status             = "Existing on $($existing.AccountName) ($($existing.CapacityKTPM)k TPM)"
        }
        continue
    }

    # 2. Identify candidate accounts supporting this model
    $supportingAccounts = @()
    foreach ($cand in $allOpenAiAccounts) {
        $compat = Get-RegionalModelCompatibility `
            -TargetModel $spec.ModelName `
            -ExplicitVersion $spec.ModelVersion `
            -PreferredSku $spec.PreferredSku `
            -FallbackSku $spec.FallbackSku `
            -TargetLocation $cand.Location `
            -ModelsCache $regionalModelsCache
        
        if ($compat.IsSupported) {
            $candQuota = $regionalQuotaCache[$cand.Location]
            $qEval = Get-SafeQuotaStatus -TargetModel $spec.ModelName -TargetSku $compat.SelectedSku -UsageList $candQuota
            $supportingAccounts += [PSCustomObject]@{
                Account       = $cand
                Location      = $cand.Location
                Compat        = $compat
                Quota         = $qEval
            }
        }
    }

    # 3. Handle Audit Only Mode
    if ($AuditOnly) {
        Write-WarnMsg "Model '$($spec.ModelName)' is NOT deployed on any account in your subscription."
        $recList = @()
        foreach ($sa in $supportingAccounts) {
            $qStr = if ($sa.Quota.State -eq "Known") { "$($sa.Quota.RemainingKTPM)k TPM available" } else { "Quota unverified" }
            $recList += "$($sa.Account.AccountName) ($($sa.Location) [SKU: $($sa.Compat.SelectedSku)] - $qStr)"
        }
        $recText = if ($recList.Count -gt 0) { "Supported on: " + ($recList -join "; ") } else { "Unsupported in current account regions" }

        $finalLegalServerConfigs += [PSCustomObject]@{
            Purpose            = $spec.Purpose
            LegalServerTier    = $spec.LegalServerTier
            LegalServerTypes   = $spec.LegalServerTypes
            VendorModelID      = $spec.ModelName
            DeploymentName     = "[NOT DEPLOYED]"
            EndpointUri        = "[SELECT CANDIDATE ACCOUNT]"
            AccountName        = "[NONE]"
            Location           = $recText
            ApiKey             = $null
            ApiVersion         = $ApiVersion
            CapacityKTPM       = 0
            Status             = "Missing (Audit Only)"
        }
        continue
    }

    # 4. Determine Target Account for Deployment (Primary vs Auto-Routed)
    $selectedDeployAccount = $null
    $chosenCompat = $null
    $allocatedCapacity = $spec.DefaultCapacityKTPM

    $primaryCompat = if ($primaryAccount) {
        Get-RegionalModelCompatibility `
            -TargetModel $spec.ModelName `
            -ExplicitVersion $spec.ModelVersion `
            -PreferredSku $spec.PreferredSku `
            -FallbackSku $spec.FallbackSku `
            -TargetLocation $primaryAccount.Location `
            -ModelsCache $regionalModelsCache
    } else { $null }

    if ($primaryAccount -and $primaryCompat -and $primaryCompat.IsSupported) {
        $selectedDeployAccount = $primaryAccount
        $chosenCompat = $primaryCompat
        $locUsages = $regionalQuotaCache[$primaryAccount.Location]
        $qEval = Get-SafeQuotaStatus -TargetModel $spec.ModelName -TargetSku $chosenCompat.SelectedSku -UsageList $locUsages
        
        # Maximize capacity to 100% of remaining quota
        if ($qEval.State -eq "Known" -and $qEval.RemainingKTPM -gt 0) {
            $allocatedCapacity = $qEval.RemainingKTPM
        } elseif ($qEval.State -eq "Zero") {
            Write-ErrorMsg "Account '$($primaryAccount.AccountName)' in '$($primaryAccount.Location)' has 0 TPM remaining quota for '$($spec.ModelName)'."
            $hasFailures = $true
            continue
        }
    } elseif ($AutoRouteRegions -and $supportingAccounts.Count -gt 0) {
        # Auto-route to supporting account with highest remaining quota
        $best = $supportingAccounts | Sort-Object { $_.Quota.RemainingKTPM } -Descending | Select-Object -First 1
        $selectedDeployAccount = $best.Account
        $chosenCompat = $best.Compat
        if ($best.Quota.State -eq "Known" -and $best.Quota.RemainingKTPM -gt 0) {
            $allocatedCapacity = $best.Quota.RemainingKTPM
        }
        Write-Info "Auto-routed '$($spec.ModelName)' to account '$($selectedDeployAccount.AccountName)' in '$($selectedDeployAccount.Location)' (SKU: $($chosenCompat.SelectedSku))."
    } else {
        Write-ErrorMsg "Model '$($spec.ModelName)' is not supported in '$($primaryAccount.Location)' and no auto-route candidate was available."
        $hasFailures = $true
        $finalLegalServerConfigs += [PSCustomObject]@{
            Purpose            = $spec.Purpose
            LegalServerTier    = $spec.LegalServerTier
            LegalServerTypes   = $spec.LegalServerTypes
            VendorModelID      = $spec.ModelName
            DeploymentName     = "[FAILED: REGION UNSUPPORTED]"
            EndpointUri        = if ($primaryAccount) { Get-AccountEndpoint -AccountObj $primaryAccount } else { "[NONE]" }
            AccountName        = if ($primaryAccount) { $primaryAccount.AccountName } else { "[NONE]" }
            Location           = if ($primaryAccount) { $primaryAccount.Location } else { "[NONE]" }
            ApiKey             = $null
            ApiVersion         = $ApiVersion
            CapacityKTPM       = 0
            Status             = "Blocked: Not supported in $($primaryAccount.Location)"
        }
        continue
    }

    # Execute Deployment
    $deployName       = $spec.DefaultDeployName
    $targetRg         = $selectedDeployAccount.ResourceGroupName
    $targetAcc        = $selectedDeployAccount.AccountName
    $targetLoc        = $selectedDeployAccount.Location
    $targetEp         = Get-AccountEndpoint -AccountObj $selectedDeployAccount
    $resolvedVersion  = $chosenCompat.ResolvedVersion
    $chosenSku        = $chosenCompat.SelectedSku

    Write-Info "Deploying '$deployName' to account '$targetAcc' in '$targetLoc' (Model: $($spec.ModelName), Version: $resolvedVersion, SKU: $chosenSku, Capacity: ${allocatedCapacity}k TPM)..."

    $depProps = @{
        Model = @{
            Format  = "OpenAI"
            Name    = $spec.ModelName
            Version = $resolvedVersion
        }
    }
    $skuProps = @{
        Name     = $chosenSku
        Capacity = [int]$allocatedCapacity
    }

    try {
        if ($PSCmdlet.ShouldProcess("Account '$targetAcc' ($targetLoc)", "Deploy model '$($spec.ModelName)' (Version: $resolvedVersion, SKU: $chosenSku, Capacity: ${allocatedCapacity}k TPM) as '$deployName'")) {
            $newDep = New-AzCognitiveServicesAccountDeployment `
                -ResourceGroupName $targetRg `
                -AccountName $targetAcc `
                -Name $deployName `
                -Properties $depProps `
                -Sku $skuProps `
                -ErrorAction Stop

            $state = if ($newDep.Properties) { $newDep.Properties.ProvisioningState } else { "Succeeded" }
            Write-Success "Deployment '$deployName' created on '$targetAcc' at max capacity: ${allocatedCapacity}k TPM (State: $state)."

            $apiKeyVal = Get-AccountApiKeySafely -Rg $targetRg -Name $targetAcc

            $finalLegalServerConfigs += [PSCustomObject]@{
                Purpose            = $spec.Purpose
                LegalServerTier    = $spec.LegalServerTier
                LegalServerTypes   = $spec.LegalServerTypes
                VendorModelID      = $spec.ModelName
                DeploymentName     = $deployName
                EndpointUri        = $targetEp
                AccountName        = $targetAcc
                Location           = $targetLoc
                ApiKey             = $apiKeyVal
                ApiVersion         = $ApiVersion
                CapacityKTPM       = $allocatedCapacity
                Status             = "Newly Deployed on $targetAcc (${allocatedCapacity}k TPM)"
            }
        }
    } catch {
        Write-ErrorMsg "Failed to deploy '$deployName' on '$targetAcc': $($_.Exception.Message)"
        $hasFailures = $true
        $finalLegalServerConfigs += [PSCustomObject]@{
            Purpose            = $spec.Purpose
            LegalServerTier    = $spec.LegalServerTier
            LegalServerTypes   = $spec.LegalServerTypes
            VendorModelID      = $spec.ModelName
            DeploymentName     = "[DEPLOYMENT ERROR]"
            EndpointUri        = $targetEp
            AccountName        = $targetAcc
            Location           = $targetLoc
            ApiKey             = $null
            ApiVersion         = $ApiVersion
            CapacityKTPM       = 0
            Status             = "Error: $($_.Exception.Message)"
        }
    }
}

# ==============================================================================
# 8. LEGALSERVER CONFIGURATION HANDOFF REPORT
# ==============================================================================
Write-SectionHeader "5. LEGALSERVER CONFIGURATION HANDOFF"

Write-Host "Log into LegalServer and navigate to:" -ForegroundColor Yellow
Write-Host "  Admin -> AI & Machine Learning Settings`n" -ForegroundColor White

Write-Host "Step 1: Global AI & Machine Learning Settings" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------------------------------"
Write-Host "  Enable Azure OpenAI : Yes" -ForegroundColor White
Write-Host "--------------------------------------------------------------------------------`n"

Write-Host "Step 2: Model Lookup Entries (Admin -> AI & Machine Learning Settings -> Configure Models)" -ForegroundColor Cyan
Write-Host "In LegalServer, click 'Add Lookup Value' for each model below and copy the values:`n" -ForegroundColor White

$modelIndex = 1
foreach ($row in $finalLegalServerConfigs) {
    $displayedKey = "[RESTRICTED / RUN WITH -RevealApiKey TO DISPLAY]"
    if ($row.ApiKey) {
        if ($RevealApiKey) {
            $displayedKey = $row.ApiKey
        } else {
            $k = $row.ApiKey
            $displayedKey = $k.Substring(0, [Math]::Min(4, $k.Length)) + "..." + $k.Substring([Math]::Max(0, $k.Length - 4)) + " (use -RevealApiKey to unmask)"
        }
    }

    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host "  Model Entry $modelIndex of $($finalLegalServerConfigs.Count): [$($row.Purpose)]" -ForegroundColor Yellow
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host "  Name                    : $($row.VendorModelID)" -ForegroundColor White
    Write-Host "  Vendor                  : Azure OpenAI" -ForegroundColor White
    Write-Host "  Tier                    : $($row.LegalServerTier)" -ForegroundColor White
    Write-Host "  Model Types             : $($row.LegalServerTypes)" -ForegroundColor White
    Write-Host "  Vendor Model Identifier : $($row.VendorModelID)" -ForegroundColor White
    Write-Host "  Azure Deployment Name   : $($row.DeploymentName)" -ForegroundColor White
    Write-Host "  Azure API Base          : $($row.EndpointUri)" -ForegroundColor Green
    Write-Host "  Azure API Version       : $($row.ApiVersion)" -ForegroundColor White
    Write-Host "  Azure API Key           : $displayedKey" -ForegroundColor $(if ($RevealApiKey -and $row.ApiKey) { "Green" } else { "Gray" })
    Write-Host "  Rate Limit / Capacity   : $($row.CapacityKTPM)k TPM" -ForegroundColor Gray
    Write-Host "  Azure Resource & Status : $($row.Status)" -ForegroundColor Gray
    Write-Host ""
    $modelIndex++
}

if ($hasFailures) {
    Write-Host "[!] Operation completed with warnings or missing models. Review details above." -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "[OK] Configuration inventory complete and ready for LegalServer." -ForegroundColor Green
    exit 0
}
