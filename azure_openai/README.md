# LegalServer Azure OpenAI Setup Tool

A self-contained PowerShell automation script (`Setup-LegalServerAzureOpenAI.ps1`) for discovering, verifying, deploying, upscaling, and managing recommended Azure OpenAI models for LegalServer integrations.

---

## Overview & Recommended Models

LegalServer's AI & Machine Learning features (chatbots, document vision, note summarization/translation, and audio transcription) utilize 4 core models:

1. **Standard Completions & Vision:** `gpt-5.4` (or `gpt-4o`) — Standard Tier
2. **Fast Completions & Vision:** `gpt-5.4-mini` (or `gpt-4o-mini`) — Fast Tier
3. **Embeddings:** `text-embedding-3-small` — Standard Tier
4. **Speech-to-Text (Transcription):** `whisper` — Standard Tier

Because Microsoft frequently updates the Azure Portal, OpenAI Studio, and AI Foundry user interfaces, this script automates the entire setup through Azure Resource Manager (ARM) APIs.

---

## Key Automation Features

* **Maximum Rate Limit Allocation (Max TPM / RPM):**
  The script automatically inspects regional quotas and provisions deployments with **100% of the maximum available Tokens-Per-Minute (TPM)** or Requests-Per-Minute (RPM).
* **Automatic Capacity Upscaling:**
  If a deployment already exists in your Azure account with a lower rate limit (such as 50k TPM), running the script will automatically **upscale it to the maximum available capacity** (e.g., 2 Million TPM) without modifying existing endpoints or keys.
* **Multi-Region Auto-Routing:**
  Some models are hosted in specific Azure regions (for example, Whisper transcription is hosted in `northcentralus` and `eastus2`, while GPT completions and Embeddings may reside in `eastus`). The script automatically detects regional availability and routes deployments across your subscription's accounts so that a single command succeeds for all 4 models.
* **Safe Deployment Deletion & Cleanup:**
  Includes a `-DeleteDeploymentNames` parameter to cleanly delete test deployments and free up quota, requiring explicit account targeting.
* **Non-Destructive Audit Mode:**
  Runs read-only discovery across your subscription without requiring elevated secret permissions or modifying resources.

---

## Prerequisites & Permissions

* **Deployment Access:** **Cognitive Services Contributor** (or **Contributor**) role on the target Resource Group or Cognitive Services accounts.
* **Regional Quota / Usage Access:** **Cognitive Services Usages Reader** (or **Reader**) role at the Subscription scope to inspect TPM quotas.
* **Azure OpenAI Accounts:** At least one Azure Cognitive Services account (Kind: `OpenAI` or `AIServices`) in your subscription.

---

## How to Run the Tool

### Method: Azure Cloud Shell in Browser (Recommended — Zero Local Installation)

1. Log into the [Azure Portal](https://portal.azure.com).
2. Click the **Cloud Shell** icon (`>_`) in the top navigation bar (or visit [shell.azure.com](https://shell.azure.com)).
3. In the top-left dropdown, select **PowerShell**.
4. Load `Setup-LegalServerAzureOpenAI.ps1` into Cloud Shell (using the **Upload** button on the toolbar or `code Setup-LegalServerAzureOpenAI.ps1`).

---

## Common Commands & Use Cases

### 1. Deploy All Recommended Defaults (One-Command Setup)
Deploys the 4 recommended models (`gpt-5.4`, `gpt-5.4-mini`, `text-embedding-3-small`, `whisper`) at maximum available TPM capacity and reveals the API keys for LegalServer:

```powershell
./Setup-LegalServerAzureOpenAI.ps1 `
    -ResourceGroupName "LegalServer_OpenAI" `
    -AccountName "legalserver-east-us" `
    -RevealApiKey
```

### 2. Read-Only Audit of All Accounts in Subscription
Inventories existing model deployments, versions, capacities, and regional quotas across all accounts without making any changes:

```powershell
./Setup-LegalServerAzureOpenAI.ps1 -ScanAllAccounts -AuditOnly
```

### 3. Upscale Existing Deployments to Maximum Available Quota
If deployments were previously created with lower rate limits, running the deployment command automatically upscales them to the maximum available capacity:

```powershell
./Setup-LegalServerAzureOpenAI.ps1 `
    -ResourceGroupName "LegalServer_OpenAI" `
    -AccountName "legalserver-east-us" `
    -MaximizeCapacity
```

### 4. Delete / Clean Up Test Deployments
To delete one or more deployments from an account and immediately release their quota (requires specifying the exact Resource Group and Account):

```powershell
./Setup-LegalServerAzureOpenAI.ps1 `
    -ResourceGroupName "LegalServer_OpenAI" `
    -AccountName "legalserver-east-us" `
    -DeleteDeploymentNames @("gpt-5.6-terra", "gpt-5.6-luna", "text-embedding-3-large")
```

### 5. Deploying Custom Models or Specific Model Versions
Override the default model names or versions:

```powershell
./Setup-LegalServerAzureOpenAI.ps1 `
    -ResourceGroupName "LegalServer_OpenAI" `
    -AccountName "legalserver-east-us" `
    -StandardCompletionModel "gpt-4o" `
    -FastCompletionModel "gpt-4o-mini" `
    -EmbeddingModel "text-embedding-3-small" `
    -AudioModel "whisper" `
    -RevealApiKey
```

---

## Parameter Reference

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-SubscriptionId` | String | Active context | Target Azure Subscription ID |
| `-TenantId` | String | Active context | Target Azure Entra ID Tenant ID |
| `-ResourceGroupName` | String | Auto-discovered | Name of the Resource Group |
| `-AccountName` | String | Auto-discovered | Name of the primary Azure OpenAI account |
| `-AutoRouteRegions` | Switch | `$true` | Auto-routes unsupported models (e.g. Whisper) to supporting regional accounts |
| `-MaximizeCapacity` | Switch | `$true` | Sizes deployments and upscales existing models to 100% max available TPM |
| `-DeleteDeploymentNames` | String[] | `$null` | List of deployment names to delete (requires explicit account) |
| `-AuditOnly` | Switch | `$false` | Read-only discovery mode |
| `-RevealApiKey` | Switch | `$false` | Displays unmasked API keys in the handoff report |
| `-StandardCompletionModel` | String | `gpt-5.4` | Standard completion and vision model |
| `-FastCompletionModel` | String | `gpt-5.4-mini` | Fast completion and vision model |
| `-EmbeddingModel` | String | `text-embedding-3-small` | Text embedding model |
| `-AudioModel` | String | `whisper` | Speech-to-text transcription model |
| `-ApiVersion` | String | `2024-10-21` | Azure OpenAI REST API version |

---

## LegalServer Configuration Handoff

At the conclusion of execution, the script displays clean, vertical copy-paste cards matching the exact layout of LegalServer's **Add Lookup Value** form:

```text
================================================================================
  5. LEGALSERVER CONFIGURATION HANDOFF
================================================================================
Log into LegalServer and navigate to:
  Admin -> AI & Machine Learning Settings

Step 1: Global AI & Machine Learning Settings
--------------------------------------------------------------------------------
  Enable Azure OpenAI : Yes
--------------------------------------------------------------------------------

Step 2: Model Lookup Entries (Admin -> AI & Machine Learning Settings -> Configure Models)
In LegalServer, click 'Add Lookup Value' for each model below and copy the values:

--------------------------------------------------------------------------------
  Model Entry 1 of 4: [Standard Completions & Vision]
--------------------------------------------------------------------------------
  Name                    : gpt-5.4
  Vendor                  : Azure OpenAI
  Tier                    : Standard
  Model Types             : Completions, Vision
  Vendor Model Identifier : gpt-5.4
  Azure Deployment Name   : gpt-5.4
  Azure API Base          : https://legalserver-east-us.openai.azure.com/
  Azure API Version       : 2024-10-21
  Azure API Key           : <YOUR_AZURE_API_KEY_EASTUS>
  Rate Limit / Capacity   : 6000k TPM
  Azure Resource & Status : legalserver-east-us (eastus) - Succeeded

--------------------------------------------------------------------------------
  Model Entry 2 of 4: [Fast Completions & Vision]
--------------------------------------------------------------------------------
  Name                    : gpt-5.4-mini
  Vendor                  : Azure OpenAI
  Tier                    : Fast
  Model Types             : Completions, Vision
  Vendor Model Identifier : gpt-5.4-mini
  Azure Deployment Name   : gpt-5.4-mini
  Azure API Base          : https://legalserver-east-us.openai.azure.com/
  Azure API Version       : 2024-10-21
  Azure API Key           : <YOUR_AZURE_API_KEY_EASTUS>
  Rate Limit / Capacity   : 6000k TPM
  Azure Resource & Status : legalserver-east-us (eastus) - Succeeded

--------------------------------------------------------------------------------
  Model Entry 3 of 4: [Text Embeddings]
--------------------------------------------------------------------------------
  Name                    : text-embedding-3-small
  Vendor                  : Azure OpenAI
  Tier                    : Standard
  Model Types             : Embedding
  Vendor Model Identifier : text-embedding-3-small
  Azure Deployment Name   : text-embedding-3-small
  Azure API Base          : https://legalserver-east-us.openai.azure.com/
  Azure API Version       : 2024-10-21
  Azure API Key           : <YOUR_AZURE_API_KEY_EASTUS>
  Rate Limit / Capacity   : 350k TPM
  Azure Resource & Status : legalserver-east-us (eastus) - Succeeded

--------------------------------------------------------------------------------
  Model Entry 4 of 4: [Speech-to-Text (Transcription)]
--------------------------------------------------------------------------------
  Name                    : whisper
  Vendor                  : Azure OpenAI
  Tier                    : Standard
  Model Types             : Audio
  Vendor Model Identifier : whisper
  Azure Deployment Name   : legalserver-whisper
  Azure API Base          : https://legalserver-north-central-us.cognitiveservices.azure.com/
  Azure API Version       : 2024-10-21
  Azure API Key           : <YOUR_AZURE_API_KEY_NCENTRALUS>
  Rate Limit / Capacity   : 3k RPM
  Azure Resource & Status : legalserver-north-central-us (northcentralus) - Succeeded
```

### Steps to Complete in LegalServer:
1. Log into LegalServer as an Administrator and navigate to **Admin &rarr; AI & Machine Learning Settings**.
2. Set **Enable Azure OpenAI** to **Yes**.
3. Click **Configure Models**.
4. Click **Add Lookup Value** for each of the 4 model cards and copy each field directly into the form.
