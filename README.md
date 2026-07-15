# Cortex Bulk Key Provisioner & Rotation Utility

An automated enterprise utility script designed to bulk-provision, audit, and rotate **Standard** security level API keys on the Palo Alto Networks Cortex platform. 

The script reads identity targets dynamically—either from a local users file or the platform users directory, evaluates existing active credential profiles for expiration, and steps through interactive operator validation before executing target rotations and fine-grained SBAC scoping updates.

---

## 🚀 Key Features

* **Automated Initial Configuration Wizard:** Includes an interactive execution flag (`--setup`) to securely generate local ini targets without requiring text editors or template duplication.
* **SBAC-Enforced Asset Group Filtering:** Queries the tenant database for active groups and strictly enforces pre-filtering matching `"IS_USED_BY_SBAC": true`.
* **Interactive Scope Query Engine:** Allows operators to pass a custom keyword string to filter through heavy asset group tables live instead of relying on rigid, hardcoded string mappings or manual integer ID entries.
* **Multi-Source Ingestion Framework:** Provides a startup selector menu letting you choose between traditional local ingest pipelines (`users.csv`) or reading live, active personnel data feeds straight from the central `platform/iam/v1/user` account directory.
* **Multi-Key Inventory Verification:** Scans the target tenant for *all* active keys registered under a user's specific comment envelope, ensuring multiple distinct access tokens are handled simultaneously.
* **Interactive Rotation Intercepts:** Detects any impending expiration (within **7 days**) or multi-key footprints and forces an explicit interactive prompt (`y/N`) allowing you to confirm or cancel the replacement request on the fly.

---

## 📋 Prerequisites & Local Setup

### 1. Interactive Configuration Initialization
Instead of manual string adjustments inside system files, you can initialize authentication profiles dynamically using the native configuration wizard:

```bash
uv run Create_Api_Keys.py --setup
```

This runs an execution environment loop to capture your parameters and cleanly write them to `API_config.ini`:

```ini
[URL]
BaseURL = [https://your-tenant-fqdn.paloaltonetworks.com](https://your-tenant-fqdn.paloaltonetworks.com)

[AUTHENTICATION]
ACCESS_KEY_ID = your_master_high_privilege_key_id
SECRET_KEY = your_master_high_privilege_secret_key
```

### 2. Ingestion Manifest Setup (Optional: `users.csv`)
If choosing local CSV ingestion, your ingestion file must be named `users.csv` and **must include explicit identity column headers**. Headers are case-insensitive and trailing whitespace is trimmed dynamically:

```csv
Firstname,Lastname,Department,Email
Oleg,Kostine,PSO,okostine@example.com
Jane,Doe,Engineering,jdoe@example.com
```

---

## 🛠️ Installation & Dependency Management

If leveraging the modern `uv` package manager, you can spin up the utility and dynamically inject all tracking and vault dependencies on-the-fly without dirtying your global system Python environment:

```bash
uv run --with boto3 --with azure-keyvault-secrets --with azure-identity --with google-cloud-secret-manager --with pykeepass --with hvac --with lastpass-python Create_Api_Keys.py
```

> **Note:** Only include the `--with` flags for providers you actually plan to use. For LastPass, the `lastpass-python` SDK handles authentication validation, but write operations require the [LastPass CLI (`lpass`)](https://github.com/lastpass/lastpass-cli) to be installed and available on your PATH.

---

## 🕹️ Interactive Runtime Workflow

`Create_Api_Keys.py` step-by-step configuration profiling:

### 1. Basic Profiles
* **Cortex Role Allocation:** Provide the authorization group mapping string. Pressing **Enter** assigns the safe base default `Developer`.
* **Expiration Bounds:** Define API Key expiration in days. Default is set to `90` days.
* **Rotation Check Window:** Define the pending expiration window in days. Default is set to 7 days.

### 2. API Key Asset Scope Configuration
* **Option 0:** Keeps default scoping rules intact (`no_scope`).
* **Option 1:** Grants full visibility to the key layer via a `see_all` payload declaration.
* **Option 2:** Enters granular containment. You can select method **`A`** to map comma-separated group integers manually, or option **`B`** to pass a live keyword string to search, filter, and multi-select exclusively from **SBAC-enabled** asset groups.

### 3. User Ingestion Source
* **Option 1:** Processes targets locally out of the configured `users.csv` file manifest.
* **Option 2:** Connects to the platform user API directory live, displays registered profiles matching a custom search parameter, and allows multi-targeting or automated `ALL` account lifecycle scoping.

### 4. Storage Engine Targets
The script maintains a reordered deployment index. Enter selections `0` through `8` to map secret replication schemes:

| Index | Target Provider Engine | Mandatory Operational Parameters |
| :---: | :--- | :--- |
| **0** | Local Storage Only | Compiles localized tracking sheet output safely away from version controls. |
| **1** | AWS Secrets Manager | AWS region targets and absolute directory storage path prefixes. |
| **2** | Azure Key Vault | Live Key Vault URL strings (Normalizes naming tags dynamically). |
| **3** | GCP Secret Manager | Target Google Cloud Project registration ID strings. |
| **4** | HashiCorp Vault / OpenBao | Server access endpoints, token parameters, mount points, and KV directories. |
| **5** | Infisical Secrets Platform | Universal Auth Machine Client IDs, matching Secrets Secrets, and Project slugs. |
| **6** | Doppler SecretOps Control | Bearer Service Tokens, Project names, and Configuration environment labels. |
| **7** | KeePass Database (`.kdbx`) | Path destination references and explicit, **non-empty master passwords**. |
| **8** | 1Password Secrets Automation | Local Connect Server API gateway URL streams and matching vault UUIDs. |
| **9** | LastPass Vault | Account email address and master password. Uses `lpass` CLI for vault writes. |

### 5. Persistent Storage Configuration

After selecting and configuring a storage provider, the script offers to **save your settings** to `.cortex_keys.config` for reuse on future runs:

```
Save storage configuration for future runs? (y/N): y
Also save vault password/token to config file? (y/N): n
[+] Storage configuration saved to .cortex_keys.config
```

On subsequent runs (when no `--storage-choice` CLI argument is provided), the script detects the saved configuration and offers to reuse it:

```
--- Saved Storage Configuration Found ---
  Provider     : keepass
  Target       : cortex_keys.kdbx
  Prefix       : Cortex Keys
  Password     : (not saved - will prompt)
Use saved storage configuration? (Y/n):
```

* Sensitive fields (passwords/tokens) are **opt-in** for disk persistence — you choose whether to save them or be prompted each run.
* CLI arguments (`--storage-choice`, `--vault-*`) always override saved configuration.
* The saved config is stored in the `[STORAGE]` section of `.cortex_keys.config`.

---

### 6. Script usage
Example script run:
```bash
 uv run --with pykeepass Create_Api_Keys.py
Enter Cortex Role name (Default: Developer):
Enter API key lifetime in days (Default: 90):
Enter key rotation check window in days (Default: 7):

--- API Key Asset Scope Configuration ---
0. Keep Default Scoping (No changes/no_scope)
1. Allow Full Visibility (see_all)
2. Restrict to Specific Asset Groups (scope)
Select Scoping Option (0-2, Default: 0): 2

Asset Scoping Selection Method:
  A. Enter specific Asset Group IDs manually
  B. Select from a filtered list of groups using a custom search string
Select method (A or B, Default: B): b
Enter search string to filter asset groups: repos
[*] Fetching available SBAC enabled asset groups from Cortex...

Filtered Asset Groups (Found 1 matching options):
  1. test - ok for Repository Name (ID: 2012)

Enter chosen group numbers (comma-separated, e.g., 1, 2): 1

--- User Ingestion Source Configuration ---
1. Load from local users.csv file
2. Select directly from live platform users
Select source (1-2, Default: 1): 2
Enter search string to filter platform users (or press Enter for all): oleg
[*] Fetching platform users...

Filtered Platform Users (Found 1 matching options):
  1. Oleg Kostine (okostine@example.com)

Enter chosen user numbers (comma-separated, e.g., 1, 2) or 'ALL': 1

--- Key Storage Configuration ---
0. Local Storage Only (No Cloud Vault)
1. AWS Secrets Manager
2. Azure Key Vault
3. GCP Secret Manager
4. HashiCorp Vault / OpenBao
5. Infisical Secrets Platform
6. Doppler SecretOps Control
7. KeePass Database (.kdbx)
8. 1Password Secrets Automation
9. LastPass Vault
Select Storage Provider (0-9, Default: 0): 7
KeePass Path (Default: cortex_keys.kdbx):
Enter KeePass Master Password: 1234
Group Name (Default: Cortex Keys):

Do you also want to save a local backup CSV ledger? (Y/n):
[*] Syncing live account records from Cortex User Directory...
[*] Syncing live token map from Cortex Gateway...
[+] Processing 1 personnel rows under account rotation checks...

[*] Found 11 existing key(s) for Oleg Kostine (okostine@example.com):
    - Key ID 1428: Expires in 7.0 days. -> FLAGS FOR ROTATION
    - Key ID 1424: Expires in 6.6 days. -> FLAGS FOR ROTATION
    - Key ID 1422: Expires in 6.6 days. -> FLAGS FOR ROTATION
    - Key ID 1421: Expires in 6.6 days. -> FLAGS FOR ROTATION
    - Key ID 1420: Expires in 6.6 days. -> FLAGS FOR ROTATION
    - Key ID 1419: Expires in 6.6 days. -> FLAGS FOR ROTATION
    - Key ID 1418: Expires in 6.6 days. -> FLAGS FOR ROTATION
    - Key ID 1417: Expires in 6.6 days. -> FLAGS FOR ROTATION
    - Key ID 1416: Expires in 6.6 days. -> FLAGS FOR ROTATION
    - Key ID 1415: Expires in 6.5 days. -> FLAGS FOR ROTATION
    - Key ID 1410: Expires in 6.3 days. -> FLAGS FOR ROTATION
[!] Policy recommends rotation for Oleg Kostine. Reason: User holds multiple keys (11 found) on the instance.
    Proceed with creating a replacement key for this user? (y/N): y

[!] Triggering rotation cycle for: Oleg Kostine. Reason: User holds multiple keys (11 found) on the instance.
        [*] Injecting Asset IAM scope configuration blocks for key reference 1429...
    [✓] Rotation processed successfully for User: Oleg Kostine
        Identity Contact: okostine@example.com | Department Group: PCS Demo - JIT Admin
        IAM Scope Injection: SUCCESS
        Old Key ID(s): 1428, 1424, 1422, 1421, 1420, 1419, 1418, 1417, 1416, 1415, 1410 -> New Key ID Reference: 1429 | Storage Sync Status: SUCCESS (KeePass)
        [!] REMINDER: The old key references (1428, 1424, 1422, 1421, 1420, 1419, 1418, 1417, 1416, 1415, 1410) should be tracked and deleted after their grace period.

[+] Processing run finished. Log ledger written out to: generated_developer_keys_20260625_113440.csv
```

## 🔐 Vault Object Data Schema

When committing credentials to cloud keychains or local password managers, the structured metadata is committed securely as a single stringified JSON document:

```json
{
  "CORTEX_API_KEY_ID": "1410",
  "CORTEX_API_KEY": "d7A8k2...f8B9",
  "ROLE": "Developer",
  "DEPARTMENT": "PSO",
  "EMAIL": "okostine@example.com",
  "SYNC_DATE": "2026-06-25T09:30:00Z"
}
```

> ⚠️ **Security Operations Ledger Warning:** Local backup logs generated by the script (`generated_developer_keys_YYYYMMDD_HHMMSS.csv`) contain raw cryptographic material. Ensure post-processing workflows purge workspace directories cleanly upon ingestion confirmation. **Never commit raw generated ledger manifests back into standard Git version control history.**
```