import configparser
import csv
import json
import os
import shutil
import subprocess
import sys
import time
import requests
import argparse
import re
from datetime import datetime, timezone, timedelta

# Conditional Cloud & Vault SDK Imports
try:
    import boto3
    from botocore.exceptions import ClientError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

try:
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

try:
    from google.cloud import secretmanager
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

try:
    from pykeepass import PyKeePass, create_database
    KEEPASS_AVAILABLE = True
except ImportError:
    KEEPASS_AVAILABLE = False

try:
    import hvac
    HASHICORP_AVAILABLE = True
except ImportError:
    HASHICORP_AVAILABLE = False

try:
    from infisical_sdk import InfisicalSDKClient
    INFISICAL_AVAILABLE = True
except ImportError:
    INFISICAL_AVAILABLE = False

try:
    import lastpass
    LASTPASS_AVAILABLE = True
except ImportError:
    LASTPASS_AVAILABLE = False

# ==============================================================================
# REPOSITORY CONFIGURATION
# ==============================================================================
API_CONFIG_PATH = 'API_config-x5.ini'
SSL_VERIFY = False
# SSL_VERIFY = True


def read_api_config():
    """
    Reads and parses tenant URL and authentication credentials from the local INI configuration file.

    Returns:
        tuple: A triplet containing the BaseURL, ACCESS_KEY_ID, and SECRET_KEY.
    """
    # Prefer .cortex_keys.config only if it contains the [URL] section with credentials
    config_path = API_CONFIG_PATH
    if os.path.exists('.cortex_keys.config'):
        test_config = configparser.ConfigParser()
        test_config.read('.cortex_keys.config')
        if test_config.has_section('URL'):
            config_path = '.cortex_keys.config'

    config = configparser.ConfigParser()
    config.read(config_path)
    try:
        baseurl = config.get('URL', 'BaseURL')
        api_key_id = config.get('AUTHENTICATION', 'ACCESS_KEY_ID')
        api_key = config.get('AUTHENTICATION', 'SECRET_KEY')
        return baseurl, api_key_id, api_key
    except (configparser.NoSectionError, configparser.NoOptionError) as err:
        print(f"[-] Configuration Error: Could not parse {config_path}. Details: {err}")
        sys.exit(1)


def load_storage_config(config_path='.cortex_keys.config'):
    """
    Reads the [STORAGE] section from the local INI configuration file and returns
    the saved storage provider settings as a dictionary.

    Args:
        config_path (str): Path to the INI configuration file.

    Returns:
        dict or None: A dictionary of storage configuration values, or None if the
        file does not exist, the [STORAGE] section is missing, or a parse error occurs.
    """
    if not os.path.exists(config_path):
        return None

    config = configparser.ConfigParser()
    try:
        config.read(config_path)
        if not config.has_section('STORAGE'):
            return None
        return {
            'provider': config.get('STORAGE', 'provider', fallback=''),
            'target': config.get('STORAGE', 'vault_target', fallback=''),
            'prefix': config.get('STORAGE', 'vault_prefix', fallback=''),
            'password': config.get('STORAGE', 'vault_password', fallback=''),
            'mount': config.get('STORAGE', 'vault_mount', fallback=''),
            'env': config.get('STORAGE', 'vault_env', fallback=''),
            'client_id': config.get('STORAGE', 'vault_client_id', fallback=''),
        }
    except (configparser.Error) as err:
        print(f"[!] Warning: Could not parse storage config from {config_path}. Details: {err}")
        return None


def save_storage_config(target_config, config_path='.cortex_keys.config', include_password=False):
    """
    Writes the [STORAGE] section to the config file, preserving existing sections.

    Reads the existing INI file to retain [URL] and [AUTHENTICATION] sections, then
    overwrites the [STORAGE] section with the provided target_config values.

    Args:
        target_config (dict): The provider config dict to persist. Expected keys:
            provider, target, prefix, password, mount, env, client_id.
        config_path (str): Path to the INI configuration file.
        include_password (bool): Whether to include the sensitive vault_password field.
    """
    config = configparser.ConfigParser()
    config.read(config_path)

    config.remove_section('STORAGE')
    config.add_section('STORAGE')

    config.set('STORAGE', 'provider', target_config['provider'])
    config.set('STORAGE', 'vault_target', target_config['target'])
    config.set('STORAGE', 'vault_prefix', target_config['prefix'])
    config.set('STORAGE', 'vault_mount', target_config.get('mount', ''))
    config.set('STORAGE', 'vault_env', target_config.get('env', ''))
    config.set('STORAGE', 'vault_client_id', target_config.get('client_id', ''))

    if include_password:
        config.set('STORAGE', 'vault_password', target_config['password'])
    else:
        config.set('STORAGE', 'vault_password', '')

    try:
        with open(config_path, 'w') as config_file:
            config.write(config_file)
    except (IOError, OSError) as error:
        print(f"[!] Warning: Could not save storage configuration: {error}")


class CortexBulkKeyProvisioner:
    """
    A client wrapper handling operations against Palo Alto Networks Cortex Public and IAM APIs.
    """

    def __init__(self, baseurl, api_key_id, api_key):
        """
        Initializes the Cortex client with gateway credentials and uniform URLs.
        """
        self.baseurl = baseurl.strip("/")
        self.api_key_id = api_key_id
        self.api_key = api_key

    def _get_headers(self):
        """
        Compiles the mandatory authentication and content headers for Cortex API authorization.

        Returns:
            dict: Standardized request header map.
        """
        return {
            'x-xdr-auth-id': self.api_key_id,
            'Authorization': self.api_key,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    def get_active_cortex_emails(self):
        """
        Queries the Cortex RBAC User Directory API to map verified platform accounts.

        Returns:
            set: Normalized, lower-case email addresses belonging to active platform users.
        """
        url = f"{self.baseurl}/public_api/v1/rbac/get_users"
        payload = {"request_data": {}}
        try:
            response = requests.post(url, headers=self._get_headers(), json=payload, verify=SSL_VERIFY, timeout=90)
            response.raise_for_status()
            res_json = response.json()

            reply = res_json.get("reply", [])
            user_list = reply if isinstance(reply, list) else reply.get("data", reply.get("DATA", []))

            active_emails = set()
            for user in user_list:
                email = user.get("user_email")
                if email:
                    active_emails.add(email.strip().lower())
            return active_emails
        except Exception as err:
            print(f"[!] Critical Error: Failed to fetch active user directory from Cortex RBAC endpoint: {err}")
            sys.exit(1)

    def get_existing_keys_lifecycle(self):
        """
        Queries the platform to build an expiration timeline map indexed by key comments.

        Returns:
            dict: A map of target comment strings to arrays of key dictionaries containing 'expiration' and 'id'.
        """
        url = f"{self.baseurl}/public_api/v1/api_keys/get_api_keys"
        payload = {"request_data": {"filters": []}}
        lifecycle_map = {}
        try:
            response = requests.post(url, headers=self._get_headers(), json=payload, verify=SSL_VERIFY, timeout=90)
            response.raise_for_status()
            res_json = response.json()
            reply = res_json.get("reply", {})
            keys_list = reply.get("DATA", []) or reply.get("data", [])

            for k in keys_list:
                comment = k.get("comment")
                expiration = k.get("expiration")
                key_id = k.get("id")
                if comment:
                    comment_str = str(comment).strip()
                    if comment_str not in lifecycle_map:
                        lifecycle_map[comment_str] = []
                    lifecycle_map[comment_str].append({
                        "expiration": expiration,
                        "id": key_id
                    })
            return lifecycle_map
        except Exception as err:
            print(f"[!] Warning: Failed to retrieve API key lifecycle data: {err}")
            return {}

    def get_asset_groups(self):
        """
        Queries the Cortex API to fetch all active Dynamic asset groups for interactive scope mapping.

        Returns:
            list: Collection of asset group dictionaries containing IDs and names.
        """
        url = f"{self.baseurl}/public_api/v1/asset-groups"
        all_groups = []
        page_size = 1000
        search_from = 0

        while True:
            payload = {
                "request_data": {
                    "filters": {
                        "AND": [{
                            "SEARCH_FIELD": "XDM.ASSET_GROUP.TYPE",
                            "SEARCH_TYPE": "EQ",
                            "SEARCH_VALUE": "Dynamic"
                        }]
                    },
                    "sort": [{
                        "FIELD": "XDM.ASSET_GROUP.NAME",
                        "ORDER": "ASC"
                    }],
                    "search_from": search_from,
                    "search_to": search_from + page_size
                }
            }
            try:
                response = requests.post(url, headers=self._get_headers(), json=payload, verify=SSL_VERIFY, timeout=90)
                response.raise_for_status()
                res_json = response.json()
                reply = res_json.get("reply", {})
                page = reply.get("data", [])

                if not page:
                    break

                all_groups.extend(page)
                search_from += page_size

                metadata = reply.get("metadata", {})
                filter_count = metadata.get("filter_count", 0)
                if search_from >= filter_count:
                    break
            except Exception as err:
                print(f"[!] Warning: Failed to fetch asset groups at offset {search_from}: {err}")
                break

        return all_groups

    def get_platform_users(self):
        """
        Queries the Cortex platform user endpoint to retrieve all registered identity profiles.

        Returns:
            list: Collection of user profile dictionaries.
        """
        url = f"{self.baseurl}/platform/iam/v1/user"
        try:
            response = requests.get(url, headers=self._get_headers(), verify=SSL_VERIFY, timeout=90)
            response.raise_for_status()
            return response.json().get("data", [])
        except Exception as err:
            print(f"[!] Warning: Failed to fetch platform users: {err}")
            return []

    def generate_api_key(self, first_name, last_name, email, role, expiration_ms=None):
        """
        Dispatches a generation request to create a new Standard security level API key.

        Returns:
            tuple: A pair containing the generated key ID (str/int) and the raw secret value (str).
        """
        url = f"{self.baseurl}/public_api/v1/api_keys/generate"
        payload = {
            "request_data": {
                "roles": [role],
                "security_level": "standard",
                "comment": f"Assigned to user: {first_name} {last_name} ({email})"
            }
        }
        # print(f"payload: {payload}")
        if expiration_ms:
            payload["request_data"]["expiration"] = expiration_ms

        try:
            response = requests.post(url, headers=self._get_headers(), json=payload, verify=SSL_VERIFY, timeout=90)
            response.raise_for_status()
            res_json = response.json()
            reply = res_json.get("reply", {})
            return reply.get("id"), reply.get("key")
        except Exception as err:
            print(f"[-] API failure for user '{first_name} {last_name}': {err}")
            return None, None

    def update_key_scope(self, key_id, scope_assets_payload):
        """
        Injects the complete multi-scope JSON schema footprint required by the PUT API method.
        This preserves structural integrity for non-asset entities across updates.

        Returns:
            tuple: A boolean status flag paired with an explanatory status message string.
        """
        url = f"{self.baseurl}/platform/iam/v1/scope/api-key/{key_id}"
        payload = {
            "request_data": {
                "assets": scope_assets_payload,
                "datasets_rows": {
                    "default_filter_mode": "no_scope",
                    "filters": []
                },
                "endpoints": {
                    "endpoint_groups": {
                        "mode": "no_scope",
                        "tags": []
                    },
                    "endpoint_tags": {
                        "mode": "no_scope",
                        "tags": []
                    }
                },
                "cases_issues": {
                    "include_cases_issues_empty_entities": False,
                    "mode": "no_scope",
                    "tags": []
                }
            }
        }
        try:
            response = requests.put(url, headers=self._get_headers(), json=payload, verify=SSL_VERIFY, timeout=90)
            response.raise_for_status()
            return True, "SUCCESS"
        except Exception as err:
            return False, f"FAILED: {str(err)}"

# ==============================================================================
# SECRETS STORAGE ENGINES
# ==============================================================================
def store_in_aws(secret_name, payload, region):
    """
    Registers or updates an encrypted key payload inside AWS Secrets Manager.

    Returns:
        str: Sync confirmation text or cloud client exception error.
    """
    client = boto3.client('secretsmanager', region_name=region)
    try:
        client.create_secret(Name=secret_name, SecretString=json.dumps(payload))
        return "SUCCESS (Created)"
    except client.exceptions.ResourceExistsException:
        try:
            client.put_secret_value(SecretId=secret_name, SecretString=json.dumps(payload))
            return "SUCCESS (Updated)"
        except ClientError as e:
            return f"AWS Error: {e.response['Error']['Message']}"


def store_in_azure(vault_url, secret_name, payload):
    """
    Saves an entry securely to Azure Key Vault, normalizing underscores and forward slashes.

    Returns:
        str: Sync confirmation message or client error details.
    """
    sanitized_name = secret_name.replace("/", "-").replace("_", "-").strip("-")
    try:
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=vault_url, credential=credential)
        client.set_secret(sanitized_name, json.dumps(payload))
        return "SUCCESS (Synced)"
    except Exception as e:
        return f"Azure Error: {str(e)}"


def store_in_gcp(project_id, secret_id, payload):
    """
    Stores an encrypted version segment inside Google Cloud Platform Secret Manager.

    Returns:
        str: Sync status string or backend cloud client exception.
    """
    sanitized_id = secret_id.replace("/", "-").strip("-")
    client = secretmanager.SecretManagerServiceClient()
    parent = f"projects/{project_id}"
    secret_path = f"{parent}/secrets/{sanitized_id}"
    try:
        try:
            client.get_secret(request={"name": secret_path})
        except Exception:
            client.create_secret(request={"parent": parent, "secret_id": sanitized_id, "secret": {"replication": {"automatic": {}}}})
        client.add_secret_version(request={"parent": secret_path, "payload": {"data": json.dumps(payload).encode("utf-8")}})
        return "SUCCESS (Synced)"
    except Exception as e:
        return f"GCP Error: {str(e)}"


def store_in_keepass(kdbx_path, kdbx_password, group_name, title, username, api_key, key_id, role, dept):
    """
    Maintains local KeePass KDBX database records using purely positional parameters.

    Returns:
        str: Sync confirmation status text or operational exception.
    """
    try:
        if os.path.exists(kdbx_path):
            kp = PyKeePass(kdbx_path, password=kdbx_password)
        else:
            kp = create_database(kdbx_path, password=kdbx_password)

        group = kp.find_groups(name=group_name, first=True)
        if not group:
            group = kp.add_group(kp.root_group, group_name)

        entry = kp.find_entries(title=title, group=group, first=True)
        notes_content = f"Role: {role}\nDepartment: {dept}\nSync Date: {datetime.now(timezone.utc).isoformat()}"

        if entry:
            entry.password = api_key
            entry.username = username
            entry.notes = notes_content
            entry.set_custom_property("CORTEX_API_KEY_ID", str(key_id), protect=False)
        else:
            new_entry = kp.add_entry(group, title, username, api_key)
            new_entry.notes = notes_content
            new_entry.set_custom_property("CORTEX_API_KEY_ID", str(key_id), protect=False)

        kp.save()
        return "SUCCESS (KeePass)"
    except Exception as e:
        return f"KeePass Error: {str(e)}"


def store_in_hashicorp(vault_url, token, mount_point, secret_path, payload):
    """
    Pushes secret maps to a HashiCorp Vault / OpenBao Key-Value v2 Engine endpoint path.

    Returns:
        str: Sync confirmation message or library exception trace.
    """
    try:
        client = hvac.Client(url=vault_url, token=token)
        client.secrets.kv.v2.create_or_update_secret(
            path=secret_path, secret=payload, mount_point=mount_point
        )
        return "SUCCESS (HashiCorp Vault)"
    except Exception as e:
        return f"HashiCorp Error: {str(e)}"


def store_in_infisical(host, client_id, client_secret, project_id, env_slug, secret_name, secret_value):
    """
    Authenticates via Universal Auth and commits keys to the Infisical Secrets Platform.

    Returns:
        str: Connection validation status or authentication exception string.
    """
    try:
        client = InfisicalSDKClient(host=host)
        client.auth.universal_auth.login(client_id=client_id, client_secret=client_secret)
        client.secrets.create_secret_by_name(
            secret_name=secret_name.upper(), project_id=project_id,
            environment_slug=env_slug, secret_value=secret_value, secret_path="/"
        )
        return "SUCCESS (Infisical)"
    except Exception as e:
        return f"Infisical Error: {str(e)}"


def store_in_doppler(api_token, project, config, secret_name, secret_value):
    """
    Dispatches a synchronous REST request to modify key maps in Doppler SecretOps.

    Returns:
        str: Synchronized feedback confirmation or network fault string.
    """
    try:
        url = "https://api.doppler.com/v3/configs/config/secrets"
        headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json", "Accept": "application/json"}
        payload = {"project": project, "config": config, "secrets": {secret_name.upper(): secret_value}}
        res = requests.post(url, headers=headers, json=payload, timeout=15)
        res.raise_for_status()
        return "SUCCESS (Doppler)"
    except Exception as e:
        return f"Doppler Error: {str(e)}"


def store_in_onepassword(connect_url, token, vault_id, item_title, base_name, payload):
    """
    Uses the 1Password Connect API framework to construct programmatic secure vault items.

    Returns:
        str: Connection execution state confirmation or backend error details.
    """
    try:
        url = f"{connect_url.strip('/')}/v1/vaults/{vault_id}/items"
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        body = {
            "title": item_title, "vault": {"id": vault_id}, "category": "API_CREDENTIAL",
            "fields": [
                {"id": "username", "type": "STRING", "purpose": "USERNAME", "label": "username", "value": base_name},
                {"id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password", "value": payload["CORTEX_API_KEY"]},
                {"id": "key_id", "type": "STRING", "label": "CORTEX_API_KEY_ID", "value": str(payload["CORTEX_API_KEY_ID"])},
                {"id": "role", "type": "STRING", "label": "ROLE", "value": payload["ROLE"]},
                {"id": "department", "type": "STRING", "label": "DEPARTMENT", "value": payload["DEPARTMENT"]}
            ]
        }
        res = requests.post(url, headers=headers, json=body, timeout=15)
        res.raise_for_status()
        return "SUCCESS (1Password Connect)"
    except Exception as e:
        return f"1Password Error: {str(e)}"


def store_in_lastpass(email, master_password, entry_name, payload):
    """
    Stores API key credentials as a LastPass vault entry using the lpass CLI.

    The API key secret is stored in the Account's 'password' field.
    Structured metadata is stored as formatted key-value text in the 'notes' field.

    Args:
        email: LastPass account email for authentication.
        master_password: LastPass master password.
        entry_name: Display name for the vault entry (e.g., "Cortex - John Smith").
        payload: Dict with keys: CORTEX_API_KEY_ID, CORTEX_API_KEY, ROLE, DEPARTMENT, EMAIL, SYNC_DATE.

    Returns:
        str: Sync confirmation text or vault error details.
    """
    try:
        # Attempt SDK authentication to validate credentials
        try:
            lastpass.Vault.open_remote(email, master_password)
        except Exception as auth_err:
            # SDK is read-only; if auth itself fails, report the error
            err_msg = str(auth_err).lower()
            if 'password' in err_msg or 'authentication' in err_msg or 'unauthorized' in err_msg:
                return f"LastPass Error: Authentication failed - {auth_err}"

        # Verify LastPass CLI is available for write operations
        if not shutil.which('lpass'):
            return "LastPass Error: lpass CLI not found. Install the LastPass CLI to use this storage backend."

        # Authenticate via CLI
        login_proc = subprocess.run(
            ['lpass', 'login', '--trust', email],
            input=master_password + '\n',
            capture_output=True,
            text=True,
            timeout=30
        )
        if login_proc.returncode != 0:
            return f"LastPass Error: Authentication failed - {login_proc.stderr.strip()}"

        # Construct structured notes from payload metadata (NOT the API key itself)
        notes = (
            f"CORTEX_API_KEY_ID: {payload['CORTEX_API_KEY_ID']}\n"
            f"ROLE: {payload['ROLE']}\n"
            f"DEPARTMENT: {payload['DEPARTMENT']}\n"
            f"EMAIL: {payload['EMAIL']}\n"
            f"SYNC_DATE: {payload['SYNC_DATE']}"
        )

        # Derive username from email (base portion before @)
        username = email.split('@')[0]

        # Build the entry content for lpass add (encoded fields format)
        entry_content = (
            f"Name: {entry_name}\n"
            f"URL: https://cortex.paloaltonetworks.com\n"
            f"Username: {username}\n"
            f"Password: {payload['CORTEX_API_KEY']}\n"
            f"Notes: {notes}"
        )

        # Create the entry via lpass CLI
        add_proc = subprocess.run(
            ['lpass', 'add', '--non-interactive', entry_name],
            input=entry_content,
            capture_output=True,
            text=True,
            timeout=30
        )
        if add_proc.returncode != 0:
            return f"LastPass Error: Failed to create entry - {add_proc.stderr.strip()}"

        return "SUCCESS (LastPass)"

    except Exception as e:
        return f"LastPass Error: {str(e)}"


def store_secret_payload(provider_config, base_name, payload):
    """
    Evaluates runtime selection parameters and forwards secret payloads to the requested vault engine.

    Returns:
        str: Target backend storage engine operational response label.
    """
    provider = provider_config['provider']
    if provider == 'none': return "NOT REQUESTED"

    if provider == 'aws':
        secret_path = f"{provider_config['prefix'].strip('/')}/{base_name}"
        return store_in_aws(secret_path, payload, provider_config['target'])
    elif provider == 'azure':
        secret_path = f"{provider_config['prefix']}-{base_name}" if provider_config['prefix'] else base_name
        return store_in_azure(provider_config['target'], secret_path, payload)
    elif provider == 'gcp':
        secret_path = f"{provider_config['prefix']}-{base_name}" if provider_config['prefix'] else base_name
        return store_in_gcp(provider_config['target'], secret_path, payload)
    elif provider == 'keepass':
        entry_title = f"Cortex - {base_name.replace('_', ' ').title()}"
        return store_in_keepass(
            provider_config['target'], provider_config['password'], provider_config['prefix'],
            entry_title, base_name, payload["CORTEX_API_KEY"], payload["CORTEX_API_KEY_ID"],
            payload["ROLE"], payload["DEPARTMENT"]
        )
    elif provider == 'hashicorp':
        path = f"{provider_config['prefix'].strip('/')}/{base_name}"
        return store_in_hashicorp(provider_config['target'], provider_config['password'], provider_config['mount'], path, payload)
    elif provider == 'infisical':
        secret_name = f"CORTEX_{base_name.upper()}"
        return store_in_infisical(provider_config['target'], provider_config['client_id'], provider_config['password'], provider_config['prefix'], provider_config['env'], secret_name, json.dumps(payload))
    elif provider == 'doppler':
        secret_name = f"CORTEX_{base_name.upper()}"
        return store_in_doppler(provider_config['password'], provider_config['prefix'], provider_config['env'], secret_name, json.dumps(payload))
    elif provider == 'onepassword':
        item_title = f"Cortex - {base_name.replace('_', ' ').title()}"
        return store_in_onepassword(provider_config['target'], provider_config['password'], provider_config['prefix'], item_title, base_name, payload)
    elif provider == 'lastpass':
        entry_title = f"Cortex - {base_name.replace('_', ' ').title()}"
        return store_in_lastpass(
            provider_config['target'],
            provider_config['password'],
            entry_title,
            payload
        )
    return "SKIPPED"


# ==============================================================================
# EXECUTIVE WORKFLOW RUNNER
# ==============================================================================
def run_provisioning_workflow(input_path, output_path, provisioner_client, role, expiration_ms=None, save_csv=True, target_config=None, scope_assets_payload=None, check_window_days=7):
    """
    Executes the comprehensive key processing manifest cycle. This coordinates directory validation,
    multi-key lifecycle mapping, rate-limiting back-offs, IAM scopes, and secret syncing.
    """
    target_records = []
    if isinstance(input_path, list):
        target_records = input_path
    else:
        if not os.path.exists(input_path):
            print(f"[!] Input file '{input_path}' missing.")
            sys.exit(1)

        with open(input_path, mode='r', newline='', encoding='utf-8-sig') as infile:
            reader = csv.DictReader(infile)
            headers = {f.lower().strip(): f for f in reader.fieldnames} if reader.fieldnames else {}

            fname_key = headers.get('firstname')
            lname_key = headers.get('lastname')
            dept_key = headers.get('department')
            email_key = headers.get('email')

            if not all([fname_key, lname_key, email_key]):
                print(f"[!] Format error: CSV requires 'Firstname', 'Lastname', and 'Email' headers.")
                sys.exit(1)

            for row in reader:
                first = row.get(fname_key, "").strip()
                last = row.get(lname_key, "").strip()
                email = row.get(email_key, "").strip().lower()
                dept = row.get(dept_key, "").strip() or "N/A"
                if email:
                    target_records.append({'first': first, 'last': last, 'email': email, 'dept': dept})

    # Step 1: Pre-fetch Cortex Directory map
    print("[*] Syncing live account records from Cortex User Directory...")
    active_cortex_emails = provisioner_client.get_active_cortex_emails()

    # Step 2: Pre-fetch Existing Key Lifecycles
    print("[*] Syncing live token map from Cortex Gateway...")
    keys_lifecycle = provisioner_client.get_existing_keys_lifecycle()

    print(f"[+] Processing {len(target_records)} personnel rows under account rotation checks...")
    results_ledger = []
    creation_count = 0
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    check_window_ms = check_window_days * 24 * 60 * 60 * 1000

    for idx, record in enumerate(target_records, start=1):
        f_name, l_name, email, dept_name = record['first'], record['last'], record['email'], record['dept']
        vault_status = "NOT REQUESTED"
        scope_status = "NOT REQUESTED"

        if email not in active_cortex_emails:
            print(f"[-] Skipped: User '{f_name} {l_name}' ({email}) has no profile account registered in Cortex.")
            results_ledger.append({
                'Firstname': f_name, 'Lastname': l_name, 'Email': email, 'Department': dept_name,
                'old_api_key_id': 'N/A', 'new_api_key_id': 'SKIPPED_NO_ACCOUNT', 'new_api_key': 'SKIPPED',
                'cortex_comment': 'N/A', 'cortex_status': 'SKIPPED', 'scope_sync_status': scope_status, 'storage_vault_status': 'SKIPPED'
            })
            continue

        # Rule Check 2: Evaluate Timeline Lease using Email-scoped unique comment structures
        target_comment = f"Assigned to user: {f_name} {l_name} ({email})"
        existing_keys = keys_lifecycle.get(target_comment, [])

        should_rotate = False
        reason = "No matching key comment footprint found for this specific email address."
        old_key_ids_str = "N/A"

        if existing_keys:
            old_key_ids_str = ", ".join([str(k["id"]) for k in existing_keys])
            print(f"\n[*] Found {len(existing_keys)} existing key(s) for {f_name} {l_name} ({email}):")

            expiring_count = 0
            for k in existing_keys:
                key_expiration = k["expiration"]
                k_id = k["id"]
                if key_expiration is None:
                    print(f"    - Key ID {k_id}: Configured to never expire.")
                else:
                    ms_until_expiration = key_expiration - now_ms
                    days_left = round(ms_until_expiration / (1000 * 60 * 60 * 24), 1)
                    if ms_until_expiration <= check_window_ms:
                        expiring_count += 1
                        print(f"    - Key ID {k_id}: Expires in {days_left} days. -> FLAGS FOR ROTATION")
                    else:
                        print(f"    - Key ID {k_id}: Expires in {days_left} days. (Healthy)")

            if expiring_count > 0 or len(existing_keys) > 1:
                should_rotate = True
                reason = f"User holds multiple keys ({len(existing_keys)} found) on the instance." if len(existing_keys) > 1 else "An existing key falls within the window."
            else:
                should_rotate = False
                reason = "All active keys associated with this profile are currently healthy."
        else:
            should_rotate = True
            reason = "No active key registered under this exact user and email comment signature block."

        if not should_rotate:
            print(f"[=] Healthy: Skipping rotation for {f_name} {l_name}. Reason: {reason}")
            results_ledger.append({
                'Firstname': f_name, 'Lastname': l_name, 'Email': email, 'Department': dept_name,
                'old_api_key_id': old_key_ids_str, 'new_api_key_id': 'CURRENT_KEY_VALID', 'new_api_key': 'SKIPPED',
                'cortex_comment': target_comment, 'cortex_status': 'SKIPPED_HEALTHY', 'scope_sync_status': scope_status, 'storage_vault_status': 'SKIPPED'
            })
            continue

        if existing_keys:
            print(f"[!] Policy recommends rotation for {f_name} {l_name}. Reason: {reason}")
            confirm_choice = input(f"    Proceed with creating a replacement key for this user? (y/N): ").strip().lower()
            if confirm_choice != 'y':
                print(f"    [→] Rotation canceled by operator request.")
                results_ledger.append({
                    'Firstname': f_name, 'Lastname': l_name, 'Email': email, 'Department': dept_name,
                    'old_api_key_id': old_key_ids_str, 'new_api_key_id': 'SKIPPED_BY_OPERATOR', 'new_api_key': 'SKIPPED',
                    'cortex_comment': target_comment, 'cortex_status': 'SKIPPED_BY_OPERATOR', 'scope_sync_status': scope_status, 'storage_vault_status': 'SKIPPED'
                })
                continue

        print(f"\n[!] Triggering rotation cycle for: {f_name} {l_name}. Reason: {reason}")

        if creation_count > 0:
            if creation_count % 10 == 0:
                print(f"[*] Batch Interval: Completed {creation_count} tokens. Halting thread for 60 seconds...")
                time.sleep(60)
            else:
                print(f"[*] Throttling delay: Pausing 15 seconds before processing next entity...")
                time.sleep(15)

        key_id, secret = provisioner_client.generate_api_key(f_name, l_name, email, role, expiration_ms)

        if key_id and secret:
            creation_count += 1

            if scope_assets_payload:
                print(f"        [*] Injecting Asset IAM scope configuration blocks for key reference {key_id}...")
                success, scope_msg = provisioner_client.update_key_scope(key_id, scope_assets_payload)
                scope_status = scope_msg if success else f"ERROR: {scope_msg}"
            else:
                scope_status = "DEFAULT_NO_CHANGES"

            secret_payload = {
                "CORTEX_API_KEY_ID": key_id, "CORTEX_API_KEY": secret,
                "ROLE": role, "DEPARTMENT": dept_name, "EMAIL": email, "SYNC_DATE": datetime.now(timezone.utc).isoformat()
            }

            base_name = f"{f_name.lower().replace(' ', '_')}_{l_name.lower().replace(' ', '_')}"
            vault_status = store_secret_payload(target_config, base_name, secret_payload)

            print(f"    [✓] Rotation processed successfully for User: {f_name} {l_name}")
            print(f"        Identity Contact: {email} | Department Group: {dept_name}")
            print(f"        IAM Scope Injection: {scope_status}")
            print(f"        Old Key ID(s): {old_key_ids_str} -> New Key ID Reference: {key_id} | Storage Sync Status: {vault_status}")
            print(f"        [!] REMINDER: The old key references ({old_key_ids_str}) should be tracked and deleted after their grace period.")

            results_ledger.append({
                'Firstname': f_name, 'Lastname': l_name, 'Email': email, 'Department': dept_name,
                'old_api_key_id': old_key_ids_str, 'new_api_key_id': key_id, 'new_api_key': secret,
                'cortex_comment': target_comment, 'cortex_status': 'ROTATED', 'scope_sync_status': scope_status, 'storage_vault_status': vault_status
            })
        else:
            results_ledger.append({
                'Firstname': f_name, 'Lastname': l_name, 'Email': email, 'Department': dept_name,
                'old_api_key_id': old_key_ids_str, 'new_api_key_id': 'FAILED', 'new_api_key': 'FAILED',
                'cortex_comment': target_comment, 'cortex_status': 'FAILED', 'scope_sync_status': 'FAILED', 'storage_vault_status': 'SKIPPED'
            })

    if save_csv:
        csv_headers = [
            'Firstname', 'Lastname', 'Email', 'Department',
            'old_api_key_id', 'new_api_key_id', 'new_api_key',
            'cortex_comment', 'cortex_status', 'scope_sync_status', 'storage_vault_status'
        ]
        with open(output_path, mode='w', newline='', encoding='utf-8-sig') as outfile:
            writer = csv.DictWriter(outfile, fieldnames=csv_headers)
            writer.writeheader()
            writer.writerows(results_ledger)
        print(f"\n[+] Processing run finished. Log ledger written out to: {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cortex Bulk Key Provisioner & Rotation Utility")
    parser.add_argument("--setup", action="store_true", help="Interactive setup wizard to configure tenant credentials.")
    parser.add_argument("--role", help="Cortex Role name.")
    parser.add_argument("--lifetime", type=int, help="API key lifetime in days.")
    parser.add_argument("--check-window", type=int, help="Key rotation check window in days.")
    parser.add_argument("--scope-choice", choices=["0", "1", "2"], help="Scoping Option: 0 (no_scope), 1 (see_all), 2 (scope).")
    parser.add_argument("--scope-method", choices=["A", "B", "a", "b"], help="Scoping Selection Method: A (manual), B (filter search).")
    parser.add_argument("--scope-ids", help="Target Asset Group IDs (comma-separated).")
    parser.add_argument("--scope-search", help="Search string to filter asset groups.")
    parser.add_argument("--scope-selection", help="Chosen filtered asset group index selections (comma-separated).")
    parser.add_argument("--source-choice", choices=["1", "2"], help="User Ingestion Source: 1 (CSV), 2 (Platform User Directory).")
    parser.add_argument("--user-search", help="Search string to filter platform users.")
    parser.add_argument("--user-selection", help="Chosen user index selections (comma-separated) or 'ALL'.")
    parser.add_argument("--storage-choice", choices=[str(i) for i in range(10)], help="Storage Provider selection index (0-9).")
    parser.add_argument("--vault-target", help="Vault provider target location parameter (Region, URL, Path).")
    parser.add_argument("--vault-prefix", help="Vault provider secret prefix / path / directory / project ID.")
    parser.add_argument("--vault-password", help="Vault provider master token, password, or key parameter.")
    parser.add_argument("--vault-mount", help="HashiCorp Vault engine mount point details.")
    parser.add_argument("--vault-env", help="Environment slug details (Infisical/Doppler).")
    parser.add_argument("--vault-client-id", help="Machine Identity Client ID tracking tag (Infisical).")
    parser.add_argument("--save-csv", choices=["y", "n", "Y", "N"], help="Save local backup CSV ledger output toggle.")
    args = parser.parse_args()

    if args.setup:
        print("Cortex Bulk Key Provisioner Setup")
        print("-" * 40)
        raw_url = input("  Cortex URL (e.g. tenant.xdr.us.paloaltonetworks.com): ").strip()
        raw_url = re.sub(r"^https?://", "", raw_url).rstrip("/")
        baseurl = f"https://{raw_url}"
        key_id = input("  ACCESS_KEY_ID: ").strip()
        api_key = input("  SECRET_KEY: ").strip()

        config = configparser.ConfigParser()
        config["URL"] = {"BaseURL": baseurl}
        config["AUTHENTICATION"] = {"ACCESS_KEY_ID": key_id, "SECRET_KEY": api_key}

        with open(".cortex_keys.config", "w") as f:
            config.write(f)

        print(f"\n[+] Config saved to .cortex_keys.config")
        print(f"  BaseURL       : {baseurl}")
        print(f"  ACCESS_KEY_ID : {key_id}")
        print(f"  SECRET_KEY    : {'*' * 6}{api_key[-4:] if len(api_key) > 4 else '****'}")
        sys.exit(0)

    baseurl, api_key_id, api_key = read_api_config()
    cortex_client = CortexBulkKeyProvisioner(baseurl, api_key_id, api_key)

    # 1. Configs & Expirations
    selected_role = args.role or input("Enter Cortex Role name (Default: Developer): ").strip() or "Developer"
    user_input = str(args.lifetime) if args.lifetime is not None else input("Enter API key lifetime in days (Default: 90): ").strip()
    expiration_ms = int((datetime.now(timezone.utc) + timedelta(days=int(user_input or 90))).timestamp() * 1000)

    check_window_input = str(args.check_window) if args.check_window is not None else input("Enter key rotation check window in days (Default: 7): ").strip()
    check_window_days = int(check_window_input or 7)

    print("\n--- API Key Asset Scope Configuration ---")
    print("0. Keep Default Scoping (No changes/no_scope)")
    print("1. Allow Full Visibility (see_all)")
    print("2. Restrict to Specific Asset Groups (scope)")
    scope_choice = args.scope_choice or input("Select Scoping Option (0-2, Default: 0): ").strip() or "0"

    scope_assets_payload = None
    if scope_choice == "1":
        scope_assets_payload = {"mode": "see_all", "asset_groups": []}
    elif scope_choice == "2":
        if not args.scope_choice:
            print("\nAsset Scoping Selection Method:")
            print("  A. Enter specific Asset Group IDs manually")
            print("  B. Select from a filtered list of groups using a custom search string")
        sub_choice = args.scope_method or input("Select method (A or B, Default: B): ").strip().upper() or "B"
        sub_choice = sub_choice.upper()

        parsed_ids = []
        if sub_choice == "A":
            group_input = args.scope_ids or input("Enter target Asset Group IDs (comma-separated, e.g., 1, 2, 3): ").strip()
            parsed_ids = [int(g.strip()) for g in group_input.split(",") if g.strip().isdigit()]
        else:
            search_string = args.scope_search or input("Enter search string to filter asset groups: ").strip().lower()
            search_string = search_string.lower()
            print("[*] Fetching available SBAC enabled asset groups from Cortex...")
            available_groups = cortex_client.get_asset_groups()
            if not available_groups:
                print("[!] Error: No dynamic asset groups found on this tenant.")
                sys.exit(1)

            filtered_groups = [
                g for g in available_groups
                if search_string in g.get("XDM.ASSET_GROUP.NAME", "").lower() and g.get("IS_USED_BY_SBAC") is True
            ]

            if not filtered_groups:
                print(f"[!] Error: No asset groups containing the string '{search_string}' were found inside the inventory.")
                sys.exit(1)

            if not args.scope_search:
                print(f"\nFiltered Asset Groups (Found {len(filtered_groups)} matching options):")
                for idx, g in enumerate(filtered_groups, start=1):
                    g_name = g.get("XDM.ASSET_GROUP.NAME", "Unnamed Group")
                    g_id = g.get("XDM.ASSET_GROUP.ID", "Unknown ID")
                    print(f"  {idx}. {g_name} (ID: {g_id})")

            selection_input = args.scope_selection or input("\nEnter chosen group numbers (comma-separated, e.g., 1, 2): ").strip()
            selected_indices = [int(i.strip()) - 1 for i in selection_input.split(",") if i.strip().isdigit()]

            for index in selected_indices:
                if 0 <= index < len(filtered_groups):
                    group_id = filtered_groups[index].get("XDM.ASSET_GROUP.ID")
                    if group_id is not None:
                        parsed_ids.append(int(group_id))

        if not parsed_ids:
            print("[!] Error: No valid asset groups were mapped or specified.")
            sys.exit(1)
        scope_assets_payload = {
            "mode": "scope",
            "asset_group_ids": parsed_ids
        }

    print("\n--- User Ingestion Source Configuration ---")
    print("1. Load from local users.csv file")
    print("2. Select directly from live platform users")
    source_choice = args.source_choice or input("Select source (1-2, Default: 1): ").strip() or "1"

    user_input_source = "users.csv"
    if source_choice == "2":
        user_search = args.user_search or input("Enter search string to filter platform users (or press Enter for all): ").strip().lower()
        if user_search:
            user_search = user_search.lower()
        print("[*] Fetching platform users...")
        platform_users = cortex_client.get_platform_users()
        if not platform_users:
            print("[!] Error: No platform users found or unable to fetch user directory.")
            sys.exit(1)

        filtered_users = [
            u for u in platform_users
            if not user_search or user_search in u.get("user_email", "").lower() or user_search in u.get("user_first_name", "").lower() or user_search in u.get("user_last_name", "").lower()
        ]

        if not filtered_users:
            print(f"[!] Error: No platform users found matching '{user_search}'.")
            sys.exit(1)

        if not args.user_search:
            print(f"\nFiltered Platform Users (Found {len(filtered_users)} matching options):")
            for idx, u in enumerate(filtered_users, start=1):
                u_email = u.get("user_email", "Unknown Email")
                u_first = u.get("user_first_name", "")
                u_last = u.get("user_last_name", "")
                print(f"  {idx}. {u_first} {u_last} ({u_email})")

        user_selection = args.user_selection or input("\nEnter chosen user numbers (comma-separated, e.g., 1, 2) or 'ALL': ").strip()

        selected_users = []
        if user_selection.upper() == "ALL":
            selected_users = filtered_users
        else:
            indices = [int(i.strip()) - 1 for i in user_selection.split(",") if i.strip().isdigit()]
            for index in indices:
                if 0 <= index < len(filtered_users):
                    selected_users.append(filtered_users[index])

        if not selected_users:
            print("[!] Error: No users selected.")
            sys.exit(1)

        user_input_source = []
        for u in selected_users:
            groups = u.get("groups", [])
            dept_val = groups[0].get("group_name", "N/A") if groups else "N/A"
            user_input_source.append({
                'first': u.get("user_first_name", "").strip(),
                'last': u.get("user_last_name", "").strip(),
                'email': u.get("user_email", "").strip().lower(),
                'dept': dept_val
            })

    target_config = {"provider": "none", "target": "", "prefix": "", "password": "", "env": "", "client_id": ""}

    # --- Persistent Storage Configuration Load ---
    saved_storage = load_storage_config()
    use_saved_config = False
    if saved_storage and saved_storage.get('provider') and saved_storage['provider'] != 'none' and not args.storage_choice:
        print("\n--- Saved Storage Configuration Found ---")
        print(f"  Provider     : {saved_storage['provider']}")
        if saved_storage.get('target'):
            print(f"  Target       : {saved_storage['target']}")
        if saved_storage.get('prefix'):
            print(f"  Prefix       : {saved_storage['prefix']}")
        if saved_storage.get('mount'):
            print(f"  Mount Point  : {saved_storage['mount']}")
        if saved_storage.get('env'):
            print(f"  Environment  : {saved_storage['env']}")
        has_saved_password = bool(saved_storage.get('password'))
        print(f"  Password     : {'(saved)' if has_saved_password else '(not saved - will prompt)'}")
        reuse_choice = input("Use saved storage configuration? (Y/n): ").strip().lower()
        if reuse_choice != 'n':
            use_saved_config = True
            target_config = {
                "provider": saved_storage['provider'],
                "target": saved_storage.get('target', ''),
                "prefix": saved_storage.get('prefix', ''),
                "password": saved_storage.get('password', ''),
                "mount": saved_storage.get('mount', ''),
                "env": saved_storage.get('env', ''),
                "client_id": saved_storage.get('client_id', '')
            }
            # Prompt for password if not saved
            if not target_config['password']:
                target_config['password'] = input(f"Enter vault password/token for {target_config['provider']}: ").strip()

    if not use_saved_config:
        print("\n--- Key Storage Configuration ---")
        print("0. Local Storage Only (No Cloud Vault)")
        print("1. AWS Secrets Manager")
        print("2. Azure Key Vault")
        print("3. GCP Secret Manager")
        print("4. HashiCorp Vault / OpenBao")
        print("5. Infisical Secrets Platform")
        print("6. Doppler SecretOps Control")
        print("7. KeePass Database (.kdbx)")
        print("8. 1Password Secrets Automation")
        print("9. LastPass Vault")
        choice = args.storage_choice or input("Select Storage Provider (0-9, Default: 0): ").strip() or "0"

        if choice == "1":
            target_config.update({
                "provider": "aws",
                "target": args.vault_target or input("AWS Region (Default: us-east-1): ").strip() or "us-east-1",
                "prefix": args.vault_prefix or input("Secret Path Prefix (Default: cortex/api_keys): ").strip() or "cortex/api_keys"
            })
        elif choice == "2":
            target_config.update({
                "provider": "azure",
                "target": args.vault_target or input("Azure Key Vault URL: ").strip(),
                "prefix": args.vault_prefix or input("Secret Prefix (Optional): ").strip()
            })
        elif choice == "3":
            target_config.update({
                "provider": "gcp",
                "target": args.vault_target or input("GCP Project ID: ").strip(),
                "prefix": args.vault_prefix or input("Secret Prefix (Optional): ").strip()
            })
        elif choice == "4":
            if not HASHICORP_AVAILABLE:
                print("[!] Aborted: 'hvac' missing. Run via: uv run --with hvac Create_Api_Keys.py"); sys.exit(1)
            target_config.update({
                "provider": "hashicorp",
                "target": args.vault_target or input("Vault Server URL (e.g., http://127.0.0.1:8200): ").strip(),
                "password": args.vault_password or input("Vault Token: ").strip(),
                "mount": args.vault_mount or input("KV Engine Mount Point (Default: secret): ").strip() or "secret",
                "prefix": args.vault_prefix or input("Secret Path Directory (Default: cortex): ").strip() or "cortex"
            })
        elif choice == "5":
            if not INFISICAL_AVAILABLE:
                print("[!] Aborted: 'infisical-sdk' missing. Run via: uv run --with infisicalsdk Create_Api_Keys.py"); sys.exit(1)
            target_config.update({
                "provider": "infisical",
                "target": args.vault_target or input("Infisical Host FQDN (Default: https://app.infisical.com): ").strip() or "https://app.infisical.com",
                "client_id": args.vault_client_id or input("Machine Identity Client ID: ").strip(),
                "password": args.vault_password or input("Machine Identity Client Secret: ").strip(),
                "prefix": args.vault_prefix or input("Project ID Link: ").strip(),
                "env": args.vault_env or input("Environment Slug (Default: dev): ").strip() or "dev"
            })
        elif choice == "6":
            target_config.update({
                "provider": "doppler",
                "password": args.vault_password or input("Doppler Service Token: ").strip(),
                "prefix": args.vault_prefix or input("Doppler Project Name: ").strip(),
                "env": args.vault_env or input("Doppler Configuration Name: ").strip()
            })
        elif choice == "7":
            if not KEEPASS_AVAILABLE:
                print("[!] Aborted: 'pykeepass' missing. Run via: uv run --with pykeepass Create_Api_Keys.py"); sys.exit(1)
            target_config.update({
                "provider": "keepass",
                "target": args.vault_target or input("KeePass Path (Default: cortex_keys.kdbx): ").strip() or "cortex_keys.kdbx",
                "password": args.vault_password or input("Enter KeePass Master Password: ").strip(),
                "prefix": args.vault_prefix or input("Group Name (Default: Cortex Keys): ").strip() or "Cortex Keys"
            })
            if not target_config["password"]:
                print("[!] Error: KeePass master password cannot be empty.")
                sys.exit(1)
        elif choice == "8":
            target_config.update({
                "provider": "onepassword",
                "target": args.vault_target or input("1Password Connect Server API URL: ").strip(),
                "password": args.vault_password or input("Connect Bearer Access Token: ").strip(),
                "prefix": args.vault_prefix or input("Target Vault UUID: ").strip()
            })
        elif choice == "9":
            if not LASTPASS_AVAILABLE:
                print("[!] Aborted: 'lastpass-python' missing. Run via: uv run --with lastpass-python Create_Api_Keys.py"); sys.exit(1)
            target_config.update({
                "provider": "lastpass",
                "target": args.vault_target or input("LastPass Email Address: ").strip(),
                "password": args.vault_password or input("LastPass Master Password: ").strip(),
                "prefix": args.vault_prefix or input("Vault Group/Folder (Default: Cortex Keys): ").strip() or "Cortex Keys"
            })
            if not target_config["target"]:
                print("[!] Error: LastPass email address cannot be empty.")
                sys.exit(1)
            if not target_config["password"]:
                print("[!] Error: LastPass master password cannot be empty.")
                sys.exit(1)

    # --- Offer to save storage configuration ---
    if not use_saved_config and target_config['provider'] != 'none':
        save_config_choice = input("\nSave storage configuration for future runs? (y/N): ").strip().lower()
        if save_config_choice == 'y':
            include_pw = False
            if target_config.get('password'):
                save_pw_choice = input("Also save vault password/token to config file? (y/N): ").strip().lower()
                include_pw = (save_pw_choice == 'y')
            save_storage_config(target_config, include_password=include_pw)
            print("[+] Storage configuration saved to .cortex_keys.config")

    if args.save_csv:
        save_local_csv = args.save_csv.lower() != 'n'
    else:
        save_local_csv = input("\nDo you also want to save a local backup CSV ledger? (Y/n): ").strip().lower() != 'n'

    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"generated_developer_keys_{timestamp_str}.csv"

    run_provisioning_workflow(user_input_source, output_filename, cortex_client, selected_role, expiration_ms, save_local_csv, target_config, scope_assets_payload, check_window_days)