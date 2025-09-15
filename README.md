# EntraID → AWS SAML STS Credential Manager (GUI)

This project is a **desktop GUI tool** that automates **Microsoft Entra ID SAML login**, retrieves **temporary AWS STS credentials**, and securely stores them in **HashiCorp Vault**.
It refresh the vaulted credential automatically.
It is used to certain circumstances that developers cannot hardcode or even store in unencrypted environment variables.
I've come to decide to develope this as tool for financial-company developers

Built with **PyQt6**, it uses **selenium-wire** to capture SAML responses from Edge browser sessions and **boto3** to call `AssumeRoleWithSAML`.  
Ideal for developers/engineers who need to easily obtain AWS credentials via SAML without manually copying/pasting tokens.

---

## Installation & Usage

Install dependencies:

```bash
pip install pyqt6 selenium-wire selenium boto3 hvac
```

Run the application:

```bash
python main_open.py
```

Fill in the fields:

- **Entra App URL** – The MyApps sign-in endpoint  
- **AWS Region** – e.g., `ap-northeast-2`  
- **DurationSeconds** – STS session lifetime (900–43200 seconds)  
- **Target RoleArn / AccountId / RoleName** – Optional filters  

Click **Start** to initiate login & credential retrieval.  
The log panel shows Vault initialization, SAML capture, STS response, and credential storage.  
Click **Stop** to terminate the worker and stop the Vault server.

---

## Packaging with PyInstaller

Build a standalone executable:

```bash
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed   --collect-all seleniumwire   main_open.py
```

- `--collect-all seleniumwire` ensures `selenium-wire` resources are included.
- `--windowed` hides console output.
- The resulting executable will be at `dist/main_open.exe`.

---

## Environment Variables & Generated Files

When credentials are successfully issued, the tool:

- Sets runtime & persistent environment variables:
  - `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_UNSEAL_KEY`, `VAULT_BIN`, `VAULT_WORKDIR`
- Generates helper scripts:
  - `vault_env.ps1` (PowerShell)
  - `vault_env.cmd` (Batch)
- Stores credentials in Vault KV v2 at `secret/aws-credentials`:
  - Keys: `vault.iam.accessKeyId`, `vault.iam.secretKey`, `vault.iam.sessionToken`, `vault.sts.expiration`

Load environment variables in a new console:

```powershell
. "$env:USERPROFILE\vault-dev\vault_env.ps1"
```

or

```bat
call "%USERPROFILE%\vault-dev\vault_env.cmd"
```

---

## Retrieving Credentials from Vault

Retrieve credentials programmatically with `hvac`:

```python
import hvac, os

client = hvac.Client(url=os.environ["VAULT_ADDR"], token=os.environ["VAULT_TOKEN"])
resp = client.secrets.kv.v2.read_secret_version(path="aws-credentials")
creds = resp["data"]["data"]

print("AccessKeyId:", creds["vault.iam.accessKeyId"])
print("SecretKey:", creds["vault.iam.secretKey"])
print("SessionToken:", creds["vault.iam.sessionToken"])
print("Expires:", creds["vault.sts.expiration"])
```

Or via Vault CLI:

```bash
vault kv get secret/aws-credentials
```

---

## Notes

- The correct `msedgedriver.exe` version is auto-downloaded if missing.
- Unseal key & root token files are stored in `%USERPROFILE%\vault-dev`; keep them secure.
- `selenium-wire` uses a local proxy and may be blocked by corporate network policy.
- Designed for Windows but most logic is cross-platform.

---

## License

MIT License.  
Please provide attribution when redistributing or modifying.
