# main_gui.py
# -*- coding: utf-8 -*-
"""
dependency:
  pip install pyqt6 selenium-wire selenium boto3 hvac
"""

from __future__ import annotations
import os, sys, re, time, base64, zipfile, socket, shutil, subprocess, json, traceback, threading
from pathlib import Path
from typing import Optional, List, Tuple
from urllib.parse import parse_qs, urlparse
from urllib.request import urlopen, urlretrieve
from xml.etree import ElementTree as ET
from datetime import datetime, timezone

import boto3, hvac

# ----- PyQt6 -----
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject, QTimer, QSettings, QByteArray
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QPushButton, QCheckBox,
    QSpinBox, QLineEdit, QTextEdit, QGridLayout, QHBoxLayout, QVBoxLayout,
    QMessageBox, QFileDialog, QSplitter
)

# ----- Selenium / selenium-wire -----
from seleniumwire import webdriver as wire_webdriver
from selenium.webdriver.edge.options import Options as EdgeOptions
from selenium.webdriver.edge.service import Service as EdgeService

def resource_path(rel_path: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.abspath(os.path.dirname(__file__)))
    return os.path.join(base, rel_path)


IS_WIN = os.name == "nt"
APP_ICON_PATH = resource_path("") #App icon file
APP_TITLE = "EntraID2AWS 1.0"
AAD_APP_SIGNIN_URL = ""#"https://launcher.myapps.microsoft.com/api/signin/aaaaaaaa-aaaa...""

# ===== General Setting =====
AWS_DEFAULT_REGION = "" # ap-northeast-2, etc
VAULT_VERSION = "1.15.4"
VAULT_ADDR = "http://127.0.0.1:8200"
WORK_DIR = Path.home() / "vault-dev"
BIN_DIR = WORK_DIR / "bin"
VAULT_EXE = shutil.which("vault") or str(BIN_DIR / ("vault.exe" if IS_WIN else "vault"))
CFG_FILE = WORK_DIR / "config.hcl"
UNSEAL_FILE = WORK_DIR / "unseal.key"
ROOT_FILE = WORK_DIR / "root.token"
KEYS_TXT = WORK_DIR / "vault.keys.txt"
LOG_FILE = WORK_DIR / "vault.log"

# ---- Vault Process Handling ----
VAULT_PROC: Optional[subprocess.Popen] = None
VAULT_LOG_FP = None
VAULT_LOCK = threading.Lock()

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def info(log_fn, msg: str): log_fn(f"[INFO] {msg}")
def warn(log_fn, msg: str): log_fn(f"[WARN] {msg}")
def err(log_fn, msg: str):  log_fn(f"[ERR ] {msg}")

def _run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return p.returncode, p.stdout, p.stderr

# ---------------- EdgeDriver ----------------
def get_edge_major_version(log_fn) -> int:
    env_major = os.getenv("EDGE_MAJOR")
    if env_major and env_major.isdigit():
        return int(env_major)
    for p in [shutil.which("msedge"),
              r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
              r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"]:
        if p and Path(p).exists():
            _, out, _ = _run([p, "--version"])
            m = re.search(r"(\d+)\.\d+\.\d+\.\d+", out)
            if m: return int(m.group(1))
    try:
        import winreg
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                key = winreg.OpenKey(hive, r"Software\Microsoft\Edge\BLBeacon")
                ver, _ = winreg.QueryValueEx(key, "version")
                m = re.search(r"^(\d+)\.", ver)
                if m: return int(m.group(1))
            except OSError:
                pass
    except Exception:
        pass
    raise RuntimeError("Couldn't find the Edge's version info. Configure EDGE_MAJOR or EDGE_DRIVER_PATH")

def _get_driver_major(exe: str) -> int | None:
    try:
        rc, out, _ = _run([exe, "--version"])  # e.g. "MSEdgeDriver 141.0.3537.85 ..."
        if rc == 0:
            m = re.search(r"\b(\d+)\.\d+\.\d+\.\d+\b", out)
            if m: return int(m.group(1))
    except Exception:
        pass
    return None

def ensure_edge_driver(log_fn) -> str:
    p = os.getenv("EDGE_DRIVER_PATH")
    if p and Path(p).exists():
        return p

    BIN_DIR.mkdir(parents=True, exist_ok=True)
    cached = BIN_DIR / "msedgedriver.exe"

    # ✅ Major Browser check
    browser_major = get_edge_major_version(log_fn)

    # ✅ compare with major version if driver is cached
    if cached.exists():
        drv_major = _get_driver_major(str(cached))
        if drv_major == browser_major:
            return str(cached)
        else:
            info(log_fn, f"Cached EdgeDriver({drv_major}) != Edge({browser_major}) → re-download")
            try:
                cached.unlink()
            except Exception:
                pass

    pinned = os.getenv("EDGE_DRIVER_VERSION")
    if pinned:
        ver = pinned.strip()
    else:
        latest_url = f"https://msedgedriver.microsoft.com/LATEST_RELEASE_{browser_major}_WINDOWS"
        info(log_fn, f"Resolving EdgeDriver… {latest_url}")
        raw = urlopen(latest_url).read()
        ver = None
        for enc in ("utf-8","utf-16","utf-16-le","utf-16-be","latin-1"):
            try:
                t = raw.decode(enc).strip()
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", t): ver = t; break
            except UnicodeDecodeError:
                continue
        if not ver:
            t = raw.decode("utf-8", errors="ignore")
            m = re.search(r"\d+\.\d+\.\d+\.\d+", t)
            if m: ver = m.group(0)
        if not ver: raise RuntimeError("EdgeDriver 버전 파싱 실패")

    url = f"https://msedgedriver.microsoft.com/{ver}/edgedriver_win64.zip"
    z = BIN_DIR / "edgedriver_win64.zip"
    info(log_fn, f"Downloading EdgeDriver {ver} …")
    urlretrieve(url, str(z))
    with zipfile.ZipFile(z, "r") as zf: zf.extractall(BIN_DIR)

    exe = None
    for root,_,files in os.walk(BIN_DIR):
        if "msedgedriver.exe" in files:
            exe = Path(root) / "msedgedriver.exe"; break
    if not exe: raise RuntimeError("msedgedriver.exe 추출 실패")
    exe.chmod(0o755)
    return str(exe)

# ---------------- Vault helpers ----------------
def _tcp_wait(host: str, port: int, timeout: int = 120) -> bool:
    end = time.time() + timeout
    import socket as s
    while time.time() < end:
        try:
            with s.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.4)
    return False

def ensure_vault_binary(log_fn):
    global VAULT_EXE
    if shutil.which("vault"):
        VAULT_EXE = shutil.which("vault"); info(log_fn, f"Found Vault: {VAULT_EXE}"); return
    if Path(VAULT_EXE).exists():
        info(log_fn, f"Using local Vault: {VAULT_EXE}"); return
    if not IS_WIN:
        raise RuntimeError("Couldn't find Vault CLI")
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    url = f"https://releases.hashicorp.com/vault/{VAULT_VERSION}/vault_{VAULT_VERSION}_windows_amd64.zip"
    zip_path = BIN_DIR / f"vault_{VAULT_VERSION}_windows_amd64.zip"
    info(log_fn, f"Downloading Vault {VAULT_VERSION} …")
    urlretrieve(url, str(zip_path))
    with zipfile.ZipFile(zip_path, "r") as zf: zf.extractall(BIN_DIR)
    (BIN_DIR / "vault.exe").chmod(0o755)
    VAULT_EXE = str(BIN_DIR / "vault.exe")

def start_vault_server(log_fn):
    #Vault on background
    global VAULT_PROC, VAULT_LOG_FP
    with VAULT_LOCK:
        if VAULT_PROC and VAULT_PROC.poll() is None:
            info(log_fn, "Vault already running."); return

        WORK_DIR.mkdir(parents=True, exist_ok=True)
        if not CFG_FILE.exists():
            CFG_FILE.write_text(
                'ui = true\n'
                'storage "file" { path = "./vault-data" }\n'
                'listener "tcp" { address = "127.0.0.1:8200" tls_disable = true }\n'
                'default_lease_ttl = "10s"\nmax_lease_ttl = "10s"\n', encoding="utf-8"
            )

        env = os.environ.copy(); env["VAULT_ADDR"] = VAULT_ADDR
        VAULT_LOG_FP = open(LOG_FILE, "a", encoding="utf-8")
        info(log_fn, "Starting Vault server… (vault.log)")
        # Make vault.exe terminates when the program terminates
        creationflags = 0
        startupinfo = None
        if IS_WIN:
            # Flags to avoid vault.exe to run with windows
            creationflags |= subprocess.CREATE_NO_WINDOW
            creationflags |= 0x08000000
            creationflags |= subprocess.DETACHED_PROCESS
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0   # SW_HIDE
            startupinfo = si

        VAULT_PROC = subprocess.Popen(
            [VAULT_EXE, "server", "-config", str(CFG_FILE)],
            cwd=str(WORK_DIR),
            env=env,
            stdin=subprocess.DEVNULL,       
            stdout=VAULT_LOG_FP,               
            stderr=VAULT_LOG_FP,
            creationflags=creationflags,
            startupinfo=startupinfo,           
            close_fds=True                     
        )
    if not _tcp_wait("127.0.0.1", 8200, 120):
        stop_vault_server(log_fn)
        raise RuntimeError("Vault port 8200 timeout")
    info(log_fn, "Vault is ready on 127.0.0.1:8200")

def stop_vault_server(log_fn):
    #Ends vault.exe with the program
    global VAULT_PROC, VAULT_LOG_FP
    with VAULT_LOCK:
        proc = VAULT_PROC
        VAULT_PROC = None
    if not proc:
        return
    try:
        if proc.poll() is None:
            info(log_fn, "Stopping Vault server…")
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                info(log_fn, "Vault did not exit in time. Killing…")
                proc.kill()
                proc.wait(timeout=5)
    except Exception as e:
        err(log_fn, f"Vault stop error: {e}")
    finally:
        try:
            if VAULT_LOG_FP:
                VAULT_LOG_FP.flush()
                VAULT_LOG_FP.close()
        except Exception:
            pass
        VAULT_LOG_FP = None

def hvac_client(token: Optional[str] = None):
    return hvac.Client(url=VAULT_ADDR, token=token)

def _vault_initialize_compat(c):
    try:
        return c.sys.initialize(secret_shares=1, secret_threshold=1)
    except TypeError:
        return c.sys.initialize(shares=1, threshold=1)

def vault_init_unseal_login(log_fn) -> str:
    c = hvac_client()
    try:
        initialized = c.sys.is_initialized()
    except Exception:
        h = c.sys.read_health_status(method="GET")
        try: initialized = bool(h.json().get("initialized"))
        except Exception: initialized = False

    if not initialized:
        info(log_fn, "Initializing Vault…")
        init = _vault_initialize_compat(c)
        unseal = init["keys_base64"][0]; root = init["root_token"]
        UNSEAL_FILE.write_text(unseal+"\n", encoding="utf-8")
        ROOT_FILE.write_text(root+"\n", encoding="utf-8")
        KEYS_TXT.write_text(f"UNSEAL_KEY={unseal}\nROOT_TOKEN={root}\n", encoding="utf-8")
    else:
        if not UNSEAL_FILE.exists() or not ROOT_FILE.exists():
            raise RuntimeError("No Key files. Delete vault-data and re-initialize")

    unseal = UNSEAL_FILE.read_text().strip()
    root   = ROOT_FILE.read_text().strip()
    try:
        if c.sys.is_sealed():
            c.sys.submit_unseal_key(unseal)
    except Exception:
        pass
    c.token = root
    return root

def vault_ensure_kvv2(log_fn):
    c = hvac_client(token=ROOT_FILE.read_text().strip())
    try:
        mounts = c.sys.list_mounted_secrets_engines()["data"]
        if "secret/" not in mounts: raise KeyError
    except Exception:
        info(log_fn, 'Enabling KV v2 at "secret" …')
        try:
            c.sys.enable_secrets_engine(backend_type="kv", path="secret", options={"version": 2})
        except hvac.exceptions.InvalidRequest:
            pass
# === Vault env export helpers ===
def _broadcast_env_change():
    if not IS_WIN:
        return
    try:
        import ctypes
        HWND_BROADCAST = 0xFFFF
        WM_SETTINGCHANGE = 0x001A
        SMTO_ABORTIFHUNG = 0x0002
        ctypes.windll.user32.SendMessageTimeoutW(
            HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment",
            SMTO_ABORTIFHUNG, 5000, None
        )
    except Exception:
        pass

def _set_user_env_win(name: str, value: str):
    """Using user's env (No needs for admin preveilege)"""
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_SET_VALUE) as k:
        typ = winreg.REG_EXPAND_SZ if "%" in value else winreg.REG_SZ
        winreg.SetValueEx(k, name, 0, typ, value)

def _ensure_user_path_contains_win(path_to_add: str):
    """Add vault bin to PATH ad hoc """
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
        try:
            cur, typ = winreg.QueryValueEx(k, "Path")
        except FileNotFoundError:
            cur, typ = "", winreg.REG_EXPAND_SZ
        parts = [p.strip().lower() for p in cur.split(";") if p.strip()]
        if path_to_add.lower() not in parts:
            new_val = (cur + ";" if cur and not cur.endswith(";") else cur) + path_to_add
            winreg.SetValueEx(k, "Path", 0, winreg.REG_EXPAND_SZ, new_val)

def export_vault_env(log_fn, persist_user_env: bool = True, add_bin_to_path: bool = False):
    """ Put VAULT_ADDR/TOKEN/UNSEAL_KEY into Runtime + User Env and create PowerShell/Batch script."""
    try:
        addr   = VAULT_ADDR
        token  = ROOT_FILE.read_text(encoding="utf-8").strip()
        unseal = UNSEAL_FILE.read_text(encoding="utf-8").strip()
    except Exception as e:
        err(log_fn, f"env export failed(Key file read failed): {e}")
        return

    # 런타임 환경
    os.environ["VAULT_ADDR"] = addr
    os.environ["VAULT_TOKEN"] = token
    os.environ["VAULT_UNSEAL_KEY"] = unseal
    os.environ["VAULT_BIN"] = str(Path(VAULT_EXE).resolve())
    os.environ["VAULT_WORKDIR"] = str(WORK_DIR.resolve())

    info(log_fn, "Runtime ENV confirgured: VAULT_ADDR/VAULT_TOKEN/VAULT_UNSEAL_KEY/…")

    # 사용자 환경변수(영구)
    if IS_WIN and persist_user_env:
        try:
            _set_user_env_win("VAULT_ADDR", addr)
            _set_user_env_win("VAULT_TOKEN", token)
            _set_user_env_win("VAULT_UNSEAL_KEY", unseal)
            _set_user_env_win("VAULT_BIN", str(Path(VAULT_EXE).resolve()))
            _set_user_env_win("VAULT_WORKDIR", str(WORK_DIR.resolve()))
            if add_bin_to_path:
                _ensure_user_path_contains_win(str(Path(VAULT_EXE).resolve().parent))
            _broadcast_env_change()
            info(log_fn, "Saved to user ENV(HKCU\\Environment). Can be used at new console.")
        except Exception as e:
            warn(log_fn, f"Failed to save into user ENV (Permission Problem?): {e}")

    # 임포트용 스크립트 생성
    try:
        ps1 = WORK_DIR / "vault_env.ps1"
        ps1.write_text(
            f'$env:VAULT_ADDR="{addr}"\n'
            f'$env:VAULT_TOKEN="{token}"\n'
            f'$env:VAULT_UNSEAL_KEY="{unseal}"\n'
            f'$env:VAULT_BIN="{Path(VAULT_EXE).resolve()}"\n'
            f'$env:VAULT_WORKDIR="{WORK_DIR.resolve()}"\n',
            encoding="utf-8"
        )
        cmd = WORK_DIR / "vault_env.cmd"
        cmd.write_text(
            "@echo off\r\n"
            f'set "VAULT_ADDR={addr}"\r\n'
            f'set "VAULT_TOKEN={token}"\r\n'
            f'set "VAULT_UNSEAL_KEY={unseal}"\r\n'
            f'set "VAULT_BIN={Path(VAULT_EXE).resolve()}"\r\n'
            f'set "VAULT_WORKDIR={WORK_DIR.resolve()}"\r\n',
            encoding="utf-8"
        )
        info(log_fn, f"Import script created: {ps1} / {cmd}")
        info(log_fn, 'PowerShell for immediate apply:  . "\\vault_env.ps1"')
    except Exception as e:
        warn(log_fn, f"Failed to create import script: {e}")

# ---------------- selenium-wire capture ----------------
def start_url() -> str:
    return AAD_APP_SIGNIN_URL

def make_driver(session_fresh: bool, force_same_tab: bool, headless: bool, log_fn):
    edge_path = ensure_edge_driver(log_fn)
    opts = EdgeOptions()
    opts.set_capability("pageLoadStrategy", "none")
    if headless: opts.add_argument("--headless=new")
    if session_fresh: opts.add_argument("--inprivate")
    opts.add_argument("--disable-gpu"); opts.add_argument("--no-sandbox")

    inj = ""
    if force_same_tab:
        inj = r"""
        (function(){
          window.open = function(u){ try{ location.href = u; }catch(e){} return window; };
          const patch = ()=>{ document.querySelectorAll('a[target="_blank"]').forEach(a=>a.setAttribute('target','_self')); };
          patch(); new MutationObserver(patch).observe(document.documentElement,{subtree:true,childList:true,attributes:true});
        })();
        """

    sw_opts = {
        "verify_ssl": False,
        "suppress_connection_errors": True,
        "mitm_http2": False,                     
        "scopes": [r".*signin\.aws\.amazon\.com\/saml.*"],
        "request_storage_base_dir": str(WORK_DIR / "wire-store"),
    }

    driver = wire_webdriver.Edge(
        seleniumwire_options=sw_opts,
        service=EdgeService(edge_path),
        options=opts,
    )

    if inj:
        try:
            driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": inj})
            driver.execute_script("(function(){%s})();" % inj)
        except Exception:
            pass

    try:
        driver.requests.clear()
    except Exception:
        pass

    return driver

def capture_saml_response(session_fresh: bool, force_same_tab: bool, headless: bool, log_fn) -> str:
    url = start_url()
    drv = make_driver(session_fresh, force_same_tab, headless, log_fn)
    try:
        info(log_fn, f"Opening: {url}")
        drv.get(url)
        deadline = time.time() + 600
        last_len = 0
        saml_b64 = None

        def try_get_from_url(u: str) -> Optional[str]:
            try:
                if "SAMLResponse=" in u:
                    qs = parse_qs(urlparse(u).query)
                    return (qs.get("SAMLResponse") or [None])[0]
            except Exception:
                return None

        while time.time() < deadline and not saml_b64:
            reqs = drv.requests
            for req in reqs[last_len:]:
                try:
                    if not req.url: continue
                    v = try_get_from_url(req.url)
                    if v: saml_b64 = v; break

                    if req.method != "POST": continue
                    if "signin.aws.amazon.com" not in req.url or "/saml" not in req.url:
                        continue

                    body = req.body or b""
                    if isinstance(body, bytes):
                        body = body.decode("utf-8", "ignore")
                    if "SAMLResponse=" in body:
                        qs = parse_qs(body)
                        saml_b64 = (qs.get("SAMLResponse") or [None])[0]
                        break
                except Exception:
                    continue

            last_len = len(reqs)

            if not saml_b64:
                try:
                    v = try_get_from_url(drv.current_url or "")
                    if v: saml_b64 = v
                except Exception:
                    pass

            time.sleep(0.15)

        if not saml_b64:
            raise RuntimeError("SAMLResponse Capture Failed")
        info(log_fn, "Captured SAMLResponse.")
        return saml_b64
    finally:
        try: drv.quit()
        except Exception: pass

# ---------------- SAML → STS / Vault ----------------
def parse_roles(assertion_xml: str) -> List[Tuple[str, str]]:
    ns = {"saml2": "urn:oasis:names:tc:SAML:2.0:assertion"}
    root = ET.fromstring(assertion_xml)
    pairs = []
    for attr in root.findall(".//saml2:Attribute", ns):
        if attr.get("Name") == "https://aws.amazon.com/SAML/Attributes/Role":
            for v in attr.findall("saml2:AttributeValue", ns):
                parts = (v.text or "").split(",")
                if len(parts) == 2:
                    a, b = parts[0].strip(), parts[1].strip()
                    if ":saml-provider/" in a:
                        principal, role = a, b
                    else:
                        role, principal = a, b
                    pairs.append((principal, role))
    return pairs

def pick_role(pairs: List[Tuple[str,str]], target_role_arn: str, target_acct: str, target_role_name: str) -> Tuple[str,str]:
    if not pairs: raise RuntimeError("No AWS Role info in the Assertion")
    if target_role_arn:
        for pr, rl in pairs:
            if rl == target_role_arn: return pr, rl
    if target_role_name:
        for pr, rl in pairs:
            if rl.split("/")[-1] == target_role_name: return pr, rl
    if target_acct:
        for pr, rl in pairs:
            if f":{target_acct}:" in rl: return pr, rl
    return pairs[0]

def sts_assume_with_saml(assertion_b64: str, principal_arn: str, role_arn: str, duration_seconds: int, region: str):
    sts = boto3.client("sts", region_name=region)
    resp = sts.assume_role_with_saml(
        RoleArn=role_arn, PrincipalArn=principal_arn,
        SAMLAssertion=assertion_b64, DurationSeconds=duration_seconds
    )
    return resp["Credentials"]

def store_creds_to_vault(creds, log_fn):
    token = ROOT_FILE.read_text().strip()
    client = hvac_client(token=token)
    payload = {
        "vault.iam.accessKeyId":  creds["AccessKeyId"],
        "vault.iam.secretKey":    creds["SecretAccessKey"],
        "vault.iam.sessionToken": creds["SessionToken"],
        "vault.sts.expiration":   creds["Expiration"].isoformat(),
    }
    client.secrets.kv.v2.create_or_update_secret(
        mount_point="secret", path="aws-credentials", secret=payload
    )
    info(log_fn, 'Saved to Vault: secret/aws-credentials')

# ---------------- Worker ----------------
class Worker(QObject):
    log = pyqtSignal(str)
    status = pyqtSignal(str)
    expiresAt = pyqtSignal(str)   # ISO8601
    finished = pyqtSignal()

    def __init__(self, duration_seconds:int, renew_leeway:int, session_fresh:bool,
                 force_same_tab:bool, headless:bool, region:str,
                 target_role_arn:str, target_acct:str, target_role_name:str,
                 continuous:bool=True):
        super().__init__()
        self.duration_seconds = duration_seconds
        self.renew_leeway = renew_leeway
        self.session_fresh = session_fresh
        self.force_same_tab = force_same_tab
        self.headless = headless
        self.region = region
        self.target_role_arn = target_role_arn
        self.target_acct = target_acct
        self.target_role_name = target_role_name
        self.continuous = continuous
        self._stop = threading.Event()

    def _log(self, s): self.log.emit(s)
    def stop(self): self._stop.set()

    def run(self):
        try:
            self.status.emit("Preparing Vault…")
            ensure_vault_binary(self._log)
            start_vault_server(self._log)
            root = vault_init_unseal_login(self._log)
            os.environ["VAULT_TOKEN"] = root
            vault_ensure_kvv2(self._log)

            ensure_vault_binary(self._log)
            start_vault_server(self._log)
            root = vault_init_unseal_login(self._log)
            os.environ["VAULT_TOKEN"] = root
            vault_ensure_kvv2(self._log)

            export_vault_env(self._log, persist_user_env=True, add_bin_to_path=False)


            while not self._stop.is_set():
                self.status.emit("Signing in (SAML)…")
                try:
                    saml_b64 = capture_saml_response(
                        session_fresh=self.session_fresh,
                        force_same_tab=self.force_same_tab,
                        headless=self.headless,
                        log_fn=self._log
                    )
                except Exception as e:
                    err(self._log, f"SAML Capture Failed: {e}")
                    if self._stop.wait(10): break
                    continue

                try:
                    xml = base64.b64decode(saml_b64).decode("utf-8", "ignore")
                    principal_arn, role_arn = pick_role(
                        parse_roles(xml),
                        self.target_role_arn, self.target_acct, self.target_role_name
                    )
                    info(self._log, f"Using Role: {role_arn}")
                    creds = sts_assume_with_saml(
                        saml_b64, principal_arn, role_arn, self.duration_seconds, self.region
                    )
                except Exception as e:
                    err(self._log, f"STS Failed: {e}")
                    if self._stop.wait(10): break
                    continue

                info(self._log, f"STS OK  AccessKeyId={creds['AccessKeyId'][:4]}********  Expires={creds['Expiration'].isoformat()}")
                try:
                    store_creds_to_vault(creds, self._log)
                except Exception as e:
                    err(self._log, f"Vault Save Failed: {e}")

                exp: datetime = creds["Expiration"]
                self.expiresAt.emit(exp.isoformat())
                self.status.emit("Issued")

                if not self.continuous:
                    break

                # Renew 10min (default) before expire
                while not self._stop.is_set():
                    now = now_utc()
                    secs = int((exp - now).total_seconds()) - max(0, self.renew_leeway)
                    if secs <= 0:
                        info(self._log, "About to be expired, Trying to renew...")
                        break
                    wait_s = min(10, max(1, secs))
                    if self._stop.wait(wait_s):
                        break
        except Exception as e:
            err(self._log, f"Fatal error: {e}\n{traceback.format_exc()}")
        finally:
            stop_vault_server(self._log)
            self.status.emit("Stopped")
            self.finished.emit()

# ---------------- GUI ----------------
class MainWindow(QMainWindow):
    ORG = "YourOrg"
    APP = "VaultEntraSAML_GUI"
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.setWindowIcon(QIcon(APP_ICON_PATH))
        self.setMinimumSize(900, 600)

        self.url_edit = QLineEdit(AAD_APP_SIGNIN_URL); self.url_edit
        self.region_edit = QLineEdit(AWS_DEFAULT_REGION)
        self.dur_spin = QSpinBox(); self.dur_spin.setRange(900, 43200); self.dur_spin.setSingleStep(300); self.dur_spin.setValue(3600)
        self.leeway_spin = QSpinBox(); self.leeway_spin.setRange(60, 7200); self.leeway_spin.setSingleStep(60); self.leeway_spin.setValue(600)

        self.session_fresh_chk = QCheckBox("InPrivate"); self.session_fresh_chk.setChecked(False)
        self.force_tab_chk = QCheckBox("Force same tab"); self.force_tab_chk.setChecked(True)
        self.headless_chk = QCheckBox("Quiet Mode"); self.headless_chk.setChecked(False)

        self.role_arn_edit = QLineEdit()
        self.role_acct_edit = QLineEdit()
        self.role_name_edit = QLineEdit()

        self.status_lbl = QLabel("Idle")
        self.expire_lbl = QLabel("-")

        self.start_btn = QPushButton("Start")
        self.stop_btn = QPushButton("Stop"); self.stop_btn.setEnabled(False)
        self.clear_btn = QPushButton("Clear Log")

        self.log_txt = QTextEdit(); self.log_txt.setReadOnly(True)

        g = QGridLayout()
        r = 0
        g.addWidget(QLabel("Entra App URL"), r, 0); g.addWidget(self.url_edit, r, 1, 1, 3); r+=1
        g.addWidget(QLabel("AWS Region"), r, 0); g.addWidget(self.region_edit, r, 1)
        g.addWidget(QLabel("DurationSeconds"), r, 2); g.addWidget(self.dur_spin, r, 3); r+=1
        g.addWidget(QLabel("Sec before Renew"), r, 0); g.addWidget(self.leeway_spin, r, 1)
        g.addWidget(self.session_fresh_chk, r, 2); g.addWidget(self.headless_chk, r, 3); r+=1
        
        g.addWidget(QLabel("Target RoleArn"), r, 0); g.addWidget(self.role_arn_edit, r, 1, 1, 3); r+=1
        g.addWidget(QLabel("Target AccountId"), r, 0); g.addWidget(self.role_acct_edit, r, 1)
        g.addWidget(QLabel("Target RoleName"), r, 2); g.addWidget(self.role_name_edit, r, 3); r+=1
        g.addWidget(QLabel("Status"), r, 0); g.addWidget(self.status_lbl, r, 1)
        g.addWidget(QLabel("Expires At (UTC)"), r, 2); g.addWidget(self.expire_lbl, r, 3); r+=1

        btn_row = QHBoxLayout()
        btn_row.addWidget(self.start_btn); btn_row.addWidget(self.stop_btn)
        btn_row.addStretch(1)
        btn_row.addWidget(self.clear_btn)

        top_box = QWidget(); top_layout = QVBoxLayout(top_box); top_layout.addLayout(g); top_layout.addLayout(btn_row)

        self.splitter = QSplitter(Qt.Orientation.Vertical)
        self.splitter.addWidget(top_box)
        self.splitter.addWidget(self.log_txt)
        self.splitter.setStretchFactor(0, 0) 
        self.splitter.setStretchFactor(1, 1) 

        w = QWidget(); outer = QVBoxLayout(w); outer.addWidget(self.splitter)
        self.setCentralWidget(w)

        # Signals
        self.start_btn.clicked.connect(self.on_start)
        self.stop_btn.clicked.connect(self.on_stop)
        self.clear_btn.clicked.connect(lambda: self.log_txt.clear())

        self.worker_thread: Optional[QThread] = None
        self.worker_obj: Optional[Worker] = None

        self.settings = QSettings(self.ORG, self.APP)
        self.restore_ui_state()

        QApplication.instance().aboutToQuit.connect(self.shutdown_cleanup)

    def restore_ui_state(self):
        geo = self.settings.value("geometry")
        if isinstance(geo, QByteArray):
            self.restoreGeometry(geo)
        else:
            self.resize(1000, 700)
        spl = self.settings.value("splitter")
        if isinstance(spl, QByteArray):
            self.splitter.restoreState(spl)

    def save_ui_state(self):
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("splitter", self.splitter.saveState())

    def log(self, s: str):
        self.log_txt.append(s)
        self.log_txt.moveCursor(self.log_txt.textCursor().MoveOperation.End)

    def on_start(self):
        if self.worker_thread:
            return
        region = self.region_edit.text().strip() or AWS_DEFAULT_REGION
        dur = int(self.dur_spin.value())
        leeway = int(self.leeway_spin.value())
        session_fresh = self.session_fresh_chk.isChecked()
        force_same = self.force_tab_chk.isChecked()
        headless = self.headless_chk.isChecked()
        role_arn = self.role_arn_edit.text().strip()
        role_acct = self.role_acct_edit.text().strip()
        role_name = self.role_name_edit.text().strip()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_lbl.setText("Starting…")
        self.expire_lbl.setText("-")
        self.log("[INFO] === Start ===")

        self.worker_thread = QThread(self)
        self.worker_obj = Worker(
            duration_seconds=dur, renew_leeway=leeway,
            session_fresh=session_fresh, force_same_tab=force_same,
            headless=headless, region=region,
            target_role_arn=role_arn, target_acct=role_acct, target_role_name=role_name,
            continuous=True
        )
        self.worker_obj.moveToThread(self.worker_thread)
        self.worker_thread.started.connect(self.worker_obj.run)
        self.worker_obj.log.connect(self.log)
        self.worker_obj.status.connect(self.status_lbl.setText)
        self.worker_obj.expiresAt.connect(self.expire_lbl.setText)
        self.worker_obj.finished.connect(self.on_finished)
        self.worker_obj.finished.connect(self.worker_thread.quit)
        self.worker_thread.finished.connect(self.cleanup_thread)
        self.worker_thread.start()

    def on_stop(self):
        if self.worker_obj:
            self.worker_obj.stop()
            self.log("[INFO] Stopping…")

    def on_finished(self):
        self.log("[INFO] Finished.")

    def cleanup_thread(self):
        self.worker_thread = None
        self.worker_obj = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_lbl.setText("Idle")


    def shutdown_cleanup(self):
        if self.worker_obj:
            self.worker_obj.stop()
        time.sleep(0.5)
        stop_vault_server(lambda s: None)

    def closeEvent(self, event):
        self.save_ui_state()
        self.shutdown_cleanup()
        super().closeEvent(event)

def main():
    app = QApplication(sys.argv)
    app.setOrganizationName(MainWindow.ORG)
    app.setApplicationName(MainWindow.APP)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
