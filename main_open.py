# main_gui.py
# -*- coding: utf-8 -*-
"""
dependency:
  pip install pyqt6 selenium-wire selenium boto3 hvac
"""

# CHANGE: Added automatic Edge driver update

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
              r"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
              r"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"]:
        if p and Path(p).exists():
            _, out, _ = _run([p, "--version"])
            m = re.search(r"(\\d+)\\.\\d+\\.\\d+\\.\\d+", out)
            if m: return int(m.group(1))
    try:
        import winreg
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                key = winreg.OpenKey(hive, r"Software\\Microsoft\\Edge\\BLBeacon")
                ver, _ = winreg.QueryValueEx(key, "version")
                m = re.search(r"^(\\d+)\\.", ver)
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
            m = re.search(r"\\b(\\d+)\\.\\d+\\.\\d+\\.\\d+\\b", out)
            if m: return int(m.group(1))
    except Exception:
        pass
    return None

def _get_driver_full_version(exe: str) -> Optional[str]:
    try:
        rc, out, _ = _run([exe, "--version"])
        if rc == 0:
            m = re.search(r"\\b(\\d+\\.\\d+\\.\\d+\\.\\d+)\\b", out)
            if m: return m.group(1)
    except Exception:
        pass
    return None

...
