#!/usr/bin/env python3
"""Cliente Tor compartilhado com isolamento por bot.

Um unico processo Tor por container, expondo um SocksPort com
`IsolateSOCKSAuth`. Cada bot usa o MESMO endpoint SOCKS, mas com
credenciais SOCKS diferentes (usuario = isolation id). O Tor cria um
circuito independente por credencial, de forma que cada bot sai por um
exit node diferente -> IP publico distinto por bot.

Observacao: o Tor nao garante matematicamente que dois circuitos nunca
escolham o mesmo exit. Na pratica os IPs ficam distintos, e o script
`check_ips.py` permite detectar/depurar colisoes. Para garantia total de
unicidade use proxy dedicado por bot via `BOT_PROXY_<NN>`.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import tarfile
import time
import urllib.request
from pathlib import Path

TOR_BUNDLE_VERSION = "15.0.23"
TOR_BUNDLE_NAME = f"tor-expert-bundle-linux-x86_64-{TOR_BUNDLE_VERSION}.tar.gz"
TOR_BUNDLE_SHA256 = "08d49de27f542b8f73e2014e064d8320562b5d20019c03d4725c5a5249d97985"
TOR_BUNDLE_URLS = [
    f"https://dist.torproject.org/torbrowser/{TOR_BUNDLE_VERSION}/{TOR_BUNDLE_NAME}",
    f"https://archive.torproject.org/tor-package-archive/torbrowser/{TOR_BUNDLE_VERSION}/{TOR_BUNDLE_NAME}",
]


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def write_state(state_file: Path, stage, ok=False, detail=None, socks_url=None):
    payload = {
        "stage": stage,
        "ok": bool(ok),
        "detail": detail,
        "socks_url": socks_url,
        "updated_at": time.time(),
    }
    try:
        state_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError:
        pass


def _wait_port(host, port, timeout=25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.25)
    return False


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tor_runtime_env(base_dir: Path, tor_bin: Path) -> dict:
    env = os.environ.copy()
    # O Expert Bundle guarda as libs ao lado do binario (e NAO incluir debug/).
    libdir = str(tor_bin.parent)
    old = env.get("LD_LIBRARY_PATH", "")
    env["LD_LIBRARY_PATH"] = libdir + (":" + old if old else "")
    env["HOME"] = str(base_dir)
    return env


def _safe_extract_tar(archive_path: Path, destination: Path):
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:gz") as tf:
        try:
            tf.extractall(destination, filter="data")
        except TypeError:
            root = destination.resolve()
            for member in tf.getmembers():
                target = (destination / member.name).resolve()
                if target != root and root not in target.parents:
                    raise RuntimeError(f"unsafe_archive_member: {member.name}")
            tf.extractall(destination)


def _find_bundled_tor(root: Path):
    preferred = root / "tor" / "tor"
    candidates = [preferred] if preferred.exists() else []
    candidates += [
        path for path in root.rglob("tor")
        if path.is_file() and path not in candidates
    ]
    for candidate in candidates:
        try:
            candidate.chmod(candidate.stat().st_mode | 0o111)
        except OSError:
            pass
        if os.access(candidate, os.X_OK):
            return candidate
    return None


def _download_bundle(state_file: Path, state_dir: Path) -> bool:
    archive_path = state_dir / TOR_BUNDLE_NAME

    if archive_path.exists():
        current = _sha256_file(archive_path)
        if current == TOR_BUNDLE_SHA256:
            write_state(state_file, "bundle_cached", True, f"sha256={current}")
            return True
        archive_path.unlink(missing_ok=True)

    tmp_path = archive_path.with_suffix(archive_path.suffix + ".part")
    tmp_path.unlink(missing_ok=True)
    errors = []

    for url in TOR_BUNDLE_URLS:
        try:
            write_state(state_file, "bundle_downloading", False, url)
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "BotVertra-Tor/1.0"},
                method="GET",
            )
            total = 0
            with urllib.request.urlopen(request, timeout=90) as response, open(tmp_path, "wb") as out:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > 64 * 1024 * 1024:
                        raise RuntimeError("bundle_too_large")
                    out.write(chunk)

            actual = _sha256_file(tmp_path)
            if actual != TOR_BUNDLE_SHA256:
                raise RuntimeError(
                    f"sha256_mismatch expected={TOR_BUNDLE_SHA256} actual={actual}"
                )
            os.replace(tmp_path, archive_path)
            write_state(state_file, "bundle_verified", True, f"{url} sha256={actual}")
            return True
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{url}: {exc}")
            tmp_path.unlink(missing_ok=True)

    write_state(state_file, "bundle_download_failed", False, " | ".join(errors))
    return False


def ensure_tor_binary(base_dir: Path, state_dir: Path, state_file: Path):
    system_tor = shutil.which("tor")
    if system_tor:
        write_state(state_file, "tor_binary_found", True, system_tor)
        return system_tor

    machine = platform.machine().lower()
    if machine not in ("x86_64", "amd64"):
        write_state(state_file, "unsupported_arch", False, f"arquitetura={machine}")
        return None

    vendor_dir = base_dir / ".local" / "tor-expert"
    bundled = _find_bundled_tor(vendor_dir)
    if bundled:
        write_state(state_file, "bundled_tor_found", True, str(bundled))
        return str(bundled)

    if not _download_bundle(state_file, state_dir):
        return None

    try:
        if vendor_dir.exists():
            shutil.rmtree(vendor_dir)
        _safe_extract_tar(state_dir / TOR_BUNDLE_NAME, vendor_dir)
    except Exception as exc:  # noqa: BLE001
        write_state(state_file, "bundle_extract_failed", False, str(exc))
        return None

    bundled = _find_bundled_tor(vendor_dir)
    if not bundled:
        write_state(state_file, "bundle_tor_missing", False, "executavel tor nao localizado")
        return None

    try:
        version_result = subprocess.run(
            [str(bundled), "--version"],
            cwd=str(bundled.parent),
            env=_tor_runtime_env(base_dir, bundled),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
            check=False,
        )
        detail = version_result.stdout.strip().replace("\n", " ")[:500]
        if version_result.returncode != 0:
            write_state(state_file, "bundled_tor_exec_failed", False, f"rc={version_result.returncode} {detail}")
            return None
        write_state(state_file, "bundled_tor_ready", True, detail or str(bundled))
        return str(bundled)
    except Exception as exc:  # noqa: BLE001
        write_state(state_file, "bundled_tor_exec_exception", False, str(exc))
        return None


# --------------------------------------------------------------------------- #
# API publica
# --------------------------------------------------------------------------- #
def start_shared_tor(base_dir: Path, state_dir: Path, log_dir: Path,
                     socks_port: int, container_name: str = "container"):
    """Inicia (ou reaproveita) o Tor compartilhado.

    Retorna {"socks_url": str, "process": Popen|None}. `socks_url` vazio
    significa que nao ha SOCKS disponivel.
    """
    state_file = state_dir / "tor-state.json"

    configured = (os.getenv("TOR_SOCKS_URL") or os.getenv("TOR_TEST_SOCKS_URL") or "").strip()
    if configured:
        socks_url = configured if "://" in configured else f"socks5h://{configured}"
        write_state(state_file, "external_socks_configured", True, "endpoint externo", socks_url)
        print(f"[tor] {container_name} usando SOCKS configurado externamente", flush=True)
        return {"socks_url": socks_url, "process": None}

    if os.getenv("TOR_DISABLE", "").strip().lower() in ("1", "true", "yes", "on"):
        write_state(state_file, "disabled", False, "TOR_DISABLE definido")
        print(f"[tor] {container_name} Tor desativado por TOR_DISABLE", flush=True)
        return {"socks_url": "", "process": None}

    tor_bin = ensure_tor_binary(base_dir, state_dir, state_file)
    if not tor_bin:
        print(f"[tor] {container_name} binario Tor indisponivel", flush=True)
        return {"socks_url": "", "process": None}

    tor_data = base_dir / "tor-data"
    tor_data.mkdir(exist_ok=True)
    tor_log = open(log_dir / "tor.log", "ab", buffering=0)
    tor_bin_path = Path(tor_bin)
    vendor_dir = base_dir / ".local" / "tor-expert"
    tor_env = (
        _tor_runtime_env(base_dir, tor_bin_path)
        if str(tor_bin_path).startswith(str(vendor_dir))
        else os.environ.copy()
    )

    tor_process = subprocess.Popen(
        [
            tor_bin,
            "--ClientOnly", "1",
            "--SocksPort", f"127.0.0.1:{socks_port} IsolateSOCKSAuth",
            "--DataDirectory", str(tor_data),
            "--Log", "notice stdout",
        ],
        cwd=str(tor_bin_path.parent),
        env=tor_env,
        stdout=tor_log,
        stderr=subprocess.STDOUT,
    )

    if _wait_port("127.0.0.1", socks_port):
        socks_url = f"socks5h://127.0.0.1:{socks_port}"
        write_state(state_file, "tor_ready", True, "SOCKS local ativo (IsolateSOCKSAuth)", socks_url)
        print(f"[tor] {container_name} SOCKS local ativo em 127.0.0.1:{socks_port}", flush=True)
        return {"socks_url": socks_url, "process": tor_process}

    write_state(state_file, "tor_socks_unavailable", False, "binario iniciou mas SOCKS nao abriu")
    print(f"[tor] {container_name} binario iniciou mas SOCKS nao abriu", flush=True)
    return {"socks_url": "", "process": tor_process}
