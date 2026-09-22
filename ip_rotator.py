#!/usr/bin/env python3
"""Rotacao de IP por bot + auditoria de duplicados/timeouts.

Objetivo: quando um bot entra em `local_timeout` / `bot_timeout` ou fica com
um IP publico igual ao de outro bot, ele deve ser reconectado por uma rota
diferente para tentar obter um IP novo.

Como a rota muda por bot:
  * Tor  -> incrementa a geracao e usa um novo TOR_ISOLATION_ID
            (novo circuito => novo exit node => novo IP publico)
  * proxy-> avanca no pool BOT_PROXY_<NN>[_ALTk]
  * direto -> nao ha alternativa (IP da VPS)

Quem reinicia o bot e o supervisor do start.py: este modulo apenas registra
a intencao (`state/rotate/<bot>.json`) e a geracao da rota (`state/routes.json`).
"""
from __future__ import annotations

import contextlib
import json
import os
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
STATE_DIR = BASE_DIR / "state"
CMD_DIR = BASE_DIR / "commands"
LOG_DIR = BASE_DIR / "logs"
ROTATE_DIR = STATE_DIR / "rotate"
ROUTES_FILE = STATE_DIR / "routes.json"

# --- configuracao (override por variavel de ambiente) ---------------------- #
CONTAINER_NAME = os.getenv("CONTAINER_NAME", "container5").strip()
BOT_COUNT = int(os.getenv("BOT_COUNT", "20"))
ROTATE_ON_TIMEOUT = os.getenv("ROTATE_ON_TIMEOUT", "1").strip().lower() not in ("0", "false", "no", "off")
ROTATION_COOLDOWN = float(os.getenv("ROTATION_COOLDOWN", "45"))
MAX_ROUTE_GENERATION = int(os.getenv("MAX_ROUTE_GENERATION", "100"))
DEFAULT_IP_AUDIT_INTERVAL = int(os.getenv("IP_AUDIT_INTERVAL", "90"))

_TIMEOUT_ERRORS = {"local_timeout", "bot_timeout", "lock_timeout"}


def all_bots():
    return [f"bot-{i:02d}" for i in range(1, BOT_COUNT + 1)]


def bot_index(bot: str) -> int:
    try:
        return int(str(bot).split("-", 1)[1])
    except (ValueError, IndexError):
        return 0


def _tor_socks_url() -> str:
    return (os.getenv("TOR_SOCKS_URL") or os.getenv("TOR_TEST_SOCKS_URL") or "").strip()


# --------------------------------------------------------------------------- #
# locks entre processos
# --------------------------------------------------------------------------- #
def _lock_path(name: str) -> Path:
    return CMD_DIR / f".{name}.lock"


@contextlib.contextmanager
def _file_lock(path: Path, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    fd = None
    while True:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError:
            try:
                if time.time() - path.stat().st_mtime > 30:
                    path.unlink(missing_ok=True)
                    continue
            except OSError:
                pass
            if time.monotonic() > deadline:
                raise TimeoutError(f"lock_timeout:{path.name}")
            time.sleep(0.05)
    try:
        yield
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        path.unlink(missing_ok=True)


def acquire_bot_lock(bot: str, timeout: float = 10.0) -> bool:
    """Lock de acesso ao canal de comandos de um bot (cross-process)."""
    path = _lock_path(bot)
    deadline = time.monotonic() + timeout
    while True:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                if time.time() - path.stat().st_mtime > 30:
                    path.unlink(missing_ok=True)
                    continue
            except OSError:
                pass
            if time.monotonic() > deadline:
                return False
            time.sleep(0.05)
        else:
            os.close(fd)
            return True


def release_bot_lock(bot: str) -> None:
    _lock_path(bot).unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# rotas
# --------------------------------------------------------------------------- #
def proxy_pool(index: int):
    keys = [f"BOT_PROXY_{index:02d}"] + [f"BOT_PROXY_{index:02d}_ALT{k}" for k in range(1, 10)]
    return [os.getenv(k, "").strip() for k in keys if os.getenv(k, "").strip()]


def resolve_route(bot: str, gen: int):
    """Define a rota (e o env) do bot para uma dada geracao."""
    index = bot_index(bot)
    pool = proxy_pool(index)

    if pool:
        proxy = pool[gen % len(pool)]
        env = {
            "BOT_PROXY": proxy,
            "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy,
            "http_proxy": proxy, "https_proxy": proxy,
        }
        return {"mode": "proxy", "target": proxy.rsplit("@", 1)[-1], "env": env}

    tor_url = _tor_socks_url()
    if tor_url:
        isolation = f"{CONTAINER_NAME}-{bot}-g{gen}"
        return {
            "mode": "tor",
            "target": isolation,
            "env": {"TOR_SOCKS_URL": tor_url, "TOR_ISOLATION_ID": isolation},
        }

    return {"mode": "direct", "target": "vps", "env": {}}


def _read_routes():
    if not ROUTES_FILE.exists():
        return {}
    try:
        return json.loads(ROUTES_FILE.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def _write_routes(routes):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = ROUTES_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(routes, indent=2), encoding="utf-8")
    os.replace(tmp, ROUTES_FILE)


def _update_routes(mutate):
    with _file_lock(_lock_path("routes")):
        routes = _read_routes()
        result = mutate(routes)
        _write_routes(routes)
        return result


def generation(bot: str) -> int:
    return int(_read_routes().get(bot, {}).get("gen", 0))


def bump_generation(bot: str, reason: str) -> int:
    """Incrementa a geracao da rota do bot (aplicada no proximo relaunch)."""

    def mutate(routes):
        rec = routes.get(bot, {"gen": 0, "rotations": 0})
        gen = int(rec.get("gen", 0)) + 1
        rec["gen"] = gen
        rec["rotations"] = int(rec.get("rotations", 0)) + 1
        rec["last_rotated_at"] = time.time()
        rec["last_reason"] = reason
        routes[bot] = rec
        return gen

    return _update_routes(mutate)


def request_rotation(bot: str, reason: str) -> bool:
    """Solicita que o supervisor reconecte o bot por uma rota diferente."""
    if bot_index(bot) < 1 or bot_index(bot) > BOT_COUNT:
        return False

    def mutate(routes):
        rec = routes.get(bot, {"gen": 0, "rotations": 0, "last_rotated_at": 0})
        now = time.time()
        if now - float(rec.get("last_rotated_at", 0)) < ROTATION_COOLDOWN:
            return False
        if int(rec.get("rotations", 0)) >= MAX_ROUTE_GENERATION:
            return False
        rec["last_rotated_at"] = now
        rec["last_reason"] = reason
        routes[bot] = rec
        return True

    if not _update_routes(mutate):
        return False

    ROTATE_DIR.mkdir(parents=True, exist_ok=True)
    (ROTATE_DIR / f"{bot}.json").write_text(
        json.dumps({"reason": reason, "ts": time.time()}), encoding="utf-8"
    )
    print(f"[ip-rotate] {bot} pediu nova rota ({reason})", flush=True)
    return True


def consume_rotation(bot: str):
    path = ROTATE_DIR / f"{bot}.json"
    if not path.exists():
        return None
    try:
        reason = json.loads(path.read_text(encoding="utf-8")).get("reason", "rotation")
    except Exception:  # noqa: BLE001
        reason = "rotation"
    path.unlink(missing_ok=True)
    return reason


# --------------------------------------------------------------------------- #
# canal de comandos local (sincrono, com lock)
# --------------------------------------------------------------------------- #
def run_local_sync(bot: str, command: str, args=None, timeout: float = 12.0):
    inbox = CMD_DIR / f"{bot}.json"
    outbox = CMD_DIR / f"{bot}.out.json"

    if not (STATE_DIR / f"{bot}.json").exists():
        return {"ok": False, "bot": bot, "error": "bot_offline"}

    if not acquire_bot_lock(bot, timeout=timeout):
        return {"ok": False, "bot": bot, "error": "lock_timeout"}

    try:
        outbox.unlink(missing_ok=True)
        inbox.write_text(
            json.dumps({"command": command, "args": args or []}, indent=2),
            encoding="utf-8",
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if outbox.exists():
                try:
                    return json.loads(outbox.read_text(encoding="utf-8"))
                except Exception as exc:  # noqa: BLE001
                    return {"ok": False, "bot": bot, "error": f"invalid_local_response: {exc}"}
            time.sleep(0.1)
        return {"ok": False, "bot": bot, "error": "local_timeout"}
    finally:
        release_bot_lock(bot)


def measure_public_ips(bots=None, timeout: float = 12.0):
    return {bot: run_local_sync(bot, "public_ip", [], timeout) for bot in (bots or all_bots())}


def duplicate_ip_bots(ip_results):
    """Retorna {ip: [bots...]} apenas para IPs compartilhados por >1 bot."""
    ipmap = {}
    for bot, res in ip_results.items():
        ip = (res or {}).get("public_ip") if (res or {}).get("ok") else None
        if ip:
            ipmap.setdefault(ip, []).append(bot)
    return {ip: owners for ip, owners in ipmap.items() if len(owners) > 1}


def audit_once(rotate: bool = True):
    """Mede IPs, detecta duplicados/timeouts e (opcionalmente) pede rotacao."""
    results = measure_public_ips()
    duplicates = duplicate_ip_bots(results)

    rotate_targets = {}
    for ip, owners in duplicates.items():
        # mantem o primeiro bot do grupo; rotaciona os demais
        for bot in owners[1:]:
            rotate_targets[bot] = f"duplicate_ip:{ip}"

    for bot, res in results.items():
        err = (res or {}).get("error")
        if err in _TIMEOUT_ERRORS and ROTATE_ON_TIMEOUT:
            rotate_targets.setdefault(bot, err)

    applied = []
    if rotate:
        for bot, reason in rotate_targets.items():
            if request_rotation(bot, reason):
                applied.append((bot, reason))

    unique_ips = len({r.get("public_ip") for r in results.values() if (r or {}).get("ok") and r.get("public_ip")})
    summary = {
        "checked": len(results),
        "unique_ips": unique_ips,
        "duplicates": {ip: owners for ip, owners in duplicates.items()},
        "timeouts": [b for b, r in results.items() if (r or {}).get("error") in _TIMEOUT_ERRORS],
        "rotations_requested": applied,
    }
    return summary


def audit_loop(interval: int = DEFAULT_IP_AUDIT_INTERVAL):
    print(f"[ip-audit] {CONTAINER_NAME} ativo (intervalo={interval}s)", flush=True)
    while True:
        try:
            summary = audit_once(rotate=True)
            if summary["duplicates"] or summary["timeouts"] or summary["rotations_requested"]:
                print(
                    f"[ip-audit] checked={summary['checked']} unicos={summary['unique_ips']} "
                    f"duplicados={summary['duplicates']} timeouts={summary['timeouts']} "
                    f"rotacoes={summary['rotations_requested']}",
                    flush=True,
                )
        except Exception as exc:  # noqa: BLE001
            print(f"[ip-audit] erro: {exc}", flush=True)
        time.sleep(max(10, interval))


def _cli():
    import argparse

    parser = argparse.ArgumentParser(description="Rotacao/auditoria de IP por bot")
    parser.add_argument("--audit", action="store_true", help="roda o loop de auditoria")
    parser.add_argument("--once", action="store_true", help="roda uma auditoria unica")
    parser.add_argument("--rotate", action="store_true", help="aplica rotacao (com --once)")
    parser.add_argument("--interval", type=int, default=DEFAULT_IP_AUDIT_INTERVAL)
    args = parser.parse_args()

    if args.audit:
        audit_loop(args.interval)
    else:
        summary = audit_once(rotate=args.rotate)
        print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    _cli()
