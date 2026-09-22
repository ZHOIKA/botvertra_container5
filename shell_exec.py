#!/usr/bin/env python3
"""Execucao de comandos shell arbitrarios nos bots.

Usado pelos workers (shared_worker.py / bot.py) para atender ao comando
exec / shell liberado pelo controller.

Recursos:
  * linha de comando livre (qualquer binario disponivel no container:
    ls, curl, wget, python3, git, tar, ...)
  * timeout configuravel por comando (teto BOT_EXEC_MAX_TIMEOUT)
  * stdout e stderr separados + codigo de saida
  * limite de tamanho da saida (evita estourar o WebSocket do controller)
  * herda a rota de IP do bot: em modo proxy/Tor as variaveis de proxy
    (http_proxy / https_proxy / all_proxy) sao injetadas no processo filho,
    entao curl, wget, pip etc. saem pelo IP daquele bot.

Configuracao por ambiente (opcional):
  BOT_EXEC_TIMEOUT        timeout padrao em segundos             (default 30)
  BOT_EXEC_MAX_TIMEOUT    teto do timeout aceito pelo cliente    (default 300)
  BOT_EXEC_MAX_OUTPUT     caracteres maximos por stream          (default 200000)
  BOT_EXEC_SHELL          shell usada                            (default /bin/bash)
  BOT_EXEC_CWD            diretorio de trabalho                  (default: pasta do projeto)

Uso como CLI (debug):
    python3 shell_exec.py "ls -la"
    python3 shell_exec.py --timeout 60 "curl -s https://api.ipify.org"
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

DEFAULT_TIMEOUT = float(os.getenv("BOT_EXEC_TIMEOUT", "30"))
MAX_TIMEOUT = float(os.getenv("BOT_EXEC_MAX_TIMEOUT", "300"))
MAX_OUTPUT = int(os.getenv("BOT_EXEC_MAX_OUTPUT", "200000"))
DEFAULT_SHELL = os.getenv("BOT_EXEC_SHELL", "/bin/bash").strip() or "/bin/bash"
DEFAULT_CWD = os.getenv("BOT_EXEC_CWD", "").strip() or str(BASE_DIR)

PROXY_KEYS = (
    "HTTP_PROXY", "http_proxy",
    "HTTPS_PROXY", "https_proxy",
    "ALL_PROXY", "all_proxy",
    "FTP_PROXY", "ftp_proxy",
)

EXEC_COMMANDS = {"exec", "shell", "sh"}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _shrink(text, limit=MAX_OUTPUT):
    """Limita o tamanho de um stream sem perder o inicio e o fim da saida."""
    if text is None:
        return ""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    text = str(text)
    if len(text) <= limit:
        return text
    head = limit // 2
    tail = limit - head
    omitted = len(text) - limit
    return text[:head] + "\n... [" + str(omitted) + " caracteres truncados] ...\n" + text[-tail:]


def _isolated_tor_url(tor_url, isolation):
    base = tor_url if "://" in tor_url else "socks5h://" + tor_url
    scheme, rest = base.split("://", 1)
    if "@" in rest:
        rest = rest.split("@", 1)[1]
    return scheme + "://" + (isolation or "shared") + ":x@" + rest


def build_command_line(args, raw=None):
    """Reconstroi a linha de comando.

    - raw (command_line) tem prioridade: e usado literalmente.
    - um unico argumento e tratado como a linha completa (preserva aspas).
    - varios argumentos sao remontados com shlex.quote (seguro).
    """
    if raw:
        return str(raw)
    if not args:
        return ""
    args = list(args)
    if len(args) == 1:
        return str(args[0])
    return " ".join(shlex.quote(str(item)) for item in args)


def describe_proxy(route_env):
    route_env = route_env or {}
    tor = str(route_env.get("TOR_SOCKS_URL") or "").strip()
    proxy = str(route_env.get("BOT_PROXY") or "").strip()
    if tor:
        return {"mode": "tor", "endpoint": tor, "isolation": route_env.get("TOR_ISOLATION_ID")}
    if proxy:
        return {"mode": "proxy", "endpoint": proxy.rsplit("@", 1)[-1]}
    return {"mode": "direct"}


def build_env(bot, route_env=None, extra=None):
    """Monta o ambiente do processo filho, aplicando a rota de IP do bot."""
    env = dict(os.environ)
    route_env = route_env or {}
    tor = str(route_env.get("TOR_SOCKS_URL") or "").strip()
    proxy = str(route_env.get("BOT_PROXY") or "").strip()
    isolation = str(route_env.get("TOR_ISOLATION_ID") or "").strip()

    # Limpa proxies herdados para que a rota do bot seja a unica fonte.
    for key in PROXY_KEYS:
        env.pop(key, None)

    if tor:
        url = _isolated_tor_url(tor, isolation)
        for key in PROXY_KEYS:
            env[key] = url
    elif proxy:
        for key in PROXY_KEYS:
            env[key] = proxy

    if tor or proxy:
        no_proxy = env.get("NO_PROXY") or "localhost,127.0.0.1,::1"
        env["NO_PROXY"] = no_proxy
        env["no_proxy"] = no_proxy

    env["BOT_ID"] = bot
    env.setdefault("TERM", "dumb")
    if isinstance(extra, dict):
        env.update({str(k): str(v) for k, v in extra.items() if v is not None})
    return env


# --------------------------------------------------------------------------- #
# execucao
# --------------------------------------------------------------------------- #
def run_shell(bot, payload, route_env=None):
    """Executa um comando shell arbitrario e devolve o resultado serializavel."""
    payload = payload or {}
    route_env = route_env or payload.get("route_env") or {}

    cmdline = build_command_line(
        payload.get("args"),
        payload.get("command_line"),
    ).strip()

    if not cmdline:
        return {"ok": False, "bot": bot, "error": "empty_command"}

    try:
        timeout = float(payload.get("timeout") or DEFAULT_TIMEOUT)
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    timeout = max(1.0, min(timeout, MAX_TIMEOUT))

    cwd = str(payload.get("cwd") or DEFAULT_CWD)
    if not os.path.isdir(cwd):
        cwd = DEFAULT_CWD

    shell = str(payload.get("shell") or DEFAULT_SHELL)
    if not os.path.exists(shell):
        shell = "/bin/sh"

    env = build_env(bot, route_env)

    stdin_data = payload.get("stdin")
    if stdin_data is not None:
        stdin_data = str(stdin_data)

    started = time.perf_counter()
    timed_out = False
    stdout = ""
    stderr = ""
    returncode = None

    try:
        proc = subprocess.run(
            [shell, "-c", cmdline],
            cwd=cwd,
            env=env,
            input=stdin_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
            errors="replace",
        )
        returncode = proc.returncode
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
    except Exception as exc:
        return {
            "ok": False,
            "bot": bot,
            "command": cmdline,
            "error": str(exc),
            "duration_ms": round((time.perf_counter() - started) * 1000, 1),
        }

    duration_ms = round((time.perf_counter() - started) * 1000, 1)
    stdout = _shrink(stdout)
    stderr = _shrink(stderr)

    return {
        "ok": not timed_out,
        "bot": bot,
        "command": cmdline,
        "shell": shell,
        "cwd": cwd,
        "returncode": returncode,
        "success": (returncode == 0),
        "timed_out": timed_out,
        "timeout_seconds": timeout,
        "duration_ms": duration_ms,
        "stdout": stdout,
        "stderr": stderr,
        "route": describe_proxy(route_env),
    }


# --------------------------------------------------------------------------- #
# CLI de debug
# --------------------------------------------------------------------------- #
def _cli():
    argv = sys.argv[1:]
    timeout = None
    cwd = None

    while argv and argv[0].startswith("--"):
        flag = argv.pop(0)
        if flag == "--timeout" and argv:
            timeout = float(argv.pop(0))
        elif flag == "--cwd" and argv:
            cwd = argv.pop(0)
        elif flag in ("-h", "--help"):
            print(__doc__)
            return
        else:
            break

    payload = {"args": argv, "timeout": timeout, "cwd": cwd}
    print(json.dumps(run_shell("local", payload), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    _cli()
