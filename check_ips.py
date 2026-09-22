#!/usr/bin/env python3
"""Verifica o IP publico de cada bot deste container e aponta colisoes.

Uso:
    python3 check_ips.py               # checa bot-01..bot-20
    python3 check_ips.py 40            # checa bot-01..bot-40
    python3 check_ips.py --rotate      # alem de listar, pede rotacao dos duplicados
"""
import sys
from pathlib import Path

import ip_rotator

BASE_DIR = Path(__file__).resolve().parent


def mass_check_ips(count=None, timeout=25.0):
    bots = [f"bot-{i:02d}" for i in range(1, (count or ip_rotator.BOT_COUNT) + 1)]
    return ip_rotator.measure_public_ips(bots, timeout=timeout)


def find_duplicates(results):
    return ip_rotator.duplicate_ip_bots(results)


def main():
    args = sys.argv[1:]
    rotate = "--rotate" in args
    args = [a for a in args if not a.startswith("--")]
    count = int(args[0]) if args else ip_rotator.BOT_COUNT

    results = mass_check_ips(count)
    duplicates = find_duplicates(results)

    print(f"{'BOT':<8} {'IP':<18} {'ROTA':<10} OBS")
    print("-" * 60)

    seen = {}
    dup_count = 0
    for bot, res in results.items():
        ip = res.get("public_ip")
        route = (res.get("route") or {}).get("mode", "-")
        obs = ""
        if ip:
            if ip in seen:
                obs = f"DUPLICADO (igual a {seen[ip]})"
                dup_count += 1
            else:
                seen[ip] = bot
        else:
            obs = res.get("error", "sem IP")
        print(f"{bot:<8} {str(ip or '-'):<18} {route:<10} {obs}")

    print("-" * 60)
    print(f"IPs unicos: {len(seen)}/{len(results)} | colisoes: {dup_count}")

    if rotate and duplicates:
        for ip, owners in duplicates.items():
            for bot in owners[1:]:
                applied = ip_rotator.request_rotation(bot, f"duplicate_ip:{ip}")
                print(f"[rotate] {bot} (duplicado com {owners[0]} em {ip}) aplicado={applied}")


if __name__ == "__main__":
    main()
