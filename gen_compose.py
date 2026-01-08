#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate docker-compose.yml for Tor nodes based on a fixed pattern.

IP rule (updated):
- guards:  198.(64 + (i-1)).0.2
- exits:   198.(80 + (i-1)).0.2
- middles: 198.(90 + (i-1)).0.2
"""

from __future__ import annotations

import argparse
from typing import Dict, List, Tuple


def indent(lines: List[str], spaces: int) -> List[str]:
    pad = " " * spaces
    return [pad + line if line else line for line in lines]


def yaml_kv(key: str, value: str, spaces: int = 0) -> str:
    pad = " " * spaces
    return f"{pad}{key}: {value}"


def yaml_list_inline(items: List[str]) -> str:
    escaped = [f"\"{x}\"" for x in items]
    return "[ " + ", ".join(escaped) + " ]"


def node_ip(third_octet_base: int, index_1based: int, host_last_octet: int = 2) -> str:
    # Example: base=64, i=1 => 198.64.0.2; i=2 => 198.65.0.2
    third = third_octet_base + (index_1based - 1)
    return f"198.{third}.0.{host_last_octet}"


def build_common_service_block(
    service_name: str,
    container_name: str,
    ports: List[str],
    env: Dict[str, str],
    volume_name: str,
    ipv4: str,
) -> List[str]:
    lines: List[str] = []

    lines.append(f"{service_name}:")
    lines += indent([yaml_kv("build", "{ context: ./relay, dockerfile: Dockerfile }")], 2)
    lines += indent([yaml_kv("container_name", container_name)], 2)
    lines += indent([yaml_kv("ports", yaml_list_inline(ports))], 2)

    lines += indent(["environment:"], 2)
    for k, v in env.items():
        lines += indent([yaml_kv(k, v)], 4)

    lines += indent([yaml_kv("volumes", yaml_list_inline([f"{volume_name}:/var/lib/tor"]))], 2)
    lines += indent([yaml_kv("restart", "unless-stopped")], 2)
    lines += indent([yaml_kv("extra_hosts", yaml_list_inline(["tordir:192.168.66.241"]))], 2)

    lines += indent(["networks:"], 2)
    lines += indent(["tor_net:"], 4)
    lines += indent([yaml_kv("ipv4_address", ipv4)], 6)

    return lines


def gen_guard(i: int, authority_ip: str, fp: str, v3ident: str) -> Tuple[List[str], str]:
    service_name = f"tor-guard{i}"
    container_name = service_name

    ports = [f"901{i}:9001", f"910{i}:9051"]
    env = {
        "TOR_NICKNAME": f"guard{i}",
        "TOR_CONTACT": f"guard{i}@local.net",
        "TOR_AUTHORITY_IP": authority_ip,
        "TOR_AUTHORITY_FINGERPRINT": fp,
        "TOR_AUTHORITY_V3IDENT": v3ident,
        "NODE_TYPE": "relay",
    }

    volume_name = f"tor-guard{i}-data"
    ipv4 = node_ip(64, i, 2)  # UPDATED
    block = build_common_service_block(service_name, container_name, ports, env, volume_name, ipv4)
    return block, volume_name


def gen_exit(i: int, authority_ip: str, fp: str, v3ident: str) -> Tuple[List[str], str]:
    service_name = f"tor-exit{i}"
    container_name = service_name

    ports = [f"902{i}:9001", f"912{i}:9051"]
    env = {
        "TOR_NICKNAME": f"Exit{i}",
        "TOR_CONTACT": f"Exit{i}@local.net",
        "TOR_AUTHORITY_IP": authority_ip,
        "TOR_AUTHORITY_FINGERPRINT": fp,
        "TOR_AUTHORITY_V3IDENT": v3ident,
        "NODE_TYPE": "exit",
    }

    volume_name = f"tor-exit{i}-data"
    ipv4 = node_ip(80, i, 2)  # UPDATED
    block = build_common_service_block(service_name, container_name, ports, env, volume_name, ipv4)
    return block, volume_name


def gen_middle(i: int, authority_ip: str, fp: str, v3ident: str) -> Tuple[List[str], str]:
    service_name = f"tor-middle{i}"
    container_name = service_name

    ports = [f"903{i}:9001", f"913{i}:9051"]
    env = {
        "TOR_NICKNAME": f"middle{i}",
        "TOR_CONTACT": f"middle{i}@local.net",
        "TOR_AUTHORITY_IP": authority_ip,
        "TOR_AUTHORITY_FINGERPRINT": fp,
        "TOR_AUTHORITY_V3IDENT": v3ident,
        "NODE_TYPE": "relay",
        "DIR_PORT": "9030",
        "BANDWIDTH_RATE": "1 MB",
        "BANDWIDTH_BURST": "1 MB",
    }

    volume_name = f"tor-middle{i}-data"
    ipv4 = node_ip(90, i, 2)  # UPDATED
    block = build_common_service_block(service_name, container_name, ports, env, volume_name, ipv4)
    return block, volume_name


def generate_compose(
    guards: int,
    exits: int,
    middles: int,
    authority_ip: str,
    fp: str,
    v3ident: str,
) -> str:
    lines: List[str] = []

    lines.append("version: '3.8'")
    lines.append("")
    lines.append("networks:")
    lines += indent(["tor_net:"], 2)
    lines += indent(["driver: bridge"], 4)
    lines += indent(["ipam:"], 4)
    lines += indent(["config:"], 6)
    lines += indent(["- subnet: 198.64.0.0/10"], 8)
    lines.append("")
    lines.append("##############################################################################")
    lines.append("# 服务")
    lines.append("##############################################################################")
    lines.append("")
    lines.append("services:")
    lines.append("")

    volume_names: List[str] = []

    for i in range(1, guards + 1):
        block, vname = gen_guard(i, authority_ip, fp, v3ident)
        lines += indent(block, 2)
        lines.append("")
        volume_names.append(vname)

    for i in range(1, exits + 1):
        block, vname = gen_exit(i, authority_ip, fp, v3ident)
        lines += indent(block, 2)
        lines.append("")
        volume_names.append(vname)

    for i in range(1, middles + 1):
        block, vname = gen_middle(i, authority_ip, fp, v3ident)
        lines += indent(block, 2)
        lines.append("")
        volume_names.append(vname)

    lines.append("##############################################################################")
    lines.append("# 数据卷")
    lines.append("##############################################################################")
    lines.append("")
    lines.append("volumes:")
    for v in volume_names:
        lines += indent([f"{v}:"], 2)

    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--guards", type=int, default=4)
    parser.add_argument("--exits", type=int, default=4)
    parser.add_argument("--middles", type=int, default=4)
    parser.add_argument("--authority-ip", default="192.168.66.241")
    parser.add_argument("--fingerprint", default="4CF9BD2D85C9D484BBB817E2F927B502C8EEFCA6")
    parser.add_argument("--v3ident", default="4CF9BD2D85C9D484BBB817E2F927B502C8EEFCA6")
    parser.add_argument("-o", "--output", default="docker-compose.yml")
    args = parser.parse_args()

    yml = generate_compose(
        guards=args.guards,
        exits=args.exits,
        middles=args.middles,
        authority_ip=args.authority_ip,
        fp=args.fingerprint,
        v3ident=args.v3ident,
    )

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(yml)

    print(f"Wrote: {args.output}")


if __name__ == "__main__":
    main()
