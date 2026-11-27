#!/usr/bin/env python3
"""Generate Xray configs for a fixed RU relay and a direct NL downlink."""

import argparse
from copy import deepcopy
from ipaddress import IPv4Address
import json
import sys
from urllib.parse import parse_qsl, urlsplit
from uuid import UUID


def port_number(value):
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError("Порт должен быть от 1 до 65535")
    return port


def relay_config(nl_address, nl_port, listen_port):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "ru-uplink",
            "listen": "0.0.0.0",
            "port": listen_port,
            "protocol": "tunnel",
            "settings": {
                "allowedNetwork": "tcp",
                "rewriteAddress": str(nl_address),
                "rewritePort": nl_port,
                "followRedirect": False,
            },
        }],
        "outbounds": [{"tag": "nl", "protocol": "freedom"}],
    }


def split_profile(direct_link, ru_address, ru_port):
    link = urlsplit(direct_link)
    query = dict(parse_qsl(link.query, keep_blank_values=True))
    if (link.scheme != "vless" or query.get("type") not in ("xhttp", "splithttp")
            or query.get("security") != "reality"):
        raise ValueError("Нужна прямая ссылка VLESS + XHTTP + REALITY с NL")
    nl_address = IPv4Address(link.hostname)
    if nl_address == ru_address:
        raise ValueError("У RU и NL должны быть разные IPv4")
    if not query.get("sni") or not query.get("pbk") or not query.get("path", "").startswith("/"):
        raise ValueError("В прямой ссылке должны быть SNI, публичный ключ и путь XHTTP")

    reality = {
        "serverName": query["sni"],
        "fingerprint": query.get("fp", "chrome"),
        "publicKey": query["pbk"],
        "shortId": query.get("sid", ""),
    }
    if "spx" in query:
        reality["spiderX"] = query["spx"]
    xhttp = {"path": query["path"], "mode": "stream-up"}
    if "host" in query:
        xhttp["host"] = query["host"]
    extra = json.loads(query.get("extra", "{}"))
    if not isinstance(extra, dict) or "downloadSettings" in extra:
        raise ValueError("Подай ссылку на прямой NL-профиль")
    if extra:
        xhttp["extra"] = extra
    stream = {
        "network": "xhttp",
        "security": "reality",
        "realitySettings": reality,
        "xhttpSettings": xhttp,
    }
    downlink = deepcopy(stream)
    downlink.update(address=str(nl_address), port=link.port or 443)
    xhttp.setdefault("extra", {})["downloadSettings"] = downlink
    return {
        "remarks": "LastVN | Split",
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks",
            "listen": "127.0.0.1",
            "port": 10808,
            "protocol": "socks",
            "settings": {"udp": True},
        }],
        "outbounds": [{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": str(ru_address),
                "port": ru_port,
                "users": [{"id": str(UUID(link.username)), "encryption": query.get("encryption", "none")}],
            }]},
            "streamSettings": stream,
        }],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    relay = commands.add_parser("relay", help="Конфигурация Xray для RU")
    relay.add_argument("nl_ipv4", type=IPv4Address)
    relay.add_argument("--listen-port", type=port_number, default=443)
    relay.add_argument("--nl-port", type=port_number, default=443)
    profile = commands.add_parser("profile", help="Клиентский JSON из прямой NL-ссылки на stdin")
    profile.add_argument("ru_ipv4", type=IPv4Address)
    profile.add_argument("--ru-port", type=port_number, default=443)
    args = parser.parse_args()
    if args.command == "relay":
        config = relay_config(args.nl_ipv4, args.nl_port, args.listen_port)
    else:
        link = next((line.strip() for line in sys.stdin if line.strip().startswith("vless://")), None)
        if link is None:
            parser.error("Передай прямую VLESS-ссылку через stdin")
        try:
            config = split_profile(link, args.ru_ipv4, args.ru_port)
        except (ValueError, TypeError):
            parser.error("Проверь IPv4 и параметры прямой VLESS + XHTTP + REALITY ссылки")
    json.dump(config, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
