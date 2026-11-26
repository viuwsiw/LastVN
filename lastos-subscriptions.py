#!/usr/bin/env python3
"""LastVN HTTPS subscription endpoint and account card."""

import base64
import binascii
from copy import deepcopy
import fcntl
import grp
from html import escape
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import re
import secrets
import socketserver
import sqlite3
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qs, quote, urlencode, urlsplit

NAME = "LastVN: первый, нидерландский 🇳🇱"
TOKENS = Path("/usr/local/etc/xray/lastvn.tokens")
PROFILES = Path("/var/www/lastvn/sub")
POLICY = Path("/etc/lastos-limits.json")
LIVE = Path("/etc/lastos-limits-live")
USAGE = Path("/var/lib/lastos-limits/usage.db")
TRANSPORTS = Path("/etc/lastos-transports.json")
XRAY_CONFIG = Path("/usr/local/etc/xray/config.json")
XRAY = "/usr/local/bin/xray"
XRAY_DROPIN = Path("/etc/systemd/system/xray.service.d/99-lastvn-transports.conf")
CERT_HOOK = Path("/etc/letsencrypt/renewal-hooks/deploy/lastvn-transports")
CERT_DIR = Path("/etc/lastvn-transports")
CERT_GROUP = "lastvn-certs"
PROFILE = Path("/etc/lastvn-ws/profile.tsv")
NGINX = Path("/etc/nginx/conf.d/lastvn-ws.conf")
UNIT = Path("/etc/systemd/system/lastvn-subscription.service")
SOCKET = Path("/run/lastvn-subscription/http.sock")
ROUTE = re.compile(r"/sub/([a-f0-9]{32})(-split)?")
GIB = 1024**3
TRANSPORT_TAGS = ("lastvn-tcp", "lastvn-tls-ws", "lastvn-tls-grpc", "lastvn-hysteria")
WS_LOCAL, GRPC_LOCAL = 16201, 16202

STYLE = """
:root{color-scheme:dark;--bg:#0c1010;--panel:#151b1a;--ink:#f0f7f4;--muted:#a4b5ad;--accent:#adf4ce;--line:#2c3933}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;padding:clamp(26px,7vw,100px) 24px;background:radial-gradient(ellipse at top right,#1a352b,transparent 48%),var(--bg);color:var(--ink);font:16px/1.5 Inter,system-ui,sans-serif}
main{max-width:760px;margin:auto}
header{display:flex;flex-direction:column;gap:12px;margin-bottom:36px}
.brand{font-weight:800;letter-spacing:-.05em;color:var(--accent)}
h1{font-size:clamp(32px,6vw,57px);letter-spacing:-.052em;line-height:1.05;margin:0;max-width:700px}
.account{color:var(--muted);margin:4px 0 0}
.account strong{color:var(--ink);overflow-wrap:anywhere}
.card{border:1px solid var(--line);background:linear-gradient(140deg,#1c2923,var(--panel) 55%);border-radius:24px;padding:clamp(21px,5vw,38px)}
.usage{font-size:clamp(34px,7vw,64px);font-variant-numeric:tabular-nums;font-weight:750;line-height:1.12;letter-spacing:-.05em;margin:5px 0 15px}
h2{margin:0;color:var(--muted);font-size:14px;font-weight:600;letter-spacing:.02em}
progress{width:100%;height:10px;border:0;border-radius:8px;display:block;margin-bottom:14px;appearance:none;overflow:hidden;background:#2c3933}
progress::-webkit-progress-bar{background:#2c3933}progress::-webkit-progress-value{background:var(--accent)}progress::-moz-progress-bar{background:var(--accent)}
.small{color:var(--muted);margin:0;font-size:14px}
.metrics{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:12px 0 23px}
.metric{background:var(--panel);border:1px solid var(--line);border-radius:17px;padding:17px 21px}
.metric p{font-size:clamp(18px,3vw,25px);font-weight:700;margin:5px 0 0;letter-spacing:-.025em}
.actions{display:flex;gap:14px;flex-wrap:wrap;align-items:center}
.profiles{margin-top:26px}.profiles ul{display:flex;flex-wrap:wrap;gap:8px;padding:0;list-style:none;color:var(--muted)}
.profiles li{border:1px solid var(--line);border-radius:12px;padding:6px 10px;font-size:14px}
button,a{display:inline-block;border-radius:12px;padding:10px 16px;font:inherit;font-weight:650;text-decoration:none}
button{appearance:none;border:0;background:var(--accent);color:#101c16;cursor:pointer}
a{color:var(--ink);border:1px solid var(--line)}
button:focus-visible,a:focus-visible{outline:3px solid #e3fff0;outline-offset:3px}
#notice{min-height:21px;margin-top:10px}
@media(max-width:430px){body{padding:26px 16px}.metrics{grid-template-columns:1fr}header{margin-bottom:24px}}
"""
SCRIPT = """
const button = document.querySelector('button');
const notice = document.querySelector('#notice');
button.addEventListener('click', async () => {
  try {
    const url = new URL(location.href);
    url.search = '';
    url.hash = '';
    await navigator.clipboard.writeText(url.href);
    notice.textContent = 'Ссылка скопирована';
  } catch (_) {
    notice.textContent = 'Скопируй ссылку из адресной строки';
  }
});
"""


def number(value):
    return f"{value:,.2f}".replace(",", " ").replace(".", ",")


def card(nick, used, quota, rate, route, has_transports=False):
    traffic = f"{number(used / GIB)} ГиБ" if used is not None else "Нет данных"
    quota_label = f"{number(quota / GIB)} ГиБ" if quota else "Безлимит"
    speed_label = f"{rate} Мбит/с" if rate else "Без ограничения"
    if quota and used is not None:
        proportion = max(0, min(100, int(used * 100 / quota)))
        usage_detail = ("Квота исчерпана" if used >= quota
                        else f"Осталось {number((quota - used) / GIB)} ГиБ")
        usage_bar = f'<progress value="{proportion}" max="100" aria-label="Использовано квоты"></progress>'
    else:
        usage_detail = "Лимит объёма не задан" if not quota else "Данные счётчика пока недоступны"
        usage_bar = ""
    transports = ""
    if has_transports:
        transports = f"""<section class="profiles"><h2>Профили VLESS</h2>
<ul><li>XHTTP + REALITY</li><li>TCP + REALITY</li><li>WebSocket + TLS</li>
<li>gRPC + TLS</li><li>Hysteria + TLS</li></ul>
<a href="{escape(route, quote=True)}?format=hysteria">Скачать Hysteria для Xray</a></section>"""
    content = f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>{escape(NAME)}</title><style>{STYLE}</style></head>
<body><main>
<header><h1><span class="brand">LastVN</span>: {escape(NAME.partition(': ')[2])}</h1>
<p class="account">Пользователь <strong>{escape(nick)}</strong></p></header>
<section class="card" aria-labelledby="download"><h2 id="download">Скачано</h2><p class="usage">{traffic}</p>
{usage_bar}<p class="small">{usage_detail}</p></section>
<div class="metrics"><section class="metric"><h2>Квота скачивания</h2><p>{quota_label}</p></section>
<section class="metric"><h2>Скорость скачивания</h2><p>{speed_label}</p></section></div>
<div class="actions"><button type="button">Скопировать подписку</button>
<a href="{escape(route, quote=True)}?format=profile">Открыть профиль</a></div>
<p id="notice" class="small" role="status"></p>
{transports}
</main><script>{SCRIPT}</script></body></html>"""
    return content.encode()


def account_for(token):
    with TOKENS.open(encoding="utf-8") as source:
        for line in source:
            parts = line.split()
            if len(parts) == 2 and secrets.compare_digest(parts[1].encode(), token.encode()):
                return parts[0]
    return None


def counters(nick):
    item = {}
    try:
        item = json.loads(POLICY.read_text()).get(nick, {})
    except (OSError, ValueError):
        pass
    used = 0 if LIVE.exists() and item and not item.get("blocked") else None
    if USAGE.is_file():
        try:
            with sqlite3.connect(f"file:{USAGE}?mode=ro", uri=True, timeout=0.4) as db:
                db.execute("PRAGMA trusted_schema=OFF")
                row = db.execute("SELECT bytes FROM usage WHERE nick = ?", (nick,)).fetchone()
            if row:
                used = row[0]
        except sqlite3.Error:
            used = None
    return used, item.get("quota", 0), item.get("mbps", 0)


def decoded_profiles(data):
    return base64.b64decode(data, validate=True).decode().splitlines()


def direct_profile(data):
    return urlsplit(next(line for line in decoded_profiles(data) if line.startswith("vless://")))


def transport_links(user, settings):
    direct = parse_qs(user.query)
    reality = {name: direct[name][0] for name in ("sni", "fp", "pbk", "sid")}
    tls = {"security": "tls", "sni": settings["hostname"]}
    for address, port, parameters, label in (
        (user.hostname, settings["raw_port"], {"security": "reality", "type": "tcp", **reality}, "TCP"),
        (settings["hostname"], settings["tls_port"], {**tls, "type": "ws",
             "host": settings["hostname"], "path": settings["path"]}, "WS"),
        (settings["hostname"], settings["tls_port"], {**tls, "type": "grpc",
             "alpn": "h2", "serviceName": settings["grpc"]}, "gRPC"),
    ):
        query = urlencode({"encryption": "none", **parameters}, quote_via=quote)
        yield f"vless://{user.username}@{address}:{port}?{query}#{quote(NAME + ' · ' + label, safe='')}"


def hysteria_profile(user, settings):
    return json.dumps({
        "remarks": NAME + " · Hysteria",
        "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks",
                      "settings": {"udp": True}}],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": settings["hostname"], "port": settings["hysteria_port"],
                "users": [{"id": user.username, "encryption": "none"}],
            }]},
            "streamSettings": {
                "network": "hysteria", "security": "tls",
                "tlsSettings": {"serverName": settings["hostname"], "alpn": ["h3"]},
                "hysteriaSettings": {"version": 2, "auth": settings["hysteria_auth"]},
            },
        }],
    }, ensure_ascii=False, indent=2).encode()


def branded_profile(data, split, settings):
    if split:
        document = json.loads(data)
        document["remarks"] = NAME
        return json.dumps(document, ensure_ascii=False).encode()
    renamed = [
        line.split("#", 1)[0] + "#" + quote(NAME, safe="") if line.startswith("vless://") else line
        for line in decoded_profiles(data)
    ]
    if settings:
        renamed.extend(transport_links(direct_profile(data), settings))
    return base64.b64encode("\n".join(renamed).encode())


class Handler(BaseHTTPRequestHandler):
    timeout = 3

    def log_message(self, *args):
        # The URL contains the subscription's bearer secret.
        return

    def answer(self, status, body, content_type, headers=()):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("Vary", "Accept, Sec-Fetch-Mode")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        location = urlsplit(self.path)
        match = ROUTE.fullmatch(location.path)
        if match is None:
            self.answer(404, b"Not found", "text/plain")
            return
        token, split = match.groups()
        try:
            profile = (PROFILES / (token + (split or ""))).read_bytes()
            nick = account_for(token)
            if not nick:
                raise FileNotFoundError
        except OSError:
            self.answer(404, b"Not found", "text/plain")
            return
        used, quota, rate = counters(nick)
        settings = json.loads(TRANSPORTS.read_text()) if TRANSPORTS.is_file() and not split else {}
        if location.query == "format=hysteria":
            if not settings:
                self.answer(404, b"Not found", "text/plain")
                return
            try:
                config = hysteria_profile(direct_profile(profile), settings)
            except (ValueError, StopIteration):
                self.answer(404, b"Profile not found", "text/plain")
                return
            self.answer(200, config, "application/json",
                        (("Content-Disposition", 'attachment; filename="LastVN-Hysteria.json"'),))
            return
        manually = location.query == "format=profile"
        accept_html = "text/html" in self.headers.get("Accept", "")
        navigation = self.headers.get("Sec-Fetch-Mode", "") in ("", "navigate")
        if not manually and accept_html and navigation:
            self.answer(200, card(nick, used, quota, rate, location.path, bool(settings)),
                        "text/html; charset=utf-8")
            return
        try:
            profile = branded_profile(profile, split, settings)
        except (ValueError, TypeError, KeyError, StopIteration, UnicodeError, binascii.Error):
            # Keep nonstandard legacy profiles importable.
            pass
        title = "base64:" + base64.b64encode(NAME.encode()).decode()
        headers = (
            ("profile-title", title),
            ("profile-update-interval", "12"),
            ("subscription-userinfo", f"upload=0; download={used or 0}; total={quota}; expire=0"),
            ("x-lastvn-user", quote(nick, safe="")),
            ("x-lastvn-download-limit-mbps", str(rate)),
        )
        self.answer(200, profile, "application/json" if split else "text/plain; charset=utf-8", headers)

    do_HEAD = do_GET


def write(path, content, mode=0o644):
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            os.fchmod(stream.fileno(), mode)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def run(*args):
    subprocess.run(args, check=True)


def checked_config(config):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".json") as draft:
        json.dump(config, draft)
        draft.flush()
        run(XRAY, "run", "-test", "-c", draft.name)


def tls_files(nginx):
    cert = re.search(r"(?m)^\s*ssl_certificate\s+(/[^;\s]+);$", nginx)
    key = re.search(r"(?m)^\s*ssl_certificate_key\s+(/[^;\s]+);$", nginx)
    if not cert or not key:
        raise ValueError("В существующем TLS-входе не найдена пара сертификат/ключ")
    return Path(cert[1]), Path(key[1])


def sync_certificate():
    certificate, private_key = tls_files(NGINX.read_text())
    try:
        group = grp.getgrnam(CERT_GROUP)
    except KeyError:
        run("groupadd", "--system", CERT_GROUP)
        group = grp.getgrnam(CERT_GROUP)
    CERT_DIR.mkdir(mode=0o750, exist_ok=True)
    os.chown(CERT_DIR, 0, group.gr_gid)
    CERT_DIR.chmod(0o750)
    for target, source in ((CERT_DIR / "tls.crt", certificate), (CERT_DIR / "tls.key", private_key)):
        write(target, source.read_text(), 0o640)
        os.chown(target, 0, group.gr_gid)


def transport_config(config, settings, certificate, private_key):
    main = config["inbounds"][0]
    if main.get("protocol") != "vless":
        raise ValueError("Основной вход Xray должен быть VLESS")
    reality = deepcopy(main["streamSettings"]["realitySettings"])
    common = {"protocol": "vless", "settings": deepcopy(main["settings"])}
    if "sniffing" in main:
        common["sniffing"] = deepcopy(main["sniffing"])
    base = [
        (TRANSPORT_TAGS[0], "::", settings["raw_port"],
         {"network": "raw", "security": "reality", "realitySettings": reality}),
        (TRANSPORT_TAGS[1], "127.0.0.1", WS_LOCAL,
         {"network": "ws", "wsSettings": {"path": settings["path"]}}),
        (TRANSPORT_TAGS[2], "127.0.0.1", GRPC_LOCAL,
         {"network": "grpc", "grpcSettings": {"serviceName": settings["grpc"]}}),
        (TRANSPORT_TAGS[3], "::", settings["hysteria_port"],
         {"network": "hysteria", "security": "tls",
          "hysteriaSettings": {"version": 2, "auth": settings["hysteria_auth"]},
          "tlsSettings": {"alpn": ["h3"], "certificates": [
              {"certificateFile": certificate, "keyFile": private_key},
          ]}}),
    ]
    config["inbounds"] = [item for item in config["inbounds"] if item.get("tag") not in TRANSPORT_TAGS]
    for tag, listen, port, stream in base:
        config["inbounds"].append({**deepcopy(common), "tag": tag, "listen": listen, "port": port,
                                   "streamSettings": stream})
    for rule in config.get("routing", {}).get("rules", []):
        if rule.get("outboundTag", "").startswith("lastos-limit-"):
            rule["inboundTag"] = list(dict.fromkeys([main["tag"], *TRANSPORT_TAGS]))


def nginx_transports(config, settings):
    start, end = "    # BEGIN LASTVN TRANSPORTS", "    # END LASTVN TRANSPORTS"
    config = re.sub(rf"(?ms)^{start}\n.*?^{end}\n", "", config)
    marker = "    location / {"
    if config.count(marker) != 1:
        raise ValueError("Не найдена точка вставки TLS-транспортов nginx")
    options = "" if re.search(r"(?m)^\s*http2 on;\s*$", config) else "    http2 on;\n"
    return config.replace(marker, f"""{start}
{options}    location = {settings['path']} {{
        proxy_pass http://127.0.0.1:{WS_LOCAL};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }}
    location ^~ /{settings['grpc']}/ {{
        grpc_pass grpc://127.0.0.1:{GRPC_LOCAL};
        grpc_read_timeout 300s;
        grpc_send_timeout 300s;
    }}
{end}
{marker}""", 1)


def check_port(port, network):
    args = "-Hlnu" if network == "udp" else "-Hlnt"
    result = subprocess.run(("ss", args, f"sport = :{port}"), check=True, capture_output=True, text=True)
    if result.stdout.strip():
        raise ValueError(f"Порт {port}/{network} занят")


def install_transports():
    nginx = NGINX.read_text()
    host, tls_port, *_ = PROFILE.read_text().strip().split("\t")
    config = json.loads(XRAY_CONFIG.read_text())
    previous = json.loads(TRANSPORTS.read_text()) if TRANSPORTS.exists() else {}
    settings = previous or {
        "hostname": host, "tls_port": int(tls_port), "raw_port": 2443,
        "hysteria_port": int(tls_port), "path": "/ws-" + secrets.token_hex(10),
        "grpc": "grpc-" + secrets.token_hex(10), "hysteria_auth": secrets.token_hex(24),
    }
    if [settings["hostname"], settings["tls_port"]] != [host, int(tls_port)]:
        raise ValueError("Изменился адрес или порт существующего TLS-входа")
    if not all(tag in {item.get("tag") for item in config["inbounds"]} for tag in TRANSPORT_TAGS):
        for port, network in ((settings["raw_port"], "tcp"), (WS_LOCAL, "tcp"),
                              (GRPC_LOCAL, "tcp"), (settings["hysteria_port"], "udp")):
            check_port(port, network)
    certificate, private_key = tls_files(nginx)
    checked = deepcopy(config)
    transport_config(checked, settings, str(certificate), str(private_key))
    checked_config(checked)
    sync_certificate()
    transport_config(config, settings, str(CERT_DIR / "tls.crt"), str(CERT_DIR / "tls.key"))
    rewritten = nginx_transports(nginx, settings)
    changes = {
        NGINX: rewritten,
        XRAY_CONFIG: json.dumps(config, ensure_ascii=False, indent=2) + "\n",
        XRAY_DROPIN: f"[Service]\nSupplementaryGroups={CERT_GROUP}\n",
    }
    if Path(certificate).is_relative_to("/etc/letsencrypt/live"):
        lineage = certificate.parent
        changes[CERT_HOOK] = f'''#!/bin/sh
if [ "${{RENEWED_LINEAGE:-}}" = "{lineage}" ]; then
    /usr/local/sbin/lastos-subscriptions refresh-cert && systemctl try-restart xray
fi
'''
    XRAY_DROPIN.parent.mkdir(parents=True, exist_ok=True)
    if CERT_HOOK in changes:
        CERT_HOOK.parent.mkdir(parents=True, exist_ok=True)
    before = {path: (path.read_text(), path.stat().st_mode & 0o777) if path.exists() else None
              for path in changes}
    restarted = False
    try:
        for path, content in changes.items():
            mode = 0o755 if path == CERT_HOOK else 0o644
            if path == XRAY_CONFIG:
                mode = before[path][1]
            write(path, content, mode)
        run("nginx", "-t")
        run("systemctl", "daemon-reload")
        restarted = True
        run("systemctl", "restart", "xray")
        run("systemctl", "is-active", "--quiet", "xray")
        run("systemctl", "reload", "nginx")
        write(TRANSPORTS, json.dumps(settings, indent=2) + "\n", 0o600)
    except BaseException:
        for path, previous_contents in before.items():
            if previous_contents is None:
                path.unlink(missing_ok=True)
            else:
                write(path, *previous_contents)
        subprocess.run(("systemctl", "daemon-reload"), check=False)
        if restarted:
            subprocess.run(("systemctl", "restart", "xray"), check=False)
        subprocess.run(("systemctl", "reload", "nginx"), check=False)
        raise
    try:
        status = subprocess.run(("ufw", "status"), capture_output=True, text=True,
                                env={**os.environ, "LC_ALL": "C"}, check=False)
    except FileNotFoundError:
        pass
    else:
        if status.stdout.splitlines()[:1] == ["Status: active"]:
            run("ufw", "allow", f"{settings['raw_port']}/tcp")
            run("ufw", "allow", f"{settings['hysteria_port']}/udp")
    print("Подписки действующих и новых пользователей дополнены транспортами VLESS.")


def install():
    original = NGINX.read_text()
    line = f"        proxy_pass http://unix:{SOCKET}:;"
    modified = original
    if line not in original:
        match = re.search(r"(?m)^    location \^~ /sub/ \{\n(?P<body>(?:[^\n]*\n)*?)^    \}", original)
        if not match:
            raise ValueError("Не найден HTTPS-блок подписок LastOS. Сначала выполни lastos-admin install.")
        body = match["body"]
        configured = re.sub(
            r"(?m)^        try_files \$uri =404;\n",
            line + "\n        proxy_connect_timeout 3s;\n        proxy_read_timeout 8s;\n",
            body,
        )
        if configured == body:
            raise ValueError("Не найден ожидаемый try_files в подписках LastOS")
        modified = original[:match.start("body")] + configured + original[match.end("body"):]
    write(UNIT, """[Unit]
Description=LastVN HTTPS subscription cards
After=local-fs.target

[Service]
RuntimeDirectory=lastvn-subscription
RuntimeDirectoryMode=0755
ExecStart=/usr/local/sbin/lastos-subscriptions serve
Restart=on-failure
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
RestrictAddressFamilies=AF_UNIX

[Install]
WantedBy=multi-user.target
""")
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", SERVICE)
    run("systemctl", "restart", SERVICE)
    for _ in range(30):
        if SOCKET.is_socket():
            break
        time.sleep(0.1)
    else:
        raise OSError("Сервис подписок не открыл локальный сокет")
    write(NGINX, modified)
    try:
        run("nginx", "-t")
        run("systemctl", "reload", "nginx")
    except BaseException:
        write(NGINX, original)
        run("nginx", "-t")
        run("systemctl", "reload", "nginx")
        raise
    print("Карточки LastVN включены на действующих HTTPS-ссылках подписок.")


def serve():
    SOCKET.unlink(missing_ok=True)
    with socketserver.UnixStreamServer(str(SOCKET), Handler) as server:
        os.chown(SOCKET, -1, grp.getgrnam("www-data").gr_gid)
        SOCKET.chmod(0o660)
        server.serve_forever()


SERVICE = "lastvn-subscription.service"


if __name__ == "__main__":
    try:
        args = sys.argv[1:]
        actions = {"install": install, "transports": install_transports, "refresh-cert": sync_certificate}
        if args == ["serve"]:
            serve()
        elif len(args) == 1 and args[0] in actions and os.geteuid() == 0:
            with open("/run/lock/lastos-admin.lock", "a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                actions[args[0]]()
        else:
            sys.exit("Установка: lastos-subscriptions install | transports (от root)")
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(f"Ошибка подписок LastVN: {error}")
