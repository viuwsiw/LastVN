#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf '%s\n' "$*" >&2
  exit 1
}

[[ $EUID == 0 ]] || fail "Запусти установку на RU VPS от root."
[[ $# == 1 ]] || fail "Использование: bash lastvn-ru-relay.sh IPv4_NL"

readonly nl_address=$1
readonly xray=/usr/local/bin/xray
readonly unit=lastvn-ru-relay.service
readonly unit_path=/etc/systemd/system/$unit
readonly config_path=/usr/local/etc/xray/lastvn-ru-relay.json
readonly generator=https://raw.githubusercontent.com/viuwsiw/LastVN/973b1f6bfc32bf18a45603cd14eeba7d3c03dcc8/lastvn-aeza-split.py

umask 077
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

curl -fsSL --retry 2 "$generator" -o "$work/generate.py"
python3 "$work/generate.py" relay "$nl_address" > "$work/relay.json"

if ip -o -4 address show | awk '{split($4,ip,"/"); print ip[1]}' | grep -Fx "$nl_address" >/dev/null; then
  fail "Это адрес NL. Открой консоль российского VPS."
fi

listener=$(ss -H -ltnp 'sport = :443')
pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
if [[ -n $listener && ( ! $pid =~ ^[1-9][0-9]*$ || $listener != *"pid=$pid,"* ) ]]; then
  fail "TCP 443 уже занят другим сервисом на RU."
fi

python3 - "$nl_address" <<'PY'
import socket
import sys

try:
    with socket.create_connection((sys.argv[1], 443), timeout=5):
        pass
except OSError as error:
    sys.exit(f"RU не может открыть TCP до NL:443: {error}")
PY

if [[ ! -x $xray ]]; then
  [[ $(uname -m) == x86_64 ]] || fail "Для этой архитектуры установи Xray перед запуском."
  curl -fsSL --retry 2 https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-64.zip \
    -o "$work/xray.zip"
  (cd "$work" && sha256sum -c <<< 'b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82  xray.zip')
  python3 - "$work" <<'PY'
from pathlib import Path
import shutil
import sys
from zipfile import ZipFile

directory = Path(sys.argv[1])
with ZipFile(directory / "xray.zip") as archive, archive.open("xray") as source:
    with (directory / "xray").open("wb") as destination:
        shutil.copyfileobj(source, destination)
PY
  install -Dm 755 "$work/xray" "$xray"
fi

"$xray" run -test -c "$work/relay.json"
cat > "$work/$unit" <<'UNIT'
[Unit]
Description=LastVN RU relay
After=network-online.target
Wants=network-online.target

[Service]
DynamicUser=yes
LoadCredential=relay.json:/usr/local/etc/xray/lastvn-ru-relay.json
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ExecStart=/usr/local/bin/xray run -c %d/relay.json
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

install -Dm 600 "$work/relay.json" "$config_path"
install -m 644 "$work/$unit" "$unit_path"
systemctl daemon-reload
if systemctl is-failed --quiet "$unit"; then
  systemctl reset-failed "$unit"
fi
systemctl restart "$unit"

for _ in {1..20}; do
  pid=$(systemctl show "$unit" -p MainPID --value)
  if [[ $pid =~ ^[1-9][0-9]*$ && $(ss -H -ltnp 'sport = :443') == *"pid=$pid,"* ]]; then
    systemctl enable "$unit"
    if command -v ufw >/dev/null && LC_ALL=C ufw status | grep -Fx 'Status: active' >/dev/null; then
      ufw allow 443/tcp
    fi
    printf 'Мост запущен. RU:443 → %s:443\n' "$nl_address"
    exit 0
  fi
  sleep .2
done

journalctl -u "$unit" -n 15 --no-pager >&2
fail "Мост не открыл TCP 443."
