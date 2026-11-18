#!/usr/bin/env bash
# LastVN — установщик VLESS + XHTTP + Reality на базе Xray-core.
# Домен и сертификат не нужны: Reality маскирует трафик под TLS чужого сайта.
#
# Использование:
#   sudo bash lastvn.sh install [--port 443] [--sni www.microsoft.com] [--name user1]
#   sudo bash lastvn.sh add <имя>        — добавить пользователя
#   sudo bash lastvn.sh del <имя>        — удалить пользователя
#   sudo bash lastvn.sh list             — список пользователей
#   sudo bash lastvn.sh link <имя>       — ссылка + QR-код для клиента
#   sudo bash lastvn.sh status           — статус сервиса
#   sudo bash lastvn.sh uninstall        — удалить всё

set -euo pipefail

XRAY_BIN="/usr/local/bin/xray"
XRAY_DIR="/usr/local/etc/xray"
CONFIG="$XRAY_DIR/config.json"
STATE="$XRAY_DIR/lastvn.env"   # параметры сервера: IP, публичный ключ, SNI и т.д.

DEFAULT_PORT=443
DEFAULT_SNI="www.microsoft.com"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
die()   { red "Ошибка: $*" >&2; exit 1; }

need_root() { [[ $EUID -eq 0 ]] || die "запусти через sudo/root"; }
installed() { [[ -f "$CONFIG" && -f "$STATE" ]]; }
need_installed() { installed || die "LastVN не установлен. Сначала: $0 install"; }

# ---------- зависимости ----------
install_deps() {
  if command -v apt-get >/dev/null; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl jq openssl qrencode unzip ca-certificates >/dev/null
  elif command -v dnf >/dev/null; then
    dnf install -y -q curl jq openssl qrencode unzip ca-certificates
  elif command -v yum >/dev/null; then
    yum install -y -q epel-release || true
    yum install -y -q curl jq openssl qrencode unzip ca-certificates
  else
    die "неизвестный пакетный менеджер, поставь вручную: curl jq openssl qrencode unzip"
  fi
}

install_xray() {
  yellow "Устанавливаю Xray-core (официальный скрипт XTLS/Xray-install)..."
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
  [[ -x "$XRAY_BIN" ]] || die "xray не установился"
}

enable_bbr() {
  if ! sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
    cat > /etc/sysctl.d/99-lastvn-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    sysctl --system >/dev/null 2>&1 || true
  fi
}

open_port() {
  local port=$1
  if command -v ufw >/dev/null && ufw status | grep -q active; then
    ufw allow "$port"/tcp >/dev/null
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd -q --permanent --add-port="$port"/tcp && firewall-cmd -q --reload
  fi
}

# ---------- генерация параметров ----------
server_ip() {
  local ip
  for url in https://api.ipify.org https://ifconfig.me https://icanhazip.com; do
    ip=$(curl -4 -fsS --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]') && [[ -n $ip ]] && { echo "$ip"; return; }
  done
  die "не удалось определить внешний IP сервера"
}

# Совместимо со старым ("Private key:/Public key:") и новым ("PrivateKey:/Password:") выводом xray x25519.
gen_keys() {
  local out priv pub
  out=$("$XRAY_BIN" x25519)
  priv=$(awk -F': *' 'tolower($1) ~ /^private ?key$/ {print $2}' <<<"$out")
  pub=$(awk -F': *' 'tolower($1) ~ /^(public ?key|password)$/ {print $2}' <<<"$out")
  [[ -n $priv && -n $pub ]] || die "не удалось распарсить вывод xray x25519:\n$out"
  echo "$priv $pub"
}

check_sni() {
  local sni=$1
  # Цель Reality должна поддерживать TLS 1.3 и HTTP/2.
  if ! curl -sS -o /dev/null --max-time 8 --tlsv1.3 --http2 "https://$sni" 2>/dev/null; then
    yellow "Внимание: $sni не ответил по TLS 1.3/HTTP2 с этого сервера — лучше выбрать другой SNI."
  fi
}

# ---------- конфиг ----------
write_config() {
  local port=$1 sni=$2 priv=$3 sid=$4 path=$5 uuid=$6 name=$7
  mkdir -p "$XRAY_DIR"
  jq -n \
    --argjson port "$port" --arg sni "$sni" --arg priv "$priv" \
    --arg sid "$sid" --arg path "$path" --arg uuid "$uuid" --arg name "$name" '
  {
    log: { loglevel: "warning" },
    inbounds: [{
      tag: "vless-xhttp-reality",
      listen: "0.0.0.0",
      port: $port,
      protocol: "vless",
      settings: {
        clients: [{ id: $uuid, email: $name }],
        decryption: "none"
      },
      streamSettings: {
        network: "xhttp",
        xhttpSettings: { path: $path, mode: "auto" },
        security: "reality",
        realitySettings: {
          show: false,
          target: ($sni + ":443"),
          xver: 0,
          serverNames: [$sni],
          privateKey: $priv,
          shortIds: [$sid]
        }
      },
      sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], routeOnly: true }
    }],
    outbounds: [
      { tag: "direct", protocol: "freedom" },
      { tag: "block",  protocol: "blackhole" }
    ],
    routing: {
      domainStrategy: "IPIfNonMatch",
      rules: [
        { type: "field", ip: ["geoip:private"], outboundTag: "block" },
        { type: "field", protocol: ["bittorrent"], outboundTag: "block" }
      ]
    }
  }' > "$CONFIG"
}

test_and_restart() {
  "$XRAY_BIN" run -test -c "$CONFIG" >/dev/null || die "конфиг невалиден: $XRAY_BIN run -test -c $CONFIG"
  systemctl restart xray
  sleep 1
  systemctl is-active --quiet xray || die "xray не запустился: journalctl -u xray -n 50"
}

# Атомарно правим конфиг через jq-фильтр.
edit_config() {
  local tmp; tmp=$(mktemp)
  jq "$@" "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG"
  chmod 644 "$CONFIG"
}

# ---------- ссылки ----------
urlencode() { jq -rn --arg s "$1" '$s|@uri'; }

make_link() {
  local name=$1 uuid
  # shellcheck disable=SC1090
  source "$STATE"
  uuid=$(jq -r --arg n "$name" '.inbounds[0].settings.clients[] | select(.email==$n) | .id' "$CONFIG")
  [[ -n $uuid ]] || die "пользователь '$name' не найден"
  local host=$SERVER_IP
  [[ $host == *:* ]] && host="[$host]"
  printf 'vless://%s@%s:%s?encryption=none&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=xhttp&path=%s&mode=auto#%s\n' \
    "$uuid" "$host" "$PORT" "$SNI" "$PUBLIC_KEY" "$SHORT_ID" "$(urlencode "$XHTTP_PATH")" "$(urlencode "LastVN-$name")"
}

show_link() {
  local link; link=$(make_link "$1")
  echo
  green "Пользователь: $1"
  echo "$link"
  echo
  command -v qrencode >/dev/null && qrencode -t ANSIUTF8 "$link"
}

# ---------- команды ----------
cmd_install() {
  need_root
  local port=$DEFAULT_PORT sni=$DEFAULT_SNI name="user1"
  while [[ $# -gt 0 ]]; do
    case $1 in
      --port) port=$2; shift 2 ;;
      --sni)  sni=$2;  shift 2 ;;
      --name) name=$2; shift 2 ;;
      *) die "неизвестный параметр: $1" ;;
    esac
  done
  [[ $port =~ ^[0-9]+$ && $port -ge 1 && $port -le 65535 ]] || die "неверный порт: $port"
  if installed; then
    yellow "LastVN уже установлен. Для переустановки сначала: $0 uninstall"
    exit 1
  fi

  install_deps
  install_xray
  enable_bbr

  local ip priv pub sid path uuid
  ip=$(server_ip)
  read -r priv pub < <(gen_keys)
  sid=$(openssl rand -hex 8)
  path="/$(openssl rand -hex 6)"
  uuid=$("$XRAY_BIN" uuid)
  check_sni "$sni"

  write_config "$port" "$sni" "$priv" "$sid" "$path" "$uuid" "$name"
  cat > "$STATE" <<EOF
SERVER_IP=$ip
PORT=$port
SNI=$sni
PUBLIC_KEY=$pub
SHORT_ID=$sid
XHTTP_PATH=$path
EOF
  chmod 600 "$STATE"
  chmod 644 "$CONFIG"

  open_port "$port"
  systemctl enable xray >/dev/null 2>&1
  test_and_restart

  green "Готово! VLESS + XHTTP + Reality работает на $ip:$port (маскировка под $sni)"
  show_link "$name"
}

cmd_add() {
  need_root; need_installed
  local name=${1:-}; [[ -n $name ]] || die "укажи имя: $0 add <имя>"
  [[ $name =~ ^[A-Za-z0-9_.-]+$ ]] || die "имя: только латиница, цифры, _ . -"
  jq -e --arg n "$name" '.inbounds[0].settings.clients[] | select(.email==$n)' "$CONFIG" >/dev/null \
    && die "пользователь '$name' уже есть"
  local uuid; uuid=$("$XRAY_BIN" uuid)
  edit_config --arg n "$name" --arg id "$uuid" '.inbounds[0].settings.clients += [{id:$id, email:$n}]'
  test_and_restart
  show_link "$name"
}

cmd_del() {
  need_root; need_installed
  local name=${1:-}; [[ -n $name ]] || die "укажи имя: $0 del <имя>"
  jq -e --arg n "$name" '.inbounds[0].settings.clients[] | select(.email==$n)' "$CONFIG" >/dev/null \
    || die "пользователь '$name' не найден"
  [[ $(jq '.inbounds[0].settings.clients | length' "$CONFIG") -gt 1 ]] || die "нельзя удалить последнего пользователя"
  edit_config --arg n "$name" '.inbounds[0].settings.clients |= map(select(.email != $n))'
  test_and_restart
  green "Пользователь '$name' удалён"
}

cmd_list() {
  need_installed
  jq -r '.inbounds[0].settings.clients[] | "\(.email)\t\(.id)"' "$CONFIG"
}

cmd_link() {
  need_installed
  local name=${1:-}; [[ -n $name ]] || die "укажи имя: $0 link <имя>"
  show_link "$name"
}

cmd_status() {
  need_installed
  # shellcheck disable=SC1090
  source "$STATE"
  echo "Сервер: $SERVER_IP:$PORT   SNI: $SNI   path: $XHTTP_PATH"
  echo "Xray:   $("$XRAY_BIN" version | head -1)"
  systemctl --no-pager status xray | head -5
}

cmd_uninstall() {
  need_root
  read -r -p "Удалить Xray и все ключи пользователей? [y/N] " ans
  [[ $ans =~ ^[Yy]$ ]] || exit 0
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge || true
  rm -rf "$XRAY_DIR" /etc/sysctl.d/99-lastvn-bbr.conf
  green "LastVN удалён"
}

usage() { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; }

case ${1:-} in
  install)   shift; cmd_install "$@" ;;
  add)       shift; cmd_add "$@" ;;
  del)       shift; cmd_del "$@" ;;
  list)      cmd_list ;;
  link)      shift; cmd_link "$@" ;;
  status)    cmd_status ;;
  uninstall) cmd_uninstall ;;
  *)         usage ;;
esac
