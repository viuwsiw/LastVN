#!/usr/bin/env bash
# LastVN — установщик VLESS + XHTTP + Reality на базе Xray-core.
# Домен и сертификат не нужны: Reality маскирует трафик под TLS чужого сайта.
#
# Использование:
#   sudo bash lastvn.sh install [--port 443] [--sub-port 2096] [--sni www.microsoft.com] [--name user1] [--support-url URL]
#   sudo bash lastvn.sh add <имя>        — добавить пользователя
#   sudo bash lastvn.sh del <имя>        — удалить пользователя
#   sudo bash lastvn.sh list             — список пользователей
#   sudo bash lastvn.sh link <имя>       — подписка, ссылка и QR-код для клиента
#   sudo bash lastvn.sh status           — статус сервисов
#   sudo bash lastvn.sh tune             — ускорение сети (BBR, TCP-буферы)
#   sudo bash lastvn.sh mtproto [--port 8443] [--domain www.google.com] — прокси для Telegram
#   sudo bash lastvn.sh mtproto-remove   — удалить прокси для Telegram
#   sudo bash lastvn.sh uninstall        — удалить всё

set -euo pipefail

TITLE="LastVN: первый, надежный"   # название в клиентах (Happ/INCY: до 25 символов)

XRAY_BIN="/usr/local/bin/xray"
XRAY_DIR="/usr/local/etc/xray"
CONFIG="$XRAY_DIR/config.json"
STATE="$XRAY_DIR/lastvn.env"      # параметры сервера
TOKENS="$XRAY_DIR/lastvn.tokens"  # "имя токен_подписки" по строке
WEB="/var/www/lastvn"
NGINX_CONF="/etc/nginx/conf.d/lastvn.conf"

DEFAULT_PORT=443
DEFAULT_SUB_PORT=2096
DEFAULT_SNI="www.microsoft.com"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
die()   { red "Ошибка: $*" >&2; exit 1; }

need_root() { [[ $EUID -eq 0 ]] || die "запусти через sudo/root"; }
installed() { [[ -f "$CONFIG" && -f "$STATE" ]]; }
need_installed() { installed || die "LastVN не установлен. Сначала: $0 install"; }
valid_port() { [[ $1 =~ ^[0-9]+$ && $1 -ge 1 && $1 -le 65535 ]]; }

port_free() {
  local port=$1 who
  who=$(ss -Hltnp "sport = :$port" 2>/dev/null || true)
  [[ -z $who ]] || die "порт $port занят: $who
Освободи его (или переустанови ОС на сервере) и запусти снова."
}

# ---------- зависимости ----------
install_deps() {
  if command -v apt-get >/dev/null; then
    # Без интерактивных вопросов (needrestart, замена конфигов dpkg и т.п.)
    export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1
    apt-get update -qq
    apt-get install -y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
      curl jq openssl qrencode unzip nginx ca-certificates iproute2 >/dev/null
  elif command -v dnf >/dev/null; then
    dnf install -y -q curl jq openssl qrencode unzip nginx ca-certificates iproute
  else
    die "поддерживаются Ubuntu/Debian и RHEL-подобные системы"
  fi
}

install_xray() {
  yellow "Устанавливаю Xray-core (официальный скрипт XTLS/Xray-install)..."
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
  [[ -x "$XRAY_BIN" ]] || die "xray не установился"
}

# Ускорение сети: BBR + большие TCP-буферы (важны для гигабита и высокого пинга).
tune_network() {
  rm -f /etc/sysctl.d/99-lastvn-bbr.conf
  cat > /etc/sysctl.d/99-lastvn.conf <<'SYSCTL'
# LastVN: ускорение сети
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 8192
net.ipv4.tcp_rmem = 4096 1048576 67108864
net.ipv4.tcp_wmem = 4096 1048576 67108864
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 131072
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.ip_local_port_range = 1024 65535
SYSCTL
  modprobe tcp_bbr 2>/dev/null || true
  sysctl --system >/dev/null 2>&1 || true
  # Лимит открытых файлов для xray (много соединений).
  mkdir -p /etc/systemd/system/xray.service.d
  printf '[Service]\nLimitNOFILE=1048576\n' > /etc/systemd/system/xray.service.d/99-lastvn.conf
  systemctl daemon-reload
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
  local ip url
  for url in https://api.ipify.org https://ifconfig.me https://icanhazip.com; do
    ip=$(curl -4 -fsS --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]') && [[ -n $ip ]] && { echo "$ip"; return; }
  done
  die "не удалось определить внешний IP сервера"
}

# Совместимо со всеми форматами xray x25519: "Private key/Public key", "PrivateKey/Password", "PrivateKey/Password (PublicKey)".
gen_keys() {
  # Во всех версиях xray x25519 первая строка — приватный ключ, вторая — публичный
  # ("Public key" / "Password" / "Password (PublicKey)"). Берём значение после последнего ": ".
  local out priv pub
  out=$("$XRAY_BIN" x25519 | tr -d '\r' | sed 's/\x1b\[[0-9;]*m//g')
  priv=$(sed -n '1s/.*:[[:space:]]*//p' <<<"$out")
  pub=$(sed -n '2s/.*:[[:space:]]*//p' <<<"$out")
  [[ $priv =~ ^[A-Za-z0-9_-]{43}$ && $pub =~ ^[A-Za-z0-9_-]{43}$ ]] \
    || die "не удалось распарсить вывод xray x25519: $out"
  echo "$priv $pub"
}

check_sni() {
  # Цель Reality должна поддерживать TLS 1.3 и HTTP/2.
  curl -sS -o /dev/null --max-time 8 --tlsv1.3 --http2 "https://$1" 2>/dev/null \
    || yellow "Внимание: $1 не ответил по TLS 1.3/HTTP2 с этого сервера — лучше выбрать другой SNI (--sni)."
}

# ---------- конфиг Xray ----------
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
  chmod 644 "$CONFIG"
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

user_uuid() {
  jq -r --arg n "$1" '.inbounds[0].settings.clients[] | select(.email==$n) | .id' "$CONFIG"
}

# ---------- ссылки и подписка ----------
urlencode() { jq -rn --arg s "$1" '$s|@uri'; }

make_link() {
  local uuid; uuid=$(user_uuid "$1")
  [[ -n $uuid ]] || die "пользователь '$1' не найден"
  # shellcheck disable=SC1090
  source "$STATE"
  printf 'vless://%s@%s:%s?encryption=none&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=xhttp&path=%s&mode=auto#%s\n' \
    "$uuid" "$SERVER_IP" "$PORT" "$SNI" "$PUBLIC_KEY" "$SHORT_ID" "$(urlencode "$XHTTP_PATH")" "$(urlencode "$TITLE")"
}

user_token() { awk -v n="$1" '$1==n {print $2}' "$TOKENS" 2>/dev/null; }

sub_url() {
  # shellcheck disable=SC1090
  source "$STATE"
  echo "http://$SERVER_IP:$SUB_PORT/sub/$(user_token "$1")"
}

# Пересобираем файлы подписок: по одному файлу на пользователя, тело — base64 со ссылками.
rebuild_subs() {
  mkdir -p "$WEB/sub"
  rm -f "$WEB/sub/"*
  local name token
  while read -r name token; do
    [[ -n $name ]] || continue
    make_link "$name" | base64 -w0 > "$WEB/sub/$token"
  done < "$TOKENS"
  chmod -R a+rX "$WEB"
}

add_token() { echo "$1 $(openssl rand -hex 16)" >> "$TOKENS"; chmod 600 "$TOKENS"; }

write_web() {
  local ip=$1 sub_port=$2 support=$3
  mkdir -p "$WEB/sub"
  write_logo "$WEB/logo.png"
  cat > "$WEB/index.html" <<EOF
<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LastVN</title><link rel="icon" href="/logo.png">
<style>body{margin:0;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;background:#000;color:#9a9a9a;font:18px system-ui,sans-serif}img{width:160px;height:160px}</style>
</head><body><img src="/logo.png" alt="LastVN"><h1>LastVN</h1><p>первый, надежный</p></body></html>
EOF

  local title_b64 support_hdr=""
  title_b64=$(printf '%s' "$TITLE" | base64 -w0)
  if [[ -n $support ]]; then support_hdr="add_header support-url \"$support\" always;"; fi

  cat > "$NGINX_CONF" <<EOF
# LastVN: сервер подписок (Happ, INCY, v2rayNG, Hiddify и др.)
server {
    listen $sub_port;
    listen [::]:$sub_port;
    server_name _;
    server_tokens off;
    root $WEB;
    access_log off;

    location = / { try_files /index.html =404; }
    location = /logo.png { }

    location /sub/ {
        default_type text/plain;
        charset utf-8;
        add_header profile-title "base64:$title_b64" always;
        add_header profile-update-interval "12" always;
        add_header subscription-userinfo "upload=0; download=0; total=0; expire=0" always;
        add_header profile-web-page-url "http://$ip:$sub_port/" always;
        add_header content-disposition "attachment; filename=\"LastVN\"" always;
        $support_hdr
        try_files \$uri =404;
    }

    location / { return 404; }
}
EOF
  nginx -t >/dev/null 2>&1 || die "конфиг nginx невалиден: nginx -t"
  systemctl enable nginx >/dev/null 2>&1
  systemctl restart nginx
}

show_user() {
  local name=$1 sub link
  sub=$(sub_url "$name")
  link=$(make_link "$name")
  echo
  green "Пользователь: $name"
  echo
  echo "Подписка (для Happ / INCY — с названием и логотипом LastVN):"
  echo "  $sub"
  echo
  echo "Прямая ссылка:"
  echo "  $link"
  echo
  if command -v qrencode >/dev/null; then
    echo "QR подписки:"
    # Консоль VNC/tty (TERM=linux) не рисует блоки UTF-8 — там используем цветные пробелы.
    if [[ ${TERM:-} == linux ]]; then qrencode -t ANSI "$sub"; else qrencode -t ANSIUTF8 "$sub"; fi
  fi
}

# ---------- команды ----------
cmd_install() {
  need_root
  local port=$DEFAULT_PORT sub_port=$DEFAULT_SUB_PORT sni=$DEFAULT_SNI name="user1" support=""
  while [[ $# -gt 0 ]]; do
    case $1 in
      --port)        port=$2;     shift 2 ;;
      --sub-port)    sub_port=$2; shift 2 ;;
      --sni)         sni=$2;      shift 2 ;;
      --name)        name=$2;     shift 2 ;;
      --support-url) support=$2;  shift 2 ;;
      *) die "неизвестный параметр: $1" ;;
    esac
  done
  valid_port "$port" || die "неверный порт: $port"
  valid_port "$sub_port" || die "неверный порт подписки: $sub_port"
  [[ $port != "$sub_port" ]] || die "порт VPN и порт подписки должны отличаться"
  [[ $name =~ ^[A-Za-z0-9_.-]+$ ]] || die "имя: только латиница, цифры, _ . -"
  installed && die "LastVN уже установлен. Для переустановки сначала: $0 uninstall"

  install_deps
  port_free "$port"
  port_free "$sub_port"
  install_xray
  tune_network

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
SUB_PORT=$sub_port
SNI=$sni
PUBLIC_KEY=$pub
SHORT_ID=$sid
XHTTP_PATH=$path
EOF
  chmod 600 "$STATE"
  : > "$TOKENS"
  add_token "$name"

  open_port "$port"
  open_port "$sub_port"
  systemctl enable xray >/dev/null 2>&1
  test_and_restart
  write_web "$ip" "$sub_port" "$support"
  rebuild_subs

  green "Готово! VLESS + XHTTP + Reality работает на $ip:$port (маскировка под $sni)"
  show_user "$name"
}

cmd_add() {
  need_root; need_installed
  local name=${1:-}; [[ -n $name ]] || die "укажи имя: $0 add <имя>"
  [[ $name =~ ^[A-Za-z0-9_.-]+$ ]] || die "имя: только латиница, цифры, _ . -"
  [[ -z $(user_uuid "$name") ]] || die "пользователь '$name' уже есть"
  local uuid; uuid=$("$XRAY_BIN" uuid)
  edit_config --arg n "$name" --arg id "$uuid" '.inbounds[0].settings.clients += [{id:$id, email:$n}]'
  test_and_restart
  add_token "$name"
  rebuild_subs
  show_user "$name"
}

cmd_del() {
  need_root; need_installed
  local name=${1:-}; [[ -n $name ]] || die "укажи имя: $0 del <имя>"
  [[ -n $(user_uuid "$name") ]] || die "пользователь '$name' не найден"
  [[ $(jq '.inbounds[0].settings.clients | length' "$CONFIG") -gt 1 ]] || die "нельзя удалить последнего пользователя"
  edit_config --arg n "$name" '.inbounds[0].settings.clients |= map(select(.email != $n))'
  test_and_restart
  local tmp; tmp=$(mktemp)
  awk -v n="$name" '$1!=n' "$TOKENS" > "$tmp" && mv "$tmp" "$TOKENS" && chmod 600 "$TOKENS"
  rebuild_subs
  green "Пользователь '$name' удалён"
}

cmd_list() {
  need_installed
  local name
  for name in $(jq -r '.inbounds[0].settings.clients[].email' "$CONFIG"); do
    printf '%-16s %s\n' "$name" "$(sub_url "$name")"
  done
}

cmd_link() {
  need_installed
  local name=${1:-}; [[ -n $name ]] || die "укажи имя: $0 link <имя>"
  show_user "$name"
}

cmd_status() {
  need_installed
  # shellcheck disable=SC1090
  source "$STATE"
  echo "Сервер:   $SERVER_IP:$PORT   SNI: $SNI   path: $XHTTP_PATH"
  echo "Подписки: http://$SERVER_IP:$SUB_PORT/sub/..."
  echo "Xray:     $("$XRAY_BIN" version | head -1)"
  echo "xray:     $(systemctl is-active xray)"
  echo "nginx:    $(systemctl is-active nginx)"
  if [[ -f $MTG_CONF ]]; then echo "mtg:      $(systemctl is-active mtg)   $(mtg_link)"; fi
}

# ---------- MTProto-прокси для Telegram (mtg, FakeTLS) ----------
MTG_BIN="/usr/local/bin/mtg"
MTG_CONF="/etc/mtg.toml"
MTG_UNIT="/etc/systemd/system/mtg.service"

install_mtg_bin() {
  local arch url tmp
  case $(uname -m) in
    x86_64|amd64)  arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "архитектура $(uname -m) не поддерживается для mtg" ;;
  esac
  url=$(curl -fsSL https://api.github.com/repos/9seconds/mtg/releases/latest 2>/dev/null \
        | jq -r --arg a "linux-$arch.tar.gz" '.assets[] | select(.name | endswith($a)) | .browser_download_url' 2>/dev/null | head -1 || true)
  if [[ -z $url ]]; then
    # Запасной путь без API: версия из редиректа /releases/latest -> /releases/tag/vX.Y.Z
    local tag
    tag=$(curl -fsSI https://github.com/9seconds/mtg/releases/latest | tr -d '\r' | sed -n 's#^[Ll]ocation:.*/tag/##p')
    [[ -n $tag ]] || die "не нашёл релиз mtg на GitHub"
    url="https://github.com/9seconds/mtg/releases/download/$tag/mtg-${tag#v}-linux-$arch.tar.gz"
  fi
  tmp=$(mktemp -d)
  curl -fsSL "$url" -o "$tmp/mtg.tar.gz"
  tar -xzf "$tmp/mtg.tar.gz" -C "$tmp"
  install -m 755 "$(find "$tmp" -type f -name mtg | head -1)" "$MTG_BIN"
  rm -rf "$tmp"
  "$MTG_BIN" --help >/dev/null 2>&1 || die "mtg не запускается"
}

mtg_link() {
  local secret port ip
  secret=$(sed -n 's/^secret *= *"\(.*\)"/\1/p' "$MTG_CONF")
  port=$(sed -n 's/^bind-to *= *".*:\([0-9]*\)"/\1/p' "$MTG_CONF")
  ip=$(sed -n 's/^SERVER_IP=//p' "$STATE" 2>/dev/null)
  [[ -n $ip ]] || ip=$(server_ip)
  echo "https://t.me/proxy?server=$ip&port=$port&secret=$secret"
}

show_mtg() {
  local link; link=$(mtg_link)
  echo
  green "MTProto-прокси для Telegram:"
  echo "  $link"
  echo
  if command -v qrencode >/dev/null; then
    if [[ ${TERM:-} == linux ]]; then qrencode -t ANSI "$link"; else qrencode -t ANSIUTF8 "$link"; fi
  fi
}

cmd_mtproto() {
  need_root
  local port=8443 domain="www.google.com"
  while [[ $# -gt 0 ]]; do
    case $1 in
      --port)   port=$2;   shift 2 ;;
      --domain) domain=$2; shift 2 ;;
      *) die "неизвестный параметр: $1" ;;
    esac
  done
  if [[ -f $MTG_CONF ]]; then
    show_mtg
    yellow "Прокси уже установлен. Пересоздать: $0 mtproto-remove, затем $0 mtproto"
    return
  fi
  valid_port "$port" || die "неверный порт: $port"
  command -v jq >/dev/null || install_deps
  port_free "$port"

  yellow "Устанавливаю mtg (MTProto-прокси)..."
  install_mtg_bin
  local secret; secret=$("$MTG_BIN" generate-secret --hex "$domain")
  [[ $secret == ee* ]] || die "не удалось сгенерировать секрет: $secret"

  cat > "$MTG_CONF" <<CONF
# LastVN: MTProto-прокси (FakeTLS под $domain)
secret = "$secret"
bind-to = "0.0.0.0:$port"
CONF
  chmod 644 "$MTG_CONF"   # mtg работает под DynamicUser; секрет всё равно уходит клиентам в ссылке

  cat > "$MTG_UNIT" <<UNIT
[Unit]
Description=LastVN MTProto proxy (mtg)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$MTG_BIN run $MTG_CONF
Restart=always
RestartSec=3
DynamicUser=true
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT
  open_port "$port"
  systemctl daemon-reload
  systemctl enable --now mtg >/dev/null 2>&1
  sleep 1
  systemctl is-active --quiet mtg || die "mtg не запустился: journalctl -u mtg -n 50"

  green "Готово! MTProto-прокси работает на порту $port (маскировка под $domain)"
  show_mtg
}

cmd_mtproto_remove() {
  need_root
  systemctl disable --now mtg 2>/dev/null || true
  rm -f "$MTG_UNIT" "$MTG_CONF" "$MTG_BIN"
  systemctl daemon-reload
  green "MTProto-прокси удалён"
}

cmd_tune() {
  need_root
  tune_network
  systemctl restart xray 2>/dev/null || true
  green "Сеть настроена: $(sysctl -n net.ipv4.tcp_congestion_control), TCP-буферы до 64 МБ"
}

cmd_uninstall() {
  need_root
  read -r -p "Удалить Xray, подписки и все ключи пользователей? [y/N] " ans
  [[ $ans =~ ^[Yy]$ ]] || exit 0
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge || true
  if [[ -f $MTG_CONF ]]; then cmd_mtproto_remove; fi
  rm -rf "$XRAY_DIR" "$WEB" "$NGINX_CONF" /etc/sysctl.d/99-lastvn.conf /etc/sysctl.d/99-lastvn-bbr.conf /etc/systemd/system/xray.service.d/99-lastvn.conf
  systemctl reload nginx 2>/dev/null || true
  green "LastVN удалён (nginx оставлен как пакет)"
}

usage() { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; }

# ---------- логотип (assets/logo.png, встроен в base64) ----------
write_logo() {
  base64 -d > "$1" <<'LOGO'
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
LOGO
}

case ${1:-} in
  install)   shift; cmd_install "$@" ;;
  add)       shift; cmd_add "$@" ;;
  del)       shift; cmd_del "$@" ;;
  list)      cmd_list ;;
  link)      shift; cmd_link "$@" ;;
  status)    cmd_status ;;
  tune)      cmd_tune ;;
  mtproto)   shift; cmd_mtproto "$@" ;;
  mtproto-remove) cmd_mtproto_remove ;;
  uninstall) cmd_uninstall ;;
  *)         usage ;;
esac
