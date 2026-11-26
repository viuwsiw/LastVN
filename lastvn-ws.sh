#!/usr/bin/env bash
set -euo pipefail

readonly WS_DIR=/etc/lastvn-ws
readonly WS_UNIT=/etc/systemd/system/lastvn-ws.service
readonly WS_NGINX=/etc/nginx/conf.d/lastvn-ws.conf
readonly WS_CERT=/etc/letsencrypt/live/lastvn-ws
readonly XRAY_BIN=/usr/local/bin/xray
readonly WS_BACKEND=10081
readonly DEFAULT_PORT=9444

die() { printf 'Ошибка: %s\n' "$*" >&2; exit 1; }

show_link() {
  local domain port uuid path
  IFS=$'\t' read -r domain port uuid path < "$WS_DIR/profile.tsv"
  printf 'vless://%s@%s:%s?encryption=none&security=tls&sni=%s&type=ws&host=%s&path=%%2F%s#LastVN-WS\n' \
    "$uuid" "$domain" "$port" "$domain" "$domain" "${path#/}"
}

port_free() {
  [[ -z $(ss -Hltn "sport = :$1") ]] || die "TCP-порт $1 уже занят"
}

open_port() {
  local port=$1
  if command -v ufw >/dev/null && LC_ALL=C ufw status | grep -qx 'Status: active'; then
    ufw allow "$port/tcp"
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$port/tcp"
    firewall-cmd --reload
  fi
}

write_xray() {
  local uuid=$1 path=$2
  jq -n --arg uuid "$uuid" --arg path "$path" --argjson port "$WS_BACKEND" '
    {
      log: {loglevel: "warning"},
      inbounds: [{
        listen: "127.0.0.1", port: $port, protocol: "vless",
        settings: {clients: [{id: $uuid}], decryption: "none"},
        streamSettings: {network: "ws", wsSettings: {path: $path}}
      }],
      outbounds: [{tag: "direct", protocol: "freedom"}, {tag: "block", protocol: "blackhole"}],
      routing: {domainStrategy: "IPOnDemand", rules: [
        {type: "field", ip: ["geoip:private"], outboundTag: "block"}
      ]}
    }' > "$WS_DIR/config.json"
}

write_nginx() {
  local domain=$1 port=$2 path=$3
  cat > "$WS_NGINX" <<NGINX
server {
    listen $port ssl;
    listen [::]:$port ssl;
    server_name $domain;
    ssl_certificate $WS_CERT/fullchain.pem;
    ssl_certificate_key $WS_CERT/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    server_tokens off;

    location = $path {
        proxy_pass http://127.0.0.1:$WS_BACKEND;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }

    location / { return 404; }
}
NGINX
}

rollback() {
  local rc=$?
  if (( rc != 0 )); then
    systemctl disable --now lastvn-ws.service >/dev/null 2>&1 || true
    rm -f "$WS_UNIT" "$WS_NGINX" "$WS_DIR/config.json" "$WS_DIR/profile.tsv"
    rmdir "$WS_DIR" 2>/dev/null || true
    systemctl daemon-reload || true
    nginx -t && systemctl reload nginx || true
  fi
}

install_ws() {
  local domain=${1:-} port=${2:-$DEFAULT_PORT}
  local ip uuid path current_domain current_port
  [[ ! -f $WS_DIR/profile.tsv ]] || {
    IFS=$'\t' read -r current_domain current_port _ < "$WS_DIR/profile.tsv"
    [[ -z $domain || $domain == "$current_domain" ]] || die "профиль уже установлен для $current_domain"
    [[ $# -lt 2 || $port == "$current_port" ]] || die "профиль уже установлен на порту $current_port"
    show_link
    return
  }
  [[ ! -e $WS_DIR && ! -e $WS_UNIT && ! -e $WS_NGINX ]] || die "найдены файлы предыдущей установки LastVN WS"
  [[ -x $XRAY_BIN ]] || die "требуется установленный Xray ($XRAY_BIN)"
  command -v jq >/dev/null && command -v openssl >/dev/null || die "требуются jq и openssl"
  systemctl is-active --quiet nginx || die "требуется работающий nginx"
  if [[ -z $domain ]]; then
    ip=$(sed -n 's/^SERVER_IP=//p' /usr/local/etc/xray/lastvn.env 2>/dev/null || true)
    [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "передай домен, который указывает на VPS"
    domain="${ip//./-}.sslip.io"
  fi
  [[ ${#domain} -le 253 && $domain =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$ ]] \
    || die "укажи домен в нижнем регистре, без https://"
  [[ $port =~ ^[1-9][0-9]{0,4}$ && $port -le 65535 && $port != 80 && $port != "$WS_BACKEND" ]] \
    || die "неверный порт TLS"
  port_free "$port"
  port_free "$WS_BACKEND"
  nginx -t

  if ! command -v certbot >/dev/null || ! certbot plugins 2>/dev/null | grep -xF '* nginx' >/dev/null; then
    command -v apt-get >/dev/null || die "установи certbot с плагином nginx"
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y certbot python3-certbot-nginx
  fi
  open_port 80
  certbot certonly --nginx --cert-name lastvn-ws -d "$domain" --keep-until-expiring \
    --agree-tos --register-unsafely-without-email --non-interactive --deploy-hook 'systemctl reload nginx'
  [[ -r $WS_CERT/fullchain.pem && -r $WS_CERT/privkey.pem ]] || die "сертификат не найден в $WS_CERT"

  umask 077
  uuid=$("$XRAY_BIN" uuid)
  path="/$(openssl rand -hex 12)"
  mkdir "$WS_DIR"
  trap rollback EXIT
  write_xray "$uuid" "$path"
  "$XRAY_BIN" run -test -c "$WS_DIR/config.json"
  cat > "$WS_UNIT" <<UNIT
[Unit]
Description=LastVN VLESS WebSocket
After=network.target

[Service]
Type=exec
DynamicUser=true
LoadCredential=config.json:$WS_DIR/config.json
Environment=XRAY_LOCATION_ASSET=/usr/local/share/xray
ExecStart=$XRAY_BIN run -c %d/config.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
  chmod 644 "$WS_UNIT"
  systemctl daemon-reload
  systemctl enable --now lastvn-ws.service

  write_nginx "$domain" "$port" "$path"
  nginx -t
  systemctl reload nginx
  open_port "$port"
  printf '%s\t%s\t%s\t%s\n' "$domain" "$port" "$uuid" "$path" > "$WS_DIR/profile.tsv"
  trap - EXIT
  show_link
}

[[ $EUID -eq 0 ]] || die "запусти через sudo или под root"
case ${1:-} in
  install) shift; [[ $# -le 2 ]] || die "использование: $0 install [домен] [порт]"; install_ws "$@" ;;
  link) [[ -r $WS_DIR/profile.tsv ]] || die "сначала выполни install"; show_link ;;
  *) printf 'Использование: %s install [домен] [порт] | link\n' "$0"; exit 2 ;;
esac
