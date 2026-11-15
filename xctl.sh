#!/usr/bin/env bash
# xctl - kontrol server xapi + tunnel Cloudflare (Armbian/Debian). Jalankan sebagai root.
# Pertama kali:  sudo bash xctl.sh install   (xapi.py harus satu folder dengan file ini)
D=/opt/xapi; E=/etc/xapi; PY="python3 $D/xapi.py"
[ "$EUID" -eq 0 ] || { echo "Jalankan sebagai root: sudo xctl"; exit 1; }
port() { $PY config | awk '$1=="port"{print $2}'; }

install_all() {
  apt-get update -qq && apt-get install -y -qq python3 curl ca-certificates || return 1
  mkdir -p $D $E /var/lib/xapi
  cp "$(dirname "$(readlink -f "$0")")/xapi.py" $D/xapi.py
  install -m755 "$(readlink -f "$0")" /usr/local/bin/xctl
  cat > /etc/systemd/system/xapi.service <<EOF
[Unit]
Description=xapi (API + database JSON)
After=network.target
[Service]
ExecStart=/usr/bin/python3 $D/xapi.py run
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload && systemctl enable --now xapi
  echo "Server jalan di port $(port). Kunci admin & pengaturan: xctl config"
  echo "Lanjut: xctl tunnel token   (pasang tunnel Cloudflare)"
}

tunnel_token() {
  if ! command -v cloudflared >/dev/null; then
    case "$(uname -m)" in aarch64|arm64) A=arm64;; armv7l|armv6l|armhf) A=arm;; x86_64) A=amd64;; *) echo "CPU tidak didukung"; return 1;; esac
    curl -fL "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$A" -o /usr/local/bin/cloudflared \
      && chmod +x /usr/local/bin/cloudflared || { echo "Gagal mengunduh cloudflared"; return 1; }
  fi
  read -rsp "Tempel token tunnel (atau seluruh perintah 'cloudflared service install ...'): " IN; echo
  T=$(grep -oE 'eyJ[A-Za-z0-9_=+/-]+' <<<"$IN" | head -1)
  [ -n "$T" ] || { echo "Token tidak ditemukan."; return 1; }
  ( umask 077; echo "TUNNEL_TOKEN=$T" > $E/tunnel.env )
  cat > /etc/systemd/system/xtunnel.service <<EOF
[Unit]
Description=Cloudflare Tunnel
After=network-online.target
Wants=network-online.target
[Service]
EnvironmentFile=$E/tunnel.env
ExecStart=/usr/local/bin/cloudflared tunnel --no-autoupdate run
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload && systemctl enable --now xtunnel
  echo "Tunnel aktif. Di Cloudflare Zero Trust > Networks > Tunnels > tunnel-mu > Public Hostname:"
  echo "  api.mypnk.web.id  ->  HTTP  ->  localhost:$(port)"
}

menu() {
  while true; do
    echo; echo "== xctl =="
    echo "server: $(systemctl is-active xapi) | tunnel: $(systemctl is-active xtunnel 2>/dev/null) | panel: $($PY config | awk '$1=="panel"{print $2}')"
    echo " 1) Hidupkan server     2) Matikan server    3) Restart server    4) Log server"
    echo " 5) Pasang/ganti token tunnel"
    echo " 6) Aktifkan tunnel     7) Nonaktifkan tunnel   8) Restart tunnel"
    echo " 9) Panel ON           10) Panel OFF           11) Lihat/ubah pengaturan   0) Keluar"
    read -rp "Pilih: " n
    case $n in
      1) systemctl start xapi;; 2) systemctl stop xapi;; 3) systemctl restart xapi;; 4) journalctl -u xapi -n 40 --no-pager;;
      5) tunnel_token;; 6) systemctl enable --now xtunnel;; 7) systemctl disable --now xtunnel;; 8) systemctl restart xtunnel;;
      9) $PY config set panel true;; 10) $PY config set panel false;;
      11) $PY config; read -rp "Kunci (kosong = batal): " k; [ -n "$k" ] && { read -rp "Nilai: " v; $PY config set "$k" "$v"; echo "Restart server bila mengubah host/port."; };;
      0) exit;;
    esac
  done
}

case "$1" in
  install) install_all;;
  start|stop|restart|status) systemctl "$1" xapi --no-pager;;
  log) journalctl -u xapi -f;;
  tunnel) case "$2" in
    token) tunnel_token;; on) systemctl enable --now xtunnel;; off) systemctl disable --now xtunnel;;
    restart) systemctl restart xtunnel;; status) systemctl status xtunnel --no-pager;; *) echo "xctl tunnel token|on|off|restart|status";; esac;;
  panel) [ "$2" = on ] && $PY config set panel true || $PY config set panel false;;
  config) shift; $PY config "$@";;
  *) menu;;
esac
