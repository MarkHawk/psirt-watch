#!/usr/bin/env bash
# deploy.sh — install PSIRT Watch (poller + dashboard) as systemd services.
# Run ON the Ubuntu box, from the directory holding the project files:
#     ./deploy.sh [PORT]        (default PORT 8080)
# Re-runnable: safe to run again after editing files (re-copies, restarts).
set -euo pipefail

PORT="${1:-8080}"
APP_DIR="$HOME/psirt-watch"
RUN_USER="$(id -un)"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> Deploying PSIRT Watch"
echo "    user:      $RUN_USER"
echo "    directory: $APP_DIR"
echo "    port:      $PORT"

# --- 1. project directory + files ---------------------------------------
mkdir -p "$APP_DIR"
for f in psirt_fetch.py dashboard.html; do
  if [ ! -f "$SRC_DIR/$f" ]; then
    echo "!! missing $f in $SRC_DIR — copy the project files here first" >&2
    exit 1
  fi
done
if [ "$SRC_DIR" != "$APP_DIR" ]; then
  cp "$SRC_DIR/psirt_fetch.py" "$SRC_DIR/dashboard.html" "$APP_DIR/"
  [ -f "$SRC_DIR/README.md" ] && cp "$SRC_DIR/README.md" "$APP_DIR/" || true
fi

# --- 2. venv (no external deps, but keeps to the venv convention) --------
if [ ! -x "$APP_DIR/venv/bin/python3" ]; then
  echo "==> creating venv"
  python3 -m venv "$APP_DIR/venv"
fi
VENV_PY="$APP_DIR/venv/bin/python3"

# --- 3. credentials file (600) ------------------------------------------
if [ ! -f "$APP_DIR/psirt.env" ]; then
  cat > "$APP_DIR/psirt.env" <<'EOF'
# Cisco API Console credentials (grant type: Client Credentials)
CISCO_CLIENT_ID=
CISCO_CLIENT_SECRET=
EOF
  chmod 600 "$APP_DIR/psirt.env"
  echo "==> created $APP_DIR/psirt.env — EDIT IT with your Client ID/Secret before the poller will work"
fi

# --- 4. systemd units (generated for this user/dir/port) ----------------
echo "==> installing systemd units (sudo)"
sudo tee /etc/systemd/system/psirt-fetch.service >/dev/null <<EOF
[Unit]
Description=PSIRT Watch - Cisco openVuln advisory poller
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_DIR/psirt.env
ExecStart=$VENV_PY $APP_DIR/psirt_fetch.py --interval 30 --mode firstpublished --days 14 --out $APP_DIR/advisories.json
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/psirt-dashboard.service >/dev/null <<EOF
[Unit]
Description=PSIRT Watch - static dashboard server
After=network-online.target

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$APP_DIR
ExecStart=$VENV_PY -m http.server $PORT --directory $APP_DIR
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# --- 5. start ------------------------------------------------------------
sudo systemctl daemon-reload
sudo systemctl enable --now psirt-fetch.service psirt-dashboard.service
sudo systemctl restart psirt-fetch.service psirt-dashboard.service

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
echo "==> Done."
echo "    Dashboard: http://${IP:-<box-ip>}:$PORT/dashboard.html"
echo "    Logs:      journalctl -u psirt-fetch -f"
echo "               journalctl -u psirt-dashboard -f"
echo
if grep -q 'CISCO_CLIENT_ID=$' "$APP_DIR/psirt.env" 2>/dev/null; then
  echo "    NOTE: psirt.env still empty — add your creds then:"
  echo "          sudo systemctl restart psirt-fetch"
fi
