#!/usr/bin/env bash
# Renders the portal's logo files from portal/branding/logo.html with headless
# Chrome: the sign-in page header logos (light and dark, used by portal.tf)
# and the favicon (portal/public/favicon.ico, also used by the sign-in pages).
# Run it after changing logo.html, then terraform apply and
# scripts/portal-deploy.sh.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
src="$root/portal/branding/logo.html"
out="$root/portal/branding"
chrome="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"

shot() { # <file> <width> <height> <query> <scale>
  "$chrome" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor="$5" \
    --default-background-color=00000000 --window-size="$2,$3" \
    --screenshot="$1" "file://$src?$4" >/dev/null 2>&1
}

# Header logos at exactly 200x60: Cognito refuses larger ones.
shot "$out/header-logo-light.png" 200 60 "mode=light" 1
shot "$out/header-logo-dark.png" 200 60 "mode=dark" 1
mark="$(mktemp -t mark).png"
trap 'rm -f "$mark"' EXIT
shot "$mark" 64 64 "mark=1" 2

# An .ico holding one 128x128 PNG (browsers accept PNG inside ICO).
python3 -I - "$mark" "$root/portal/public/favicon.ico" <<'PY'
import struct, sys
png = open(sys.argv[1], "rb").read()
# ICONDIR, then one ICONDIRENTRY: width/height 0 means 256 or more; 128 fits a byte.
entry = struct.pack("<BBBBHHII", 128, 128, 0, 0, 1, 32, len(png), 6 + 16)
open(sys.argv[2], "wb").write(struct.pack("<HHH", 0, 1, 1) + entry + png)
PY
ls -l "$out"/*.png "$root/portal/public/favicon.ico"
