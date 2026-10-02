#!/bin/bash
# Install optional pentest binaries — failures are non-fatal.
set -u

install_pd_zip() {
  local tool="$1"
  echo "Installing ${tool}..."
  local json url
  json=$(curl -fsSL "https://api.github.com/repos/projectdiscovery/${tool}/releases/latest" || return 0)
  url=$(echo "$json" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    for asset in data.get('assets', []):
        u = asset.get('browser_download_url', '')
        if 'linux_amd64.zip' in u:
            print(u)
            break
except Exception:
    pass
" || true)
  if [ -z "$url" ]; then
    echo "WARN: no release asset found for ${tool}, skipping"
    return 0
  fi
  curl -fsSL "$url" -o "/tmp/${tool}.zip" || return 0
  unzip -o "/tmp/${tool}.zip" -d /usr/local/bin/ || return 0
  chmod +x "/usr/local/bin/${tool}" 2>/dev/null || true
  rm -f "/tmp/${tool}.zip"
  echo "OK: ${tool}"
}

install_dalfox() {
  echo "Installing dalfox..."
  local json url
  json=$(curl -fsSL "https://api.github.com/repos/hahwul/dalfox/releases/latest" || return 0)
  url=$(echo "$json" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    for asset in data.get('assets', []):
        u = asset.get('browser_download_url', '')
        if 'linux_amd64' in u and u.endswith('.tar.gz'):
            print(u)
            break
except Exception:
    pass
" || true)
  if [ -z "$url" ]; then
    echo "WARN: dalfox release not found, skipping"
    return 0
  fi
  curl -fsSL "$url" -o /tmp/dalfox.tar.gz || return 0
  tar -xzf /tmp/dalfox.tar.gz -C /usr/local/bin/ 2>/dev/null || true
  chmod +x /usr/local/bin/dalfox 2>/dev/null || true
  rm -f /tmp/dalfox.tar.gz
  echo "OK: dalfox"
}

install_amass() {
  echo "Installing amass..."
  local json url
  json=$(curl -fsSL "https://api.github.com/repos/owasp-amass/amass/releases/latest" || true)
  url=$(echo "$json" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    for asset in data.get('assets', []):
        u = asset.get('browser_download_url', '')
        if 'amass_linux_amd64' in u and u.endswith('.zip'):
            print(u)
            break
except Exception:
    pass
" 2>/dev/null || true)
  # Fallback to known stable release if API lookup fails
  if [ -z "$url" ]; then
    url="https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_linux_amd64.zip"
  fi
  curl -fsSL "$url" -o /tmp/amass.zip || return 0
  unzip -o /tmp/amass.zip -d /tmp/amass_extracted/ 2>/dev/null || return 0
  find /tmp/amass_extracted -name "amass" -type f -exec cp {} /usr/local/bin/amass \; 2>/dev/null || true
  chmod +x /usr/local/bin/amass 2>/dev/null || true
  rm -rf /tmp/amass.zip /tmp/amass_extracted/
  echo "OK: amass"
}

install_gau() {
  echo "Installing gau..."
  local json url
  json=$(curl -fsSL "https://api.github.com/repos/lc/gau/releases/latest" || return 0)
  url=$(echo "$json" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    for asset in data.get('assets', []):
        u = asset.get('browser_download_url', '')
        if 'linux_amd64' in u and u.endswith('.tar.gz'):
            print(u)
            break
except Exception:
    pass
" || true)
  if [ -z "$url" ]; then
    echo "WARN: gau release not found, skipping"
    return 0
  fi
  curl -fsSL "$url" -o /tmp/gau.tar.gz || return 0
  tar -xzf /tmp/gau.tar.gz -C /usr/local/bin/ 2>/dev/null || true
  chmod +x /usr/local/bin/gau 2>/dev/null || true
  rm -f /tmp/gau.tar.gz
  echo "OK: gau"
}

install_pd_zip subfinder
install_pd_zip httpx
install_pd_zip nuclei
install_pd_zip katana
install_dalfox
install_amass
install_gau

echo "Tool install script finished."
