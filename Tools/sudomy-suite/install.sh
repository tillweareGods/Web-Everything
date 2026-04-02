#!/usr/bin/env bash
# ============================================================
#  install.sh — Sudomy v2.0 dependency installer
#  Supports: Debian/Ubuntu, Arch, macOS (Homebrew)
# ============================================================

set -e

RESET="\033[0m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
CYAN="\033[1;36m"
BOLD="\033[01;01m"

ok()   { echo -e "${GREEN}[✓]${RESET} $*"; }
warn() { echo -e "${YELLOW}[~]${RESET} $*"; }
err()  { echo -e "${RED}[!]${RESET} $*"; }
info() { echo -e "${CYAN}[*]${RESET} $*"; }

echo -e "${BOLD}"
echo "  ╔══════════════════════════════════════╗"
echo "  ║   Sudomy v2.0 — Installer            ║"
echo "  ╚══════════════════════════════════════╝"
echo -e "${RESET}"

# ── Detect OS ────────────────────────────────────────────────────────────────

OS="unknown"
if [[ "$(uname)" == "Darwin" ]]; then
  OS="macos"
elif [[ -f /etc/debian_version ]]; then
  OS="debian"
elif [[ -f /etc/arch-release ]]; then
  OS="arch"
elif [[ -f /etc/redhat-release ]]; then
  OS="rhel"
fi

info "Detected OS: ${OS}"

# ── System package installer ─────────────────────────────────────────────────

install_system_packages() {
  case "${OS}" in
  debian)
    info "Installing system packages via apt..."
    sudo apt-get update -qq
    sudo apt-get install -y \
      curl jq nmap dig python3 python3-pip \
      git wget build-essential 2>/dev/null
    ok "System packages installed"
    ;;
  arch)
    sudo pacman -Sy --noconfirm \
      curl jq nmap python python-pip bind-tools git wget 2>/dev/null
    ok "System packages installed"
    ;;
  macos)
    if command -v brew &>/dev/null; then
      brew install curl jq nmap python3 git wget 2>/dev/null || true
      ok "Homebrew packages installed"
    else
      warn "Homebrew not found. Install from https://brew.sh"
    fi
    ;;
  *)
    warn "Unknown OS — please install manually: curl jq nmap python3 dig git"
    ;;
  esac
}

# ── Go tools ─────────────────────────────────────────────────────────────────

install_go() {
  if command -v go &>/dev/null; then
    ok "Go already installed: $(go version)"
    return
  fi
  info "Installing Go..."
  GO_VERSION="1.22.3"
  GOARCH="amd64"
  [[ "$(uname -m)" == "arm64" || "$(uname -m)" == "aarch64" ]] && GOARCH="arm64"
  GOOS="linux"
  [[ "${OS}" == "macos" ]] && GOOS="darwin"

  wget -q "https://go.dev/dl/go${GO_VERSION}.${GOOS}-${GOARCH}.tar.gz" -O /tmp/go.tar.gz
  sudo tar -C /usr/local -xzf /tmp/go.tar.gz
  rm -f /tmp/go.tar.gz

  # Add to PATH if not already there
  if ! grep -q '/usr/local/go/bin' ~/.bashrc 2>/dev/null; then
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
  fi
  export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
  ok "Go installed"
}

install_go_tool() {
  local name="${1}" pkg="${2}"
  if command -v "${name}" &>/dev/null; then
    ok "${name} already installed"
    return
  fi
  info "Installing ${name}..."
  GOPATH="${HOME}/go" go install "${pkg}" 2>/dev/null && ok "${name} installed" || warn "Failed to install ${name}"
}

# ── Python packages ───────────────────────────────────────────────────────────

install_python_packages() {
  info "Installing Python packages..."
  pip3 install --break-system-packages --quiet \
    aiodns \
    requests \
    censys \
    PyYAML \
    2>/dev/null || \
  pip3 install --quiet \
    aiodns \
    requests \
    censys \
    PyYAML \
    2>/dev/null
  ok "Python packages installed"
}

# ── Run installation ──────────────────────────────────────────────────────────

info "Step 1/4: System packages"
install_system_packages

info "Step 2/4: Go runtime"
install_go

info "Step 3/4: Go tools"
install_go_tool "httprobe"   "github.com/tomnomnom/httprobe@latest"
install_go_tool "httpx"      "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "dnsx"       "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_go_tool "gobuster"   "github.com/OJ/gobuster/v3@latest"
install_go_tool "gowitness"  "github.com/sensepost/gowitness@latest"
install_go_tool "subfinder"  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"

info "Step 4/4: Python packages"
install_python_packages

# ── Final permissions ─────────────────────────────────────────────────────────

chmod +x "$(dirname "$0")/sudomy"
chmod +x "$(dirname "$0")/lib/"*.py 2>/dev/null || true
chmod +x "$(dirname "$0")/engine/"*.my 2>/dev/null || true

echo -e "\n${BOLD}${GREEN}════════════════════════════════════════════${RESET}"
echo -e "${GREEN}  Sudomy v2.0 installation complete!${RESET}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════${RESET}\n"
echo "  Next steps:"
echo "  1. Edit sudomy.api  → add your API keys"
echo "  2. Run: ./sudomy -d example.com"
echo "  3. Full scan: ./sudomy -d example.com --all --httpx --dnsx -rS -tO"
echo ""
