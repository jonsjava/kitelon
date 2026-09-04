#!/bin/bash
# Cross-platform install script for Kitelon
# Supports: Debian/Ubuntu, RHEL/CentOS/Fedora/Amazon Linux, Arch Linux, macOS

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/bin/kitelon_ui.sh"
source "$SCRIPT_DIR/bin/banner.sh"
kitelon_banner
echo ""
kl_msg_info "Kitelon installer"
kl_msg_info "Multi-distro support"
echo ""

# Installation directories
INSTALL_DIR=/usr/share/kitelon
LOOT_DIR=/usr/share/kitelon/loot
PLUGINS_DIR=/usr/share/kitelon/plugins
GO_DIR=~/go/bin
KITELON_GO_VERSION="1.27.0"
IS_KALI=0
DISTRO_ID=""

# Detect OS and distribution
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        kl_msg_info "Detected macOS"
    elif [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO_ID="$ID"
        case "$ID" in
            kali)
                IS_KALI=1
                OS="debian"
                PKG_MANAGER="apt"
                kl_msg_info "Detected Kali Linux: $PRETTY_NAME"
                ;;
            ubuntu|debian|parrot|pop)
                OS="debian"
                PKG_MANAGER="apt"
                kl_msg_info "Detected Debian-based system: $PRETTY_NAME"
                ;;
            rhel|centos|fedora|rocky|alma|amzn)
                OS="rhel"
                if command -v dnf &> /dev/null; then
                    PKG_MANAGER="dnf"
                else
                    PKG_MANAGER="yum"
                fi
                kl_msg_info "Detected RHEL-based system: $PRETTY_NAME"
                ;;
            arch|manjaro|endeavouros)
                OS="arch"
                PKG_MANAGER="pacman"
                kl_msg_info "Detected Arch-based system: $PRETTY_NAME"
                ;;
            opensuse*|sles)
                OS="opensuse"
                PKG_MANAGER="zypper"
                kl_msg_info "Detected openSUSE-based system: $PRETTY_NAME"
                ;;
            *)
                kl_msg_err "Unsupported distribution: $ID"
                kl_msg_err "Supported: Debian/Ubuntu, RHEL/CentOS/Fedora, Arch Linux, macOS"
                exit 1
                ;;
        esac
    else
        kl_msg_err "Unable to detect operating system"
        exit 1
    fi
}

# Check if running as root (not needed for macOS with brew)
check_root() {
    if [[ "$OS" != "macos" ]] && [[ $EUID -ne 0 ]]; then
        kl_msg_err "This script must be run as root on Linux systems"
        kl_msg_err "Please run: sudo $0"
        exit 1
    fi
}

# Package manager abstraction
pkg_update() {
    kl_msg_info "Updating package repositories..."
    local rc=0
    case "$OS" in
        debian)
            run_quiet "apt update failed" apt-get update -qq || rc=1
            ;;
        rhel)
            run_quiet "package cache update failed" $PKG_MANAGER makecache -y -q \
                || run_quiet "package cache update failed" $PKG_MANAGER makecache || rc=1
            ;;
        arch)
            run_quiet "pacman sync failed" pacman -Sy --noconfirm || rc=1
            ;;
        opensuse)
            run_quiet "zypper refresh failed" zypper -q refresh -y || rc=1
            ;;
        macos)
            run_quiet "brew update failed" brew update || rc=1
            ;;
    esac
    if [[ $rc -eq 0 ]]; then
        kl_msg_ok "Package repositories updated"
    fi
}

warn_optional() {
    kl_msg_warn "$* (optional: continuing)"
}

kitelon_tmpfile() {
    mktemp /tmp/kitelon-run.XXXXXX 2>/dev/null || echo "/tmp/kitelon-run.$$"
}

# Print error lines from captured command output (fallback: last few lines).
kitelon_show_cmd_errors() {
    local file="$1"
    [[ -s "$file" ]] || return 0
    local lines
    lines=$(grep -iE '(^ERROR|^E: |^Err:|^error:|fatal:|FAILED|Cannot |Unable to|not found|command not found|No package)' "$file" \
        | grep -v -E '^DEPRECATION:|^WARNING: Running pip' \
        | head -20 || true)
    if [[ -n "$lines" ]]; then
        echo "$lines" | sed 's/^/    /'
    else
        tail -8 "$file" | sed 's/^/    /'
    fi
}

# Run a command silently; emit errors only on failure.
run_quiet() {
    local desc="$1"
    shift
    local out rc=0
    out=$(kitelon_tmpfile)
    "$@" >"$out" 2>&1 || rc=$?
    if [[ $rc -ne 0 ]]; then
        kl_msg_err "$desc"
        kitelon_show_cmd_errors "$out"
    fi
    rm -f "$out"
    return $rc
}

kitelon_pip_filter_noise() {
    grep -v -E \
        '^DEPRECATION: Loading egg at|^WARNING: Running pip as the ('\''root'\'' )?user|It is recommended to use a virtual environment instead:|^Requirement already satisfied:|^Collecting |^Downloading |^Installing collected packages:|^Successfully installed |^Using cached ' \
        || true
}

kitelon_pip_install() {
    local out rc=0
    out=$(kitelon_tmpfile)
    PIP_ROOT_USER_ACTION=ignore pip3 "$@" >"$out" 2>&1 || rc=$?
    if [[ $rc -ne 0 ]]; then
        kitelon_pip_filter_noise < "$out" | sed 's/^/    /'
    fi
    rm -f "$out"
    return $rc
}

pip_install_pkg() {
    local pkg="$1"
    kl_msg_info "pip install $pkg"
    if kitelon_pip_install install "$pkg" --break-system-packages \
        || kitelon_pip_install install "$pkg" --break-system-packages --user; then
        kl_msg_ok "pip install $pkg"
        return 0
    fi
    return 1
}

_pkg_install_run() {
    local packages=("$@")
    case "$OS" in
        debian)
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${packages[@]}"
            ;;
        rhel)
            $PKG_MANAGER install -y -q "${packages[@]}"
            ;;
        arch)
            pacman -S --noconfirm --needed "${packages[@]}"
            ;;
        opensuse)
            zypper -q install -y "${packages[@]}"
            ;;
        macos)
            for pkg in "${packages[@]}"; do
                brew install "$pkg" 2>/dev/null || brew upgrade "$pkg"
            done
            ;;
    esac
}

pkg_install() {
    local packages=("$@")
    kl_msg_info "Installing: ${packages[*]}"
    if run_quiet "Package install failed: ${packages[*]}" _pkg_install_run "${packages[@]}"; then
        kl_msg_ok "${packages[*]}"
        return 0
    fi
    return 1
}

pkg_install_optional() {
    local packages=("$@")
    kl_msg_info "Installing (optional): ${packages[*]}"
    local out rc=0
    out=$(kitelon_tmpfile)
    _pkg_install_run "${packages[@]}" >"$out" 2>&1 || rc=$?
    if [[ $rc -eq 0 ]]; then
        kl_msg_ok "${packages[*]}"
    else
        warn_optional "Package install failed: ${packages[*]}"
        kitelon_show_cmd_errors "$out"
    fi
    rm -f "$out"
}

run_optional() {
    local desc="$1"
    shift
    kl_msg_info "$desc"
    local out rc=0
    out=$(kitelon_tmpfile)
    "$@" >"$out" 2>&1 || rc=$?
    if [[ $rc -eq 0 ]]; then
        kl_msg_ok "$desc"
    else
        warn_optional "$desc"
        kitelon_show_cmd_errors "$out"
    fi
    rm -f "$out"
    return 0
}

git_clone_quiet() {
    local url="$1"
    local dest="${2:-}"
    if [[ -n "$dest" ]]; then
        git clone -q "$url" "$dest"
    else
        git clone -q "$url"
    fi
}

git_clone_optional() {
    local label="$1"
    local url="$2"
    shift 2
    local out rc=0
    out=$(kitelon_tmpfile)
    git_clone_quiet "$url" "$@" >"$out" 2>&1 || rc=$?
    if [[ $rc -eq 0 ]]; then
        kl_msg_ok "$label"
        return 0
    fi
    warn_optional "$label"
    kitelon_show_cmd_errors "$out"
    rm -f "$out"
    return 1
}

# Pull latest for an existing plugin clone, or clone if missing.
kitelon_git_sync() {
    local label="$1"
    local url="$2"
    local dest="$3"
    local branch="${4:-}"

    if [[ -d "$dest/.git" ]]; then
        kl_msg_info "Updating $label..."
        git -C "$dest" pull --ff-only 2>/dev/null \
            || warn_optional "$label git update failed (existing clone left in place)"
        return 0
    fi
    if [[ ! -d "$dest" ]]; then
        if [[ -n "$branch" ]]; then
            git_clone_optional "$label" "$url" "$dest" -b "$branch" --depth 1
        else
            git_clone_optional "$label" "$url" "$dest" --depth 1
        fi
    fi
}

py_setup_install_optional() {
    local label="$1"
    local out rc=0
    out=$(kitelon_tmpfile)
    python3 setup.py install >"$out" 2>&1 || rc=$?
    if [[ $rc -eq 0 ]]; then
        kl_msg_ok "$label"
        rm -f "$out"
        return 0
    fi
    warn_optional "$label"
    kitelon_show_cmd_errors "$out"
    rm -f "$out"
    return 1
}

# When the installer runs via sudo, return the invoking user (not root).
kitelon_install_user() {
    local user="${SUDO_USER:-}"

    if [[ -n "$user" && "$user" != "root" ]]; then
        echo "$user"
        return 0
    fi

    if [[ $EUID -ne 0 ]]; then
        echo "${USER:-$(id -un)}"
        return 0
    fi

    user=$(logname 2>/dev/null || true)
    if [[ -n "$user" && "$user" != "root" ]]; then
        echo "$user"
        return 0
    fi

    return 1
}

run_as_install_user() {
    local desc="$1"
    shift

    if [[ $EUID -ne 0 ]]; then
        run_optional "$desc" "$@"
        return 0
    fi

    local install_user
    install_user=$(kitelon_install_user) || {
        kl_msg_warn "Cannot determine non-root user for: $desc"
        kl_msg_warn "Run manually as your user: $*"
        return 1
    }

    run_optional "$desc (as $install_user)" sudo -u "$install_user" -H "$@"
}

# Map package names across distributions
get_package_name() {
    local generic_name=$1
    
    case "$OS" in
        debian)
            case "$generic_name" in
                python) echo "python3" ;;
                pip) echo "python3-pip" ;;
                ruby-dev) echo "ruby-dev" ;;
                *) echo "$generic_name" ;;
            esac
            ;;
        rhel)
            case "$generic_name" in
                python) echo "python3" ;;
                pip) echo "python3-pip" ;;
                ruby-dev) echo "ruby-devel" ;;
                libssl-dev) echo "openssl-devel" ;;
                libpcap-dev) echo "libpcap-devel" ;;
                build-essential) echo "gcc gcc-c++ make" ;;
                *) echo "$generic_name" ;;
            esac
            ;;
        arch)
            case "$generic_name" in
                python) echo "python" ;;
                pip) echo "python-pip" ;;
                ruby-dev) echo "ruby" ;;
                libssl-dev) echo "openssl" ;;
                libpcap-dev) echo "libpcap" ;;
                build-essential) echo "base-devel" ;;
                *) echo "$generic_name" ;;
            esac
            ;;
        macos)
            case "$generic_name" in
                python) echo "python@3" ;;
                pip) echo "" ;; # comes with python
                ruby-dev) echo "ruby" ;;
                libssl-dev) echo "openssl" ;;
                libpcap-dev) echo "libpcap" ;;
                build-essential) echo "" ;; # xcode tools
                *) echo "$generic_name" ;;
            esac
            ;;
    esac
}

# Install build tools
install_build_tools() {
    kl_msg_info "Installing build tools..."
    
    case "$OS" in
        debian)
            pkg_install build-essential git curl wget cmake
            ;;
        rhel)
            pkg_install gcc gcc-c++ make git curl wget cmake
            if [[ "$PKG_MANAGER" == "dnf" ]]; then
                run_optional "Development Tools group (dnf)" $PKG_MANAGER groupinstall -y "Development Tools"
            else
                run_optional "Development Tools group (yum)" $PKG_MANAGER groupinstall -y "Development Tools"
            fi
            ;;
        arch)
            pkg_install base-devel git curl wget cmake
            ;;
        opensuse)
            pkg_install -t pattern devel_basis
            pkg_install git curl wget cmake
            ;;
        macos)
            # Check for Xcode Command Line Tools
            if ! xcode-select -p &>/dev/null; then
                kl_msg_info "Installing Xcode Command Line Tools..."
                xcode-select --install || warn_optional "Xcode Command Line Tools install prompt failed"
            fi
            pkg_install git curl wget
            ;;
    esac
}

# Install base dependencies
install_base_dependencies() {
    kl_msg_info "Installing base dependencies..."
    
    local base_pkgs=()
    
    case "$OS" in
        debian)
            base_pkgs=(
                sudo gpg curl wget git
                nmap nikto
                whois dnsutils
                python3 python3-pip
                dos2unix
                net-tools iputils-ping
                libssl-dev
                libpcap-dev
            )
            
            pkg_install_optional theharvester
            pkg_install_optional dnsrecon
            pip_install_pkg theHarvester || warn_optional "pip install theHarvester failed"
            ;;
            
        rhel)
            # Enable EPEL for RHEL-based systems
            if [[ "$ID" == "rhel" ]] || [[ "$ID" == "centos" ]] || [[ "$ID" == "rocky" ]] || [[ "$ID" == "alma" ]]; then
                run_optional "EPEL release" $PKG_MANAGER install -y epel-release
            fi
            
            base_pkgs=(
                sudo git curl wget
                nmap
                whois bind-utils
                python3 python3-pip
                net-tools iputils
                openssl openssl-devel
            )
            
            pkg_install_optional nikto
            ;;
            
        arch)
            base_pkgs=(
                sudo git curl wget
                nmap nikto
                whois dnsutils
                python python-pip
                dos2unix
                libxml2 libxslt
                net-tools iputils
                openssl
            )
            ;;
            
        macos)
            base_pkgs=(
                git curl wget
                nmap
                python@3
                libxml2 libxslt
                openssl
            )
            ;;
    esac
    
    pkg_install "${base_pkgs[@]}" || {
        kl_msg_err "Base dependency install failed"
        exit 1
    }
}

# Setup Python environment
setup_python() {
    kl_msg_info "Setting up Python environment..."
    
    # Upgrade pip
    kl_msg_info "Upgrading pip..."
    if kitelon_pip_install install --upgrade pip --break-system-packages \
        || kitelon_pip_install install --upgrade pip; then
        kl_msg_ok "pip upgraded"
    else
        warn_optional "pip upgrade failed"
    fi
    
    # Install Python packages
    local py_packages=(
        dnspython
        colorama
        tldextract
        urllib3
        ipaddress
        requests
        webtech
        shodan
        censys
        'psycopg[binary]'
        fastapi
        python-multipart
        'uvicorn[standard]'
        croniter
        cmd2
    )
    
    for pkg in "${py_packages[@]}"; do
        pip_install_pkg "$pkg" || warn_optional "pip install $pkg failed"
    done
}

# PDF report export: wkhtmltopdf (system) + pdfkit (pip)
install_pdf_report_tools() {
    kl_msg_info "Installing PDF report tools (wkhtmltopdf + pdfkit)..."

    case "$OS" in
        debian)
            run_quiet "apt install wkhtmltopdf failed" apt-get install -y -qq wkhtmltopdf || return 1
            ;;
        rhel)
            run_quiet "$PKG_MANAGER install wkhtmltopdf failed" $PKG_MANAGER install -y -q wkhtmltopdf || return 1
            ;;
        arch)
            run_quiet "pacman install wkhtmltopdf failed" pacman -S --noconfirm --needed wkhtmltopdf || return 1
            ;;
        macos)
            run_quiet "brew install wkhtmltopdf failed" brew install --cask wkhtmltopdf \
                || run_quiet "brew install wkhtmltopdf failed" brew install wkhtmltopdf \
                || return 1
            ;;
        *)
            kl_msg_warn "Unknown OS for wkhtmltopdf: install manually"
            return 1
            ;;
    esac

    pip_install_pkg pdfkit || {
        kl_msg_err "pip install pdfkit failed"
        return 1
    }

    if ! command -v wkhtmltopdf &>/dev/null; then
        kl_msg_err "wkhtmltopdf not on PATH after install"
        return 1
    fi

    if ! python3 -c "import pdfkit" 2>/dev/null; then
        kl_msg_err "pdfkit not importable after install"
        return 1
    fi

    kl_msg_ok "PDF report tools ready ($(command -v wkhtmltopdf), pdfkit)"
    return 0
}

# Setup Go environment: official tarball from https://go.dev/doc/install
kitelon_go_tarball_os() {
    case "$OS" in
        macos) echo "darwin" ;;
        *) echo "linux" ;;
    esac
}

kitelon_go_tarball_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *)
            echo ""
            return 1
            ;;
    esac
}

kitelon_go_tarball_sha256() {
    local tarball="$1"
    python3 - <<'PY' "$tarball"
import json
import sys
import urllib.request

tar = sys.argv[1]
try:
    with urllib.request.urlopen("https://go.dev/dl/?mode=json", timeout=60) as resp:
        rows = json.load(resp)
except OSError:
    sys.exit(0)
for row in rows:
    if row.get("file") == tar:
        print(row.get("sha256", ""))
        break
PY
}

kitelon_installed_go_version() {
    local go_bin="$1"
    "$go_bin" version 2>/dev/null | awk '{print $3}' | sed 's/^go//'
}

kitelon_go_path() {
    export GOPATH=${GOPATH:-$HOME/go}
    export PATH="/usr/local/go/bin:${GOPATH}/bin:${PATH}"
    export GOTOOLCHAIN=auto
}

kitelon_link_go_binary() {
    local name="$1"
    local src="$2"
    [[ -x "$src" ]] || return 0
    ln -sf "$src" "/usr/local/bin/$name" 2>/dev/null \
        || ln -sf "$src" "/usr/bin/$name" 2>/dev/null \
        || warn_optional "symlink $name failed"
}

install_official_golang() {
    local os arch tarball url tgz
    os=$(kitelon_go_tarball_os) || return 1
    arch=$(kitelon_go_tarball_arch) || {
        warn_optional "unsupported CPU for Go install: $(uname -m)"
        return 1
    }
    tarball="go${KITELON_GO_VERSION}.${os}-${arch}.tar.gz"
    url="https://go.dev/dl/${tarball}"

    kl_msg_info "Installing Go ${KITELON_GO_VERSION} from go.dev..."
    tgz=$(kitelon_tmpfile)
    if ! run_quiet "Go ${KITELON_GO_VERSION} download failed" curl -fsSL "$url" -o "${tgz}.tar.gz"; then
        rm -f "${tgz}.tar.gz"
        return 1
    fi
    local expected actual
    expected=$(kitelon_go_tarball_sha256 "$tarball")
    if [[ -n "$expected" ]]; then
        actual=$(sha256sum "${tgz}.tar.gz" | awk '{print $1}')
        if [[ "$actual" != "$expected" ]]; then
            warn_optional "Go tarball SHA256 mismatch for ${tarball}"
            rm -f "${tgz}.tar.gz"
            return 1
        fi
    else
        warn_optional "Go tarball checksum unavailable for ${tarball}; skipping verify"
    fi
    rm -rf /usr/local/go
    if ! tar -C /usr/local -xzf "${tgz}.tar.gz"; then
        warn_optional "Go tarball extract failed"
        rm -f "${tgz}.tar.gz"
        return 1
    fi
    rm -f "${tgz}.tar.gz"
    kitelon_go_path
    kitelon_link_go_binary go /usr/local/go/bin/go
    if /usr/local/go/bin/go version >/dev/null 2>&1; then
        kl_msg_ok "golang: $(/usr/local/go/bin/go version | awk '{print $3}') (/usr/local/go)"
        return 0
    fi
    warn_optional "Go installed to /usr/local/go but binary check failed"
    return 1
}

ensure_golang() {
    kitelon_go_path
    local ver go_bin="/usr/local/go/bin/go"

    if [[ -x "$go_bin" ]]; then
        ver=$(kitelon_installed_go_version "$go_bin")
        if [[ "$ver" == "$KITELON_GO_VERSION" ]]; then
            kitelon_link_go_binary go "$go_bin"
            kl_msg_ok "golang: go${ver} (/usr/local/go)"
            return 0
        fi
        kl_msg_info "Upgrading Go (found go${ver:-unknown}, want ${KITELON_GO_VERSION})..."
        install_official_golang && return 0
    fi

    if install_official_golang; then
        return 0
    fi

    kl_msg_info "Falling back to distribution golang package..."
    case "$OS" in
        debian|rhel|opensuse)
            pkg_install golang || return 1
            ;;
        arch|macos)
            pkg_install go || return 1
            ;;
    esac
    kitelon_go_path
    if go version >/dev/null 2>&1; then
        ver=$(kitelon_installed_go_version "$(command -v go)")
        kl_msg_ok "golang: go${ver} (distro fallback)"
        [[ "$ver" == "$KITELON_GO_VERSION" ]] \
            || warn_optional "distro Go is go${ver}, not ${KITELON_GO_VERSION}"
        return 0
    fi
    warn_optional "golang not available on PATH after install"
    return 1
}

install_wafw00f() {
    local wafw00f_repo="$PLUGINS_DIR/wafw00f"
    if [[ -d "$wafw00f_repo/.git" ]]; then
        kl_msg_info "Updating wafw00f..."
        git -C "$wafw00f_repo" pull --ff-only 2>/dev/null \
            || warn_optional "wafw00f git update failed (existing clone left in place)"
    elif [[ ! -d "$wafw00f_repo" ]]; then
        kl_msg_info "Installing wafw00f..."
        git_clone_optional "wafw00f" https://github.com/EnableSecurity/wafw00f.git "$wafw00f_repo" \
            || return 1
    fi
    if [[ "$OS" == "debian" ]] && dpkg-query -W -f='${Status}' wafw00f 2>/dev/null | grep -q "install ok installed"; then
        kl_msg_info "Removing outdated apt wafw00f package..."
        run_optional "apt remove wafw00f" apt-get remove -y -qq wafw00f
    fi
    if [[ ! -d "$wafw00f_repo" ]]; then
        warn_optional "wafw00f source tree missing"
        return 1
    fi
    if kitelon_pip_install install --upgrade "$wafw00f_repo" --break-system-packages \
        || kitelon_pip_install install --upgrade "$wafw00f_repo"; then
        local wafw00f_ver
        wafw00f_ver=$(python3 -c "import wafw00f; print(wafw00f.__version__)" 2>/dev/null || true)
        kl_msg_ok "wafw00f${wafw00f_ver:+ v$wafw00f_ver} ($(command -v wafw00f 2>/dev/null || echo not on PATH))"
        command -v wafw00f >/dev/null 2>&1
        return $?
    fi
    warn_optional "wafw00f pip install failed"
    return 1
}

ensure_wafw00f() {
    if command -v wafw00f >/dev/null 2>&1; then
        kl_msg_ok "wafw00f: $(command -v wafw00f)"
        return 0
    fi
    install_wafw00f
}

ensure_required_tools() {
    kl_msg_info "Ensuring required tools (golang, wafw00f)..."
    ensure_golang || true
    ensure_wafw00f || true
}

setup_go() {
    kl_msg_info "Setting up Go environment..."
    ensure_golang || return 1
    mkdir -p "$GO_DIR"
}

# Install Metasploit Framework + local MSF DB (msfdb)
install_metasploit() {
    kl_msg_info "Installing Metasploit Framework..."

    case "$OS" in
        debian|rhel)
            if ! command -v msfconsole &>/dev/null; then
                curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
                chmod 755 /tmp/msfinstall
                run_optional "Metasploit Framework install" /tmp/msfinstall
                rm -f /tmp/msfinstall
            else
                kl_msg_ok "Metasploit Framework already installed"
            fi
            ;;
        arch)
            pkg_install_optional metasploit
            ;;
        macos)
            run_optional "brew metasploit" brew install metasploit
            ;;
    esac

    if [[ -f "$SCRIPT_DIR/bin/msfdb.sh" ]]; then
        # shellcheck source=/dev/null
        source "$SCRIPT_DIR/bin/msfdb.sh"
        kitelon_msfdb_setup || warn_optional "Metasploit DB setup failed"
    fi
}

# Create directory structure
create_directories() {
    kl_msg_info "Creating directory structure..."
    
    local dirs=(
        "$INSTALL_DIR"
        "$LOOT_DIR"
        "$LOOT_DIR/domains"
        "$LOOT_DIR/screenshots"
        "$LOOT_DIR/nmap"
        "$LOOT_DIR/reports"
        "$LOOT_DIR/output"
        "$LOOT_DIR/osint"
        "$LOOT_DIR/workspace"
        "$PLUGINS_DIR"
        "$GO_DIR"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
    done
}

# Canonical workspace dir + workspaces symlink (must run after file copy)
fix_loot_workspace_layout() {
    kl_msg_info "Ensuring loot/workspace layout..."
    PYTHONPATH="$INSTALL_DIR/bin${PYTHONPATH:+:$PYTHONPATH}" \
        python3 "$INSTALL_DIR/bin/kitelon_db.py" fix-loot-layout --loot-root "$LOOT_DIR" \
        || warn_optional "loot workspace layout fix failed"
}

# Install Kitelon files
install_kitelon_files() {
    kl_msg_info "Installing Kitelon files..."
    
    cp -Rf "$SCRIPT_DIR"/* "$INSTALL_DIR/" || {
        kl_msg_err "Failed to copy Kitelon files to $INSTALL_DIR"
        exit 1
    }
}

# Install Go-based tools
install_go_tools() {
    kl_msg_info "Installing Go-based tools..."
    
    kitelon_go_path
    ensure_golang || {
        warn_optional "golang required for Go-based tools"
        return 1
    }
    
    export GOTOOLCHAIN=auto
    export GOPATH="${KITELON_GOPATH:-/usr/local/share/kitelon-go}"
    export GOBIN="${KITELON_GOBIN:-/usr/local/bin}"
    mkdir -p "$GOPATH" "$GOBIN"
    cd "$GOPATH/bin" 2>/dev/null || mkdir -p "$GOPATH/bin" && cd "$GOPATH/bin" || return

    local versions_file="$SCRIPT_DIR/conf/go-tool-versions.conf"
    [[ -f "$versions_file" ]] || versions_file="$INSTALL_DIR/conf/go-tool-versions.conf"
    if [[ ! -f "$versions_file" ]]; then
        warn_optional "missing conf/go-tool-versions.conf"
        return 1
    fi

    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        IFS=':' read -r tool_path tool_name <<< "$line"
        kl_msg_info "Installing $tool_name ($tool_path)..."
        local out rc=0
        out=$(kitelon_tmpfile)
        env GO111MODULE=on go install "$tool_path" >"$out" 2>&1 || rc=$?
        if [[ $rc -eq 0 ]]; then
            kl_msg_ok "$tool_name"
        else
            warn_optional "go install $tool_name failed"
            kitelon_show_cmd_errors "$out"
        fi
        rm -f "$out"

        if [[ -f "$GOBIN/$tool_name" ]]; then
            chmod 755 "$GOBIN/$tool_name" 2>/dev/null || true
        elif [[ -f "$GOPATH/bin/$tool_name" ]]; then
            ln -fs "$GOPATH/bin/$tool_name" "$GOBIN/$tool_name" 2>/dev/null \
                || warn_optional "symlink $tool_name failed"
        fi
    done < "$versions_file"
    
    # Update nuclei templates
    mkdir -p "$PLUGINS_DIR/nuclei-templates"
    if command -v nuclei &>/dev/null; then
        kl_msg_info "Updating nuclei templates..."
        local out rc=0
        out=$(kitelon_tmpfile)
        nuclei -update-templates -ud "$PLUGINS_DIR/nuclei-templates" >"$out" 2>&1 \
            || nuclei -update-templates >>"$out" 2>&1 \
            || nuclei --update >>"$out" 2>&1 || rc=$?
        if [[ $rc -eq 0 ]]; then
            kl_msg_ok "nuclei templates updated"
        else
            warn_optional "nuclei template update failed"
            kitelon_show_cmd_errors "$out"
        fi
        rm -f "$out"
    fi
}

# Install Python-based tools
install_python_tools() {
    kl_msg_info "Installing Python-based tools..."
    
    cd "$PLUGINS_DIR" || return
    
    # SSH-Audit
    if [[ ! -d "ssh-audit" ]]; then
        kl_msg_info "Installing SSH-Audit..."
        git_clone_optional "SSH-Audit" https://github.com/jtesta/ssh-audit.git ssh-audit
    fi

    # testssl.sh: deep SSL/TLS analysis
    local testssl_repo="$PLUGINS_DIR/testssl.sh"
    if [[ -d "$testssl_repo/.git" ]]; then
        kl_msg_info "Updating testssl.sh..."
        git -C "$testssl_repo" pull --ff-only 2>/dev/null \
            || warn_optional "testssl.sh git update failed (existing clone left in place)"
    elif [[ ! -d "$testssl_repo" ]]; then
        kl_msg_info "Installing testssl.sh..."
        git_clone_optional "testssl.sh" https://github.com/drwetter/testssl.sh.git "$testssl_repo"
    fi
    if [[ -f "$testssl_repo/testssl.sh" ]]; then
        # A prior install may have overwritten the real script with the /usr/local/bin wrapper.
        if [[ $(wc -l < "$testssl_repo/testssl.sh" 2>/dev/null | tr -d ' ') -lt 100 ]]; then
            kl_msg_warn "testssl.sh script corrupted, restoring from git..."
            git -c safe.directory="$testssl_repo" -C "$testssl_repo" checkout -- testssl.sh 2>/dev/null \
                || warn_optional "testssl.sh restore failed: remove $testssl_repo and re-run install"
        fi
        if [[ $(wc -l < "$testssl_repo/testssl.sh" 2>/dev/null | tr -d ' ') -lt 100 ]]; then
            warn_optional "testssl.sh still corrupted after restore: remove $testssl_repo and re-run install"
        fi
        # Wrapper belongs in /usr/local/bin only: never overwrite the repo script.
        chmod 755 "$testssl_repo/testssl.sh" 2>/dev/null \
            || chmod +x "$testssl_repo/testssl.sh" \
            || warn_optional "testssl.sh chmod failed"
        find "$testssl_repo/bin" -maxdepth 1 -type f -name '*.sh' -exec chmod 755 {} + 2>/dev/null || true
        cat > /usr/local/bin/testssl.sh <<EOF
#!/bin/bash
exec bash "$testssl_repo/testssl.sh" "\$@"
EOF
        chmod 755 /usr/local/bin/testssl.sh
        kl_msg_ok "testssl.sh"
    fi

    # wafw00f: WAF fingerprinting (EnableSecurity; pip install from plugins clone)
    install_wafw00f || warn_optional "wafw00f install failed"

    # metagoofil: metadata / file discovery OSINT
    local metagoofil_repo="$PLUGINS_DIR/metagoofil"
    kitelon_git_sync "metagoofil" https://github.com/laramies/metagoofil.git "$metagoofil_repo"
    if [[ -f "$metagoofil_repo/metagoofil.py" ]]; then
        chmod 755 "$metagoofil_repo/metagoofil.py" 2>/dev/null || chmod +x "$metagoofil_repo/metagoofil.py" || true
        kl_msg_ok "metagoofil"
    fi
    
    # Dirsearch: web path brute-forcer (git v0.4.3; flags match scan scripts)
    local dirsearch_repo="$PLUGINS_DIR/dirsearch"
    kitelon_git_sync "dirsearch" https://github.com/maurosoria/dirsearch.git "$dirsearch_repo" "v0.4.3"
    if [[ -d "$dirsearch_repo" ]]; then
        kitelon_pip_install install -r "$dirsearch_repo/requirements.txt" --break-system-packages \
            || kitelon_pip_install install -r "$dirsearch_repo/requirements.txt" \
            || warn_optional "dirsearch requirements install failed"
        chmod 755 "$dirsearch_repo/dirsearch.py" 2>/dev/null || chmod +x "$dirsearch_repo/dirsearch.py" || true
        ln -sf "$dirsearch_repo/dirsearch.py" /usr/local/bin/dirsearch 2>/dev/null || true
        kl_msg_ok "dirsearch"
    fi
    
    kl_msg_info "Installing engine tools (enum4linux-ng, smbmap)..."
    install_smb_engine_tools
}

install_smb_engine_tools() {
    pkg_install_optional smbclient samba-common-bin ldap-utils
    pkg_install_optional enum4linux-ng

    if ! command -v enum4linux-ng &>/dev/null; then
        local repo="$PLUGINS_DIR/enum4linux-ng"
        if [[ ! -f "$repo/enum4linux-ng.py" ]]; then
            kl_msg_info "Cloning enum4linux-ng from GitHub..."
            git_clone_optional "enum4linux-ng" https://github.com/cddmp/enum4linux-ng "$repo"
        fi
        if [[ -f "$repo/requirements.txt" ]]; then
            kitelon_pip_install install -r "$repo/requirements.txt" --break-system-packages \
                || warn_optional "enum4linux-ng requirements install failed"
        fi
        if [[ -f "$repo/enum4linux-ng.py" ]]; then
            cat > /usr/local/bin/enum4linux-ng <<EOF
#!/bin/bash
exec python3 "$repo/enum4linux-ng.py" "\$@"
EOF
            chmod 755 /usr/local/bin/enum4linux-ng
            kl_msg_ok "enum4linux-ng wrapper installed at /usr/local/bin/enum4linux-ng"
        fi
    else
        kl_msg_ok "enum4linux-ng: $(command -v enum4linux-ng)"
    fi

    if kitelon_pip_install install smbmap --break-system-packages --ignore-installed blinker; then
        kl_msg_ok "smbmap"
    else
        warn_optional "pip install smbmap failed"
    fi
}

# Install additional tools
install_additional_tools() {
    kl_msg_info "Installing additional tools..."
    
    # GoBuster: prefer go install (apt/tarball v3.0.1 predates dir subcommand)
    if command -v gobuster &>/dev/null; then
        kl_msg_ok "gobuster: $(gobuster version 2>/dev/null | head -1 || command -v gobuster)"
    elif [[ -f "$HOME/go/bin/gobuster" ]]; then
        ln -sf "$HOME/go/bin/gobuster" /usr/local/bin/gobuster 2>/dev/null \
            || ln -sf "$HOME/go/bin/gobuster" /usr/bin/gobuster 2>/dev/null || true
        kl_msg_ok "gobuster (from go install)"
    else
        kl_msg_info "Installing GoBuster..."
        case "$OS" in
            debian)
                run_optional "apt install gobuster" apt-get install -y -qq gobuster
                ;;
            macos)
                run_optional "brew gobuster" brew install gobuster
                ;;
        esac
        if ! command -v gobuster &>/dev/null; then
            warn_optional "gobuster not installed: rerun install after Go tools step"
        fi
    fi
    
    # Vulners Nmap Script
    kl_msg_info "Installing Vulners Nmap script..."
    local nmap_scripts_dir
    case "$OS" in
        debian|rhel|arch)
            nmap_scripts_dir="/usr/share/nmap/scripts"
            ;;
        macos)
            nmap_scripts_dir="/usr/local/share/nmap/scripts"
            ;;
    esac
    
    if [[ -d "$nmap_scripts_dir" ]]; then
        run_quiet "Vulners NSE download failed" wget -q https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse -O "$nmap_scripts_dir/vulners.nse"
        chmod 644 "$nmap_scripts_dir/vulners.nse" || warn_optional "chmod vulners.nse failed"
        run_optional "nmap --script-updatedb" nmap --script-updatedb
        kl_msg_ok "Vulners Nmap script installed"
    fi
    
    mkdir -p "$INSTALL_DIR/wordlists"
    kl_msg_info "Fetching SecLists web wordlist..."
    local seclists_base="https://raw.githubusercontent.com/danielmiessler/SecLists/master"
    run_quiet "web-brute-common download failed" wget -q "$seclists_base/Discovery/Web-Content/common.txt" -O "$INSTALL_DIR/wordlists/web-brute-common.txt" \
        || warn_optional "web-brute-common.txt download failed"
}

# Install CLI on PATH
install_cli_symlink() {
    local bin="$INSTALL_DIR/kitelon"

    if [[ ! -f "$bin" ]]; then
        kl_msg_err "Kitelon binary not found at $bin"
        exit 1
    fi

    chmod 755 "$bin" || {
        kl_msg_err "chmod failed on $bin"
        exit 1
    }

    local dest
    local linked=0
    local -a path_dirs=()

    case "$OS" in
        macos)
            path_dirs=(/usr/local/bin)
            ;;
        *)
            path_dirs=(/usr/local/bin /usr/bin)
            ;;
    esac

    kl_msg_info "Adding kitelon to PATH..."

    for dest in "${path_dirs[@]}"; do
        mkdir -p "$(dirname "$dest")"
        if ln -sf "$bin" "$dest"; then
            kl_msg_ok "$dest -> $bin"
            linked=1
        else
            kl_msg_warn "Could not link $dest (permission denied?)"
        fi
    done

    if [[ $linked -eq 0 ]]; then
        kl_msg_err "Failed to add kitelon to PATH."
        kl_msg_err "Run manually: sudo ln -sf $bin /usr/local/bin/kitelon"
        exit 1
    fi

    if command -v kitelon >/dev/null 2>&1; then
        kl_msg_ok "kitelon is available on PATH: $(command -v kitelon)"
    else
        kl_msg_warn "Open a new shell if 'kitelon' is not found yet."
    fi
}

install_kitelon_cli_symlink() {
    local cli="$INSTALL_DIR/bin/kitelon_cli.py"

    if [[ ! -f "$cli" ]]; then
        kl_msg_warn "kitelon-cli script not found at $cli (skipping)"
        return 0
    fi

    local dest
    local linked=0
    local -a path_dirs=()

    case "$OS" in
        macos)
            path_dirs=(/usr/local/bin)
            ;;
        *)
            path_dirs=(/usr/local/bin /usr/bin)
            ;;
    esac

    kl_msg_info "Adding kitelon-cli to PATH..."

    for dest in "${path_dirs[@]}"; do
        mkdir -p "$(dirname "$dest")"
        # Replace any stale symlink (writing through a symlink would corrupt kitelon_cli.py).
        rm -f "$dest/kitelon-cli"
        # Wrapper lives outside INSTALL_DIR so kitelon_secure_install cannot strip +x.
        cat > "$dest/kitelon-cli" <<EOF
#!/bin/bash
export KITELON_INSTALL_DIR="$INSTALL_DIR"
export PYTHONPATH="$INSTALL_DIR/bin\${PYTHONPATH:+\:$PYTHONPATH}"
exec python3 "$INSTALL_DIR/bin/kitelon_cli.py" "\$@"
EOF
        if chmod 755 "$dest/kitelon-cli"; then
            kl_msg_ok "$dest/kitelon-cli"
            linked=1
        else
            kl_msg_warn "Could not install $dest/kitelon-cli (permission denied?)"
        fi
    done

    if [[ $linked -eq 0 ]]; then
        kl_msg_warn "Failed to add kitelon-cli to PATH."
        kl_msg_warn "Run manually: sudo bash $SCRIPT_DIR/install.sh force"
    elif command -v kitelon-cli >/dev/null 2>&1; then
        kl_msg_ok "kitelon-cli is available on PATH: $(command -v kitelon-cli)"
    fi
}

# Create symlinks
create_symlinks() {
    install_cli_symlink
    install_kitelon_cli_symlink

    kl_msg_info "Creating tool symlinks..."

    ln -fs "$PLUGINS_DIR/dirsearch/dirsearch.py" /usr/bin/dirsearch || \
        ln -fs "$PLUGINS_DIR/dirsearch/dirsearch.py" /usr/local/bin/dirsearch || \
        warn_optional "dirsearch symlink failed"
    
    if [[ "$IS_KALI" == "1" ]]; then
        ln -fs /usr/share/kitelon/loot/workspace /workspace || warn_optional "/workspace symlink failed"
        ln -fs /usr/share/kitelon/loot/workspace /root/workspace || warn_optional "/root/workspace symlink failed"
    fi
    
    if [[ "$OS" != "macos" ]]; then
        ln -fs /root/.kitelon.conf /usr/share/kitelon/conf/kitelon.conf || warn_optional "kitelon.conf symlink failed"
        if [[ -f /root/.kitelon_api_keys.conf ]]; then
            ln -fs /root/.kitelon_api_keys.conf /usr/share/kitelon/conf/kitelon_api_keys.conf || warn_optional "kitelon_api_keys.conf symlink failed"
        fi
    fi
}

# Setup desktop shortcuts (Linux only)
setup_desktop_shortcuts() {
    if [[ "$OS" == "macos" ]]; then
        return
    fi
    
    kl_msg_info "Setting up desktop shortcuts..."
    
    cp -f "$INSTALL_DIR/kitelon.desktop" /usr/share/applications/ || warn_optional "kitelon.desktop copy failed"
    
    if [[ "$IS_KALI" != "1" ]]; then
        return 0
    fi
    
    kl_msg_info "Installing Kali menu and desktop shortcuts..."
    
    if [[ -d /usr/share/kali-menu/applications ]]; then
        cp -f "$INSTALL_DIR/kitelon.desktop" /usr/share/kali-menu/applications/ || warn_optional "kali-menu kitelon.desktop copy failed"
    fi
    
    if [[ -d /home/kali/Desktop ]]; then
        ln -fs /usr/share/kitelon/loot/workspace/ /home/kali/Desktop/workspaces || warn_optional "kali Desktop workspaces link failed"
    fi
    if [[ -d /root/Desktop ]]; then
        ln -fs /usr/share/kitelon/loot/workspace/ /root/Desktop/workspaces || warn_optional "root Desktop workspaces link failed"
    fi
}

# Install job worker units + verify PostgreSQL
install_phase3_services() {
    kl_msg_info "Installing job worker units..."

    if [[ "$OS" == "macos" ]]; then
        kl_msg_warn "systemd worker skipped on macOS"
        return 0
    fi

    cp -f "$INSTALL_DIR/conf/kitelon-worker.service" /etc/systemd/system/ \
        || warn_optional "kitelon-worker.service copy failed"
    cp -f "$INSTALL_DIR/conf/kitelon-worker-scan.service" /etc/systemd/system/ \
        || warn_optional "kitelon-worker-scan.service copy failed"
    cp -f "$INSTALL_DIR/conf/kitelon-worker-post.service" /etc/systemd/system/ \
        || warn_optional "kitelon-worker-post.service copy failed"
    cp -f "$INSTALL_DIR/conf/kitelon-worker-cron.service" /etc/systemd/system/ \
        || warn_optional "kitelon-worker-cron.service copy failed"
    cp -f "$INSTALL_DIR/conf/kitelon-worker-cron.timer" /etc/systemd/system/ \
        || warn_optional "kitelon-worker-cron.timer copy failed"
    systemctl daemon-reload 2>/dev/null || warn_optional "systemctl daemon-reload failed"

    mkdir -p /var/log/kitelon
    chmod 755 /var/log/kitelon 2>/dev/null || true

    cat > /etc/cron.d/kitelon-worker <<'CRON'
# Kitelon worker safety net (recover stuck jobs, promote schedules)
*/5 * * * * root /usr/bin/python3 /usr/share/kitelon/bin/kitelon_worker.py recover >> /var/log/kitelon/worker-cron.log 2>&1
CRON
    chmod 644 /etc/cron.d/kitelon-worker 2>/dev/null || true

    kl_msg_info "Checking PostgreSQL connectivity..."
    if PYTHONPATH="$INSTALL_DIR/bin" python3 -c "
from kitelon_db import get_connection
with get_connection() as conn:
    conn.execute('SELECT 1')
print('ok')
" 2>/dev/null; then
        kl_msg_ok "PostgreSQL reachable"
    else
        kl_msg_warn "PostgreSQL not configured yet"
        kl_msg_warn "  Create database + /root/.kitelon_db.conf, then: kitelon db migrate"
        kl_msg_warn "  Example: cp $INSTALL_DIR/conf/kitelon_db.conf.example /root/.kitelon_db.conf"
    fi

    kl_msg_warn "After DB setup: systemctl enable --now kitelon-worker kitelon-worker-cron.timer"
    kl_msg_warn "  Optional split pools: kitelon-worker-scan + kitelon-worker-post (disable kitelon-worker)"
}

# Setup configuration
kitelon_write_conf() {
    local dest="$1"
    local db_enabled="$2"
    local db_host="$3"
    local db_port="$4"
    local db_name="$5"
    local db_user="$6"
    local web_bind="$7"
    local web_port="$8"

    cat > "$dest" <<EOF
INSTALL_DIR="/usr/share/kitelon"
PLUGINS_DIR="\$INSTALL_DIR/plugins"
WORDLIST_DIR="\$INSTALL_DIR/wordlists"

KL_C_INFO='\033[94m'
KL_C_ERR='\033[91m'
KL_C_OK='\033[92m'
KL_C_WARN='\033[93m'
KL_RESET='\e[0m'

ENABLE_AUTO_UPDATES="0"
REPORT="1"
LOOT="1"
LOOT_DB="1"
LOOT_REPORT="1"
MAX_HOSTS="2000"
THREADS="10"
OUT_OF_SCOPE=()

ENABLE_NUCLEI="1"
ENABLE_TESTSSL="1"
ENABLE_DIRSEARCH="1"
ENABLE_GOBUSTER="1"
ENABLE_HTTPX="1"
ENABLE_SUBFINDER="1"
ENABLE_WAFW00F="1"
ENABLE_VULNERS="1"
ENABLE_OS_DETECT="1"
ENABLE_METASPLOIT="1"
ENABLE_DNSRECON="1"
ENABLE_METAGOOFILE="0"
ENABLE_GAU="1"
ENABLE_SHODAN="1"
ENABLE_CENSYS="1"
SHODAN_MAX_RESULTS="25"
CENSYS_MAX_RESULTS="25"
CENSYS_MODE="hosts"
GAU_MAX_URLS="500"
GAU_PROVIDERS="wayback"
GAU_INCLUDE_SUBS="1"
METAGOOFILE_LIMIT="25"
METAGOOFILE_TYPES="pdf,doc,xls"
DNSRECON_AXFR="0"
DNSRECON_TIMEOUT="300"
METAGOOFILE_TIMEOUT="600"
GAU_TIMEOUT="300"
SHODAN_TIMEOUT="60"
CENSYS_TIMEOUT="60"
MSF_MODULE_TIMEOUT="420"
MSF_MAX_MODULES="12"
NUCLEI_TEMPLATES="\$PLUGINS_DIR/nuclei-templates"

DB_ENABLED="$db_enabled"
DB_HOST="$db_host"
DB_PORT="$db_port"
DB_NAME="$db_name"
DB_USER="$db_user"
LOOT_ARTIFACTS_DB="1"
LOOT_FS_MIRROR="1"
WEB_BIND="$web_bind"
WEB_PORT="$web_port"

WORKER_ROLE="both"
WORKER_POLL_SEC="10"
WORKER_POST_CONCURRENCY="2"

SHODAN_API_KEY=""
CENSYS_APP_ID=""
CENSYS_API_SECRET=""
HUNTERIO_KEY=""
GITHUB_API_KEY=""
WP_API_KEY=""

BURP_HOST="127.0.0.1"
BURP_PORT="1338"
OPENVAS="0"
NESSUS="0"
SLACK_NOTIFICATIONS="0"

BROWSER="firefox"

LOG_ENABLED="1"
LOG_DIR="/var/log/kitelon"
LOG_LEVEL="INFO"
LOG_MAX_BYTES="10485760"
LOG_BACKUP_COUNT="5"
LOG_STDERR="1"
EOF
}

kitelon_prompt_conf_values() {
    local db_enabled db_host db_port db_name db_user db_password web_bind web_port
    local answer

    echo ""
    kl_msg_info "Kitelon configuration (Enter accepts the default)"
    read -r -p "  Enable PostgreSQL + Web UI? [Y/n]: " answer
    case "${answer:-Y}" in
        n|N|0) db_enabled="0" ;;
        *) db_enabled="1" ;;
    esac

    db_host="127.0.0.1"
    db_port="5432"
    db_name="kitelon"
    db_user="postgres"
    db_password=""
    web_bind="127.0.0.1"
    web_port="8080"

    if [[ "$db_enabled" == "1" ]]; then
        read -r -p "  DB host [$db_host]: " answer
        db_host="${answer:-$db_host}"
        read -r -p "  DB port [$db_port]: " answer
        db_port="${answer:-$db_port}"
        read -r -p "  DB name [$db_name]: " answer
        db_name="${answer:-$db_name}"
        read -r -p "  DB user [$db_user]: " answer
        db_user="${answer:-$db_user}"
        while [[ -z "$db_password" ]]; do
            read -r -s -p "  DB password (required): " db_password
            echo ""
            if [[ -z "$db_password" ]]; then
                kl_msg_warn "Password is required when the database is enabled."
            fi
        done
        read -r -p "  Web UI bind address [$web_bind]: " answer
        web_bind="${answer:-$web_bind}"
        read -r -p "  Web UI port [$web_port]: " answer
        web_port="${answer:-$web_port}"
    fi

    kitelon_write_conf "$SCRIPT_DIR/kitelon.conf" \
        "$db_enabled" "$db_host" "$db_port" "$db_name" "$db_user" "$web_bind" "$web_port"
    cp -f "$SCRIPT_DIR/kitelon.conf" "$INSTALL_DIR/kitelon.conf" || {
        warn_optional "Failed to copy generated kitelon.conf to $INSTALL_DIR"
        return 1
    }
    kl_msg_ok "Created kitelon.conf"

    if [[ "$OS" != "macos" && "$db_enabled" == "1" && -n "$db_password" ]]; then
        printf '# Kitelon PostgreSQL password (chmod 600)\nDB_PASSWORD=%s\n' "$db_password" > /root/.kitelon_db.conf
        chmod 600 /root/.kitelon_db.conf
    fi
}

kitelon_setup_root_config() {
    [[ "$OS" == "macos" ]] && return 0

    if [[ -f /root/.kitelon.conf ]]; then
        cp -a /root/.kitelon.conf /root/.kitelon.conf.bak || true
    fi
    cp -f "$INSTALL_DIR/kitelon.conf" /root/.kitelon.conf \
        || warn_optional "copy kitelon.conf to /root failed"

    if [[ ! -f /root/.kitelon_db.conf ]] && grep -q '^DB_ENABLED="1"' /root/.kitelon.conf 2>/dev/null; then
        echo ""
        kl_msg_info "PostgreSQL password not configured yet"
        local db_password=""
        read -r -s -p "  DB password (Enter to skip): " db_password
        echo ""
        if [[ -n "$db_password" ]]; then
            printf '# Kitelon PostgreSQL password (chmod 600)\nDB_PASSWORD=%s\n' "$db_password" > /root/.kitelon_db.conf
            chmod 600 /root/.kitelon_db.conf
            kl_msg_ok "Wrote /root/.kitelon_db.conf"
        fi
    fi

    if [[ -f /root/.kitelon_db.conf ]] && grep -q '^DB_ENABLED="1"' /root/.kitelon.conf 2>/dev/null; then
        kl_msg_info "Testing PostgreSQL connection..."
        if PYTHONPATH="$INSTALL_DIR/bin" python3 "$INSTALL_DIR/bin/kitelon_db.py" test 2>/dev/null; then
            kl_msg_info "Running database migrations..."
            PYTHONPATH="$INSTALL_DIR/bin" python3 "$INSTALL_DIR/bin/kitelon_db.py" migrate \
                || warn_optional "database migrate failed"
        else
            warn_optional "PostgreSQL connection failed: fix credentials and run: kitelon db migrate"
        fi
    fi
}

setup_configuration() {
    kl_msg_info "Setting up configuration..."

    if [[ -f "$SCRIPT_DIR/kitelon.conf" ]]; then
        kl_msg_ok "Using kitelon.conf from installer directory"
        cp -f "$SCRIPT_DIR/kitelon.conf" "$INSTALL_DIR/kitelon.conf" || {
            warn_optional "Failed to copy config to $INSTALL_DIR/kitelon.conf"
            return 0
        }
    else
        kl_msg_warn "No kitelon.conf found: starting interactive setup"
        kitelon_prompt_conf_values || return 0
    fi

    kitelon_setup_root_config

    # X11 setup for GUI tools (Linux only)
    if [[ -f /root/.Xauthority ]]; then
        cp -a /root/.Xauthority /root/.Xauthority.bak || warn_optional "Xauthority backup failed"
    fi

    if [[ "$USER" != "root" ]] && [[ -f /home/$USER/.Xauthority ]]; then
        cp -a /home/$USER/.Xauthority /root/.Xauthority || warn_optional "Xauthority copy failed"
        chown root:root /root/.Xauthority || warn_optional "Xauthority chown failed"
    fi
}

# Cleanup
cleanup() {
    kl_msg_info "Cleaning up temporary files..."
    rm -rf /tmp/gobuster* /tmp/msfinstall /tmp/dirsearch* || true
}

# Main installation flow
main() {
    kl_msg_warn "This script will install Kitelon under $INSTALL_DIR."

    if [[ "$1" != "force" ]] && [[ "$1" != "-y" ]]; then
        kl_msg_warn "Do you want to continue? (y/n)"
        read -r answer
        if [[ "$answer" != "y" ]] && [[ "$answer" != "Y" ]]; then
            kl_msg_info "Installation cancelled."
            exit 0
        fi
    fi
    
    # Detect OS
    detect_os
    
    # Check root privileges
    check_root
    
    # Create directories
    create_directories
    
    install_kitelon_files
    fix_loot_workspace_layout
    install_cli_symlink

    # Update package repos
    pkg_update
    
    # Install build tools
    install_build_tools
    
    # Install base dependencies
    install_base_dependencies
    
    # Setup language environments
    setup_python
    ensure_required_tools
    install_pdf_report_tools || kl_msg_warn "PDF report tools install failed (wkhtmltopdf + pdfkit required for report.py)"
    setup_go

    install_metasploit || kl_msg_warn "Metasploit setup had errors (continuing)"

    # Install tools by category (optional; failures must not block kitelon install)
    install_go_tools || kl_msg_warn "Go tools install had errors (continuing)"
    install_python_tools || kl_msg_warn "Python tools install had errors (continuing)"
    install_additional_tools || kl_msg_warn "Additional tools install had errors (continuing)"
    
    # Create symlinks
    create_symlinks
    
    # Setup desktop shortcuts (Linux only)
    setup_desktop_shortcuts
    
    # Setup configuration
    setup_configuration

    install_phase3_services

    # Final permission pass: 644 files, 755 dirs, +x only on true executables
    if [[ "$OS" != "macos" ]] && [[ -f "$SCRIPT_DIR/bin/permissions.sh" ]]; then
        # shellcheck source=/dev/null
        source "$SCRIPT_DIR/bin/permissions.sh"
        kitelon_secure_install "$INSTALL_DIR"
    fi

    # PATH wrappers must be installed after secure_install (symlinks to .py break when chmod 644).
    install_kitelon_cli_symlink
    
    # Cleanup
    cleanup
    
    echo ""
    kl_msg_ok "Installation complete!"
    kl_msg_ok "To run Kitelon, type: kitelon or kitelon-cli"
    echo ""
    kl_msg_warn "OS Detected: $OS"
    kl_msg_warn "Install Directory: $INSTALL_DIR"
    kl_msg_warn "Loot Directory: $LOOT_DIR"
    echo ""
    
    # System-specific notes
    case "$OS" in
        macos)
            kl_msg_warn "Note: Some tools may require additional configuration on macOS"
            kl_msg_warn "Run with sudo if you encounter permission issues"
            ;;
        rhel)
            kl_msg_warn "Note: Some optional tools may not be available in RHEL repos"
            kl_msg_warn "Consider enabling additional repositories if needed"
            ;;
    esac
}

# Run main installation
main "$@"
