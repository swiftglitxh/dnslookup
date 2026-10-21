# ⛧ SWIFTGLITXH // DNS RECON
<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/310946b7-a73f-4a1b-9835-676453f5329c" />

<div align="center">

### `[ DNS INTELLIGENCE // OSINT // NETWORK RECON ]`

![Python](https://img.shields.io/badge/PYTHON-3.10%2B-red?style=for-the-badge&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/VERSION-1.1.0-black?style=for-the-badge)
![License](https://img.shields.io/badge/LICENSE-MIT-red?style=for-the-badge)
![Platform](https://img.shields.io/badge/PLATFORM-CROSS--PLATFORM-black?style=for-the-badge)

**DISCOVER. ANALYZE. RECON.**

</div>

---

## `[+] SYSTEM OVERVIEW`

**DNS Recon** is a Python-based DNS and OSINT reconnaissance toolkit developed by **SwiftGlitxh**.

Designed for network administrators, security researchers, penetration testers, and OSINT enthusiasts.

### Features

| Module | Description | Argument |
|---|---|---|
| DNS Lookup | Retrieve A, AAAA, MX, NS, TXT, CNAME, SOA, CAA records | `--dns` |
| Reverse DNS | Resolve IP addresses to PTR hostnames | `--reverse-dns` |
| WHOIS / RDAP | Retrieve domain registration information | `--whois` |
| Reverse IP | Discover domains associated with an IP address | `--reverse-ip` |
| Full Recon | Execute all applicable reconnaissance modules | `--all` |

---

## `[+] INSTALLATION`

### 01 // Clone Repository

```bash
git clone https://github.com/swiftglitxh/dnslookup
cd dnslookup
```

*Replace the repository URL if your actual repository name differs.*

### 02 // Create Virtual Environment

```bash
python -m venv .venv
```

**Linux / macOS**

```bash
source .venv/bin/activate
```

**Windows**

```powershell
.venv\Scripts\activate
```

### 03 // Install Requirements

```bash
python -m pip install -r requirements.txt
```

The `requirements.txt` file contains:

```text
requests>=2.32,<3
rich>=13.9,<15
```

### 04 // Launch

```bash
python dns_recon.py --help
```

---

## `[+] COMMAND & CONTROL`

**DNS Lookup**

```bash
python dns_recon.py example.com --dns
```

**Reverse DNS**

```bash
python dns_recon.py 8.8.8.8 --reverse-dns
```

**WHOIS / RDAP**

```bash
python dns_recon.py example.com --whois
```

**Reverse IP Lookup**

```bash
python dns_recon.py 8.8.8.8 --reverse-ip
```

**Full Reconnaissance**

```bash
python dns_recon.py example.com --all
```

---

## `[+] PROJECT STRUCTURE`

```text
DNS-Recon/
│
├── dns_recon.py
├── requirements.txt
├── README.md
├── LICENSE
│
└── assets/
    └── banner.png
```

---

## `[+] TECHNOLOGY STACK`

| Technology | Purpose |
|---|---|
| Python | Core application |
| Requests | DNS and reverse-IP API requests |
| Rich | Terminal interface |
| argparse | CLI arguments |
| socket | Reverse DNS resolution |
| ipaddress | IP validation |
| RDAP | Domain registration intelligence |

### External Services

```text
DNS Records
└── https://dns-lookup.com/api/dns

WHOIS / RDAP
└── https://rdap.org/domain/

Reverse IP
└── https://api.hackertarget.com/reverseiplookup/
```

External services may impose rate limits or change their response formats.

---

## `[+] ROADMAP`

- [x] DNS record lookup
- [x] Reverse DNS
- [x] WHOIS / RDAP
- [x] Reverse IP lookup
- [x] Rich CLI interface
- [x] argparse support
- [x] requirements.txt
- [ ] SSL/TLS certificate inspection
- [ ] DNS propagation checks
- [ ] SPF / DMARC analysis
- [ ] Subdomain discovery
- [ ] IP geolocation
- [ ] JSON / CSV exports
- [ ] Automated tests

---

## `[!] DISCLAIMER`

This toolkit is intended for educational purposes, legitimate network administration, OSINT research, and authorized security assessments.

Respect API rate limits and service terms. DNS and reverse-IP data may be incomplete or outdated.

---

## `[+] LICENSE`

Distributed under the **MIT License**.

See the `LICENSE` file for details.

---

## `[+] DEVELOPER`

**SwiftGlitxh**

GitHub: https://github.com/swiftglitxh

```text
[+] SWIFTGLITXH DNS RECON
[+] DISCOVER
[+] ANALYZE
[+] RECON

[ SYSTEM READY ]
```

