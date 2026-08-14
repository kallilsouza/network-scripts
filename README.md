# Network Scripts

A collection of useful, standalone network-related scripts and utilities for diagnostics, DNS queries, network troubleshooting, and automation.

---

## 📁 Available Scripts

### 1. `nslookup_tool.py`
A flexible DNS and NSLookup utility written in Python 3.12+. It accepts full URLs, domain names, hostnames, or IP addresses and retrieves detailed DNS record information.

**Features:**
- Accepts raw domains (`example.com`), full URLs (`https://sub.domain.org/path`), and IP addresses.
- Queries common record types (`A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, or `ALL`).
- Supports querying custom DNS servers (e.g. `8.8.8.8`, `1.1.1.1`).
- Optional JSON output format (`--json`) for easy piping into other scripts.
- Pure Python standard library fallback with optional `dnspython` or system `nslookup` integration.

**Usage:**
```bash
# Interactive mode (prompts for target URL/domain)
python3 nslookup_tool.py

# Query a specific domain or URL
python3 nslookup_tool.py example.com
python3 nslookup_tool.py https://www.google.com/search

# Query a specific DNS record type with a custom DNS server
python3 nslookup_tool.py example.com --type MX --dns-server 8.8.8.8

# Output results as JSON
python3 nslookup_tool.py example.com --json
```

---

## 🛠️ Contributing / Adding New Scripts

When adding new scripts to this repository:
1. Ensure scripts are standalone or clearly document their dependencies.
2. Include docstrings and CLI `--help` flags.
3. Add a brief summary and usage guide to this README.md.
