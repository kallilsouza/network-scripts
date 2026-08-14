#!/usr/bin/env python3
"""
DNS / NSLookup Tool in Python 3.12+

Accepts a URL, site address, or domain name and retrieves DNS / nslookup
information using Python's standard library with optional support for
the system `nslookup` utility and `dnspython` (if installed).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse


def extract_domain(input_str: str) -> str:
    """Extract a clean hostname/domain from a URL or raw site address.

    Handles:
      - 'https://www.example.com/path?arg=1' -> 'www.example.com'
      - 'http://example.com:8080'           -> 'example.com'
      - 'sub.domain.org/path'               -> 'sub.domain.org'
      - 'user:pass@example.com'             -> 'example.com'
      - '1.1.1.1'                           -> '1.1.1.1'
    """
    clean_str = input_str.strip()

    # Prepend a scheme if missing so urlparse handles path-like URLs correctly
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean_str):
        parsed = urlparse(f"http://{clean_str}")
    else:
        parsed = urlparse(clean_str)

    hostname = parsed.hostname or clean_str.split("/")[0].split(":")[0]

    # Remove trailing dots, spaces, or rogue characters
    hostname = hostname.strip().rstrip(".")
    if not hostname:
        raise ValueError(f"Could not extract a valid domain name from '{input_str}'")

    return hostname


@dataclass
class RecordInfo:
    record_type: str
    values: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class NSLookupResult:
    input_target: str
    resolved_domain: str
    is_ip: bool = False
    canonical_name: str | None = None
    ipv4_addresses: list[str] = field(default_factory=list)
    ipv6_addresses: list[str] = field(default_factory=list)
    reverse_dns: str | None = None
    records: dict[str, list[str]] = field(default_factory=dict)
    system_nslookup_output: str | None = None
    errors: list[str] = field(default_factory=list)


def query_system_nslookup(
    domain: str, dns_server: str | None = None, record_type: str | None = None
) -> str | None:
    """Execute the system `nslookup` command if available."""
    nslookup_path = shutil.which("nslookup")
    if not nslookup_path:
        return None

    cmd = [nslookup_path]
    if record_type and record_type.upper() != "ALL":
        cmd.append(f"-type={record_type.upper()}")
    cmd.append(domain)
    if dns_server:
        cmd.append(dns_server)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return (proc.stdout + proc.stderr).strip()
    except (subprocess.SubprocessError, OSError) as exc:
        return f"Failed to execute nslookup: {exc}"


def query_dnspython(
    domain: str,
    record_types: list[str],
    dns_server: str | None = None,
) -> dict[str, list[str]]:
    """Query DNS records using `dnspython` if available."""
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return {}

    resolver = dns.resolver.Resolver()
    if dns_server:
        resolver.nameservers = [dns_server]

    results: dict[str, list[str]] = {}
    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype, lifetime=5)
            results[rtype] = [str(rdata) for rdata in answers]
        except Exception:  # NXDOMAIN, NoAnswer, Timeout, etc.
            continue

    return results


def perform_nslookup(
    target: str,
    dns_server: str | None = None,
    record_type: str | None = None,
    include_system_output: bool = True,
) -> NSLookupResult:
    """Perform a comprehensive DNS/NSLookup investigation for the given target."""
    domain = extract_domain(target)
    result = NSLookupResult(input_target=target, resolved_domain=domain)

    # Check if the target is an IP address
    try:
        ip_obj = ipaddress.ip_address(domain)
        result.is_ip = True
        if isinstance(ip_obj, ipaddress.IPv4Address):
            result.ipv4_addresses.append(domain)
        else:
            result.ipv6_addresses.append(domain)

        # Reverse DNS lookup for IP
        try:
            host, _, _ = socket.gethostbyaddr(domain)
            result.reverse_dns = host
        except socket.herror:
            result.reverse_dns = "No PTR record found"
    except ValueError:
        result.is_ip = False

    # Standard Library DNS Resolution (socket.getaddrinfo & socket.getfqdn)
    if not result.is_ip:
        try:
            # Canonical name
            canon_name = socket.getfqdn(domain)
            if canon_name and canon_name != domain:
                result.canonical_name = canon_name
        except Exception as exc:
            result.errors.append(f"Canonical name lookup: {exc}")

        # IPv4 and IPv6 resolution
        try:
            addr_info = socket.getaddrinfo(
                domain,
                80,
                proto=socket.IPPROTO_TCP,
                flags=socket.AI_CANONNAME,
            )
            ipv4_set: set[str] = set()
            ipv6_set: set[str] = set()

            for family, _, _, canon, sockaddr in addr_info:
                if canon and not result.canonical_name:
                    result.canonical_name = canon
                ip = sockaddr[0]
                if family == socket.AF_INET:
                    ipv4_set.add(ip)
                elif family == socket.AF_INET6:
                    ipv6_set.add(ip)

            result.ipv4_addresses = sorted(ipv4_set)
            result.ipv6_addresses = sorted(ipv6_set)
        except socket.gaierror as exc:
            result.errors.append(f"Standard address resolution failed: {exc}")

    # dnspython extended query (if installed)
    types_to_query = (
        [record_type.upper()]
        if (record_type and record_type.upper() != "ALL")
        else ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "CAA"]
    )
    py_dns_records = query_dnspython(domain, types_to_query, dns_server)
    if py_dns_records:
        result.records.update(py_dns_records)

    # System `nslookup` command execution
    if include_system_output:
        sys_out = query_system_nslookup(domain, dns_server, record_type)
        if sys_out:
            result.system_nslookup_output = sys_out

    return result


def display_results(result: NSLookupResult, verbose: bool = False) -> None:
    """Format and print the lookup results nicely in the terminal."""
    divider = "=" * 64
    sub_divider = "-" * 64

    print(f"\n{divider}")
    print(f"  NSLOOKUP & DNS INFORMATION")
    print(f"{divider}")
    print(f"Target Input     : {result.input_target}")
    print(f"Target Domain/IP : {result.resolved_domain}")

    if result.is_ip:
        print(f"Type             : IP Address")
        if result.reverse_dns:
            print(f"Reverse DNS (PTR): {result.reverse_dns}")
    else:
        if result.canonical_name:
            print(f"Canonical Name   : {result.canonical_name}")

        print(f"\n{sub_divider}")
        print("  IP ADDRESSES (Standard Resolution)")
        print(f"{sub_divider}")
        if result.ipv4_addresses:
            print("IPv4 (A) Records :")
            for ip in result.ipv4_addresses:
                print(f"  • {ip}")
        else:
            print("IPv4 (A) Records : None found")

        if result.ipv6_addresses:
            print("IPv6 (AAAA) Records:")
            for ip in result.ipv6_addresses:
                print(f"  • {ip}")
        elif verbose:
            print("IPv6 (AAAA) Records: None found")

    # Additional dnspython records if any were resolved
    if result.records:
        print(f"\n{sub_divider}")
        print("  DNS RECORDS (Extended Resolution)")
        print(f"{sub_divider}")
        for rtype, values in result.records.items():
            print(f"{rtype} Records:")
            for val in values:
                print(f"  • {val}")

    # System nslookup command raw output
    if result.system_nslookup_output:
        print(f"\n{sub_divider}")
        print("  SYSTEM `nslookup` COMMAND OUTPUT")
        print(f"{sub_divider}")
        print(result.system_nslookup_output)

    if result.errors:
        print(f"\n{sub_divider}")
        print("  NOTICES / ERRORS")
        print(f"{sub_divider}")
        for err in result.errors:
            print(f"  [!] {err}")

    print(f"{divider}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Query DNS / nslookup info for any URL or domain address.",
        epilog="Examples:\n"
        "  python nslookup_tool.py https://github.com\n"
        "  python nslookup_tool.py google.com --dns-server 8.8.8.8\n"
        "  python nslookup_tool.py example.com --type MX\n"
        "  python nslookup_tool.py cloudflare.com --json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="URL or domain/site address (e.g. 'https://example.com' or 'example.com')",
    )
    parser.add_argument(
        "-s",
        "--dns-server",
        dest="dns_server",
        help="Specific DNS server to query (e.g. '8.8.8.8' or '1.1.1.1')",
    )
    parser.add_argument(
        "-t",
        "--type",
        dest="record_type",
        default=None,
        help="DNS record type to look up (e.g. A, AAAA, MX, NS, TXT, CNAME, SOA, ALL)",
    )
    parser.add_argument(
        "--no-system",
        dest="no_system",
        action="store_true",
        help="Do not run the system `nslookup` binary (pure Python only)",
    )
    parser.add_argument(
        "--json",
        dest="output_json",
        action="store_true",
        help="Output results as structured JSON",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_true",
        help="Display verbose output",
    )

    args = parser.parse_args()

    # If no target passed as argument, prompt the user interactively
    target = args.target
    if not target:
        try:
            target = input("Enter a URL or site address: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(0)

    if not target:
        parser.print_help()
        sys.exit(1)

    try:
        result = perform_nslookup(
            target=target,
            dns_server=args.dns_server,
            record_type=args.record_type,
            include_system_output=not args.no_system,
        )
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.output_json:
        print(json.dumps(asdict(result), indent=2))
    else:
        display_results(result, verbose=args.verbose)


if __name__ == "__main__":
    main()
