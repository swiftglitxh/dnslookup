
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ╔══════════════════════════════════════════════╗
# ║ SCRIPT  : dns_recon.py                       ║
# ║ AUTHOR  : SwiftGlitxh                        ║
# ║ VERSION : 1.1.0                              ║
# ║ LICENSE : MIT                                ║
# ║ ABOUT   : DNS and OSINT reconnaissance       ║
# ╚══════════════════════════════════════════════╝

import argparse
import ipaddress
import logging
import socket
import sys
from urllib.parse import urlsplit

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
logger = logging.getLogger(__name__)

DNS_API = "https://dns-lookup.com/api/dns"
RDAP_BOOTSTRAP = "https://rdap.org/domain/"
REVERSE_IP_API = "https://api.hackertarget.com/reverseiplookup/"

RECORD_TYPES = "A,AAAA,MX,NS,TXT,CNAME,SOA,CAA"
TIMEOUT = 12


class DNS:
    def __init__(self, target: str):
        self.target = target.strip()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SwiftGlitxh-DNS-Recon/1.1"
        })

        self.ip = self._parse_ip(self.target)

        if self.ip is None:
            self.domain = self._parse_domain(self.target)
        else:
            self.domain = None

    @staticmethod
    def _parse_ip(value):
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            return None

    @staticmethod
    def _parse_domain(value):
        parsed = urlsplit(
            value if "://" in value else f"//{value}"
        )

        hostname = parsed.hostname

        if not hostname:
            raise ValueError("Invalid domain or URL")

        hostname = hostname.rstrip(".").lower()

        try:
            hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Invalid domain") from exc

        if (
            len(hostname) > 253
            or "." not in hostname
            or any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                for label in hostname.split(".")
            )
        ):
            raise ValueError("Invalid domain name")

        return hostname

    def request_json(self, url, params=None):
        response = self.session.get(
            url,
            params=params,
            timeout=TIMEOUT
        )
        response.raise_for_status()
        return response.json()

    @staticmethod
    def show_table(title, columns, rows):
        table = Table(
            title=title,
            border_style="red",
            header_style="bold red",
            show_lines=True
        )

        for column in columns:
            table.add_column(column, overflow="fold")

        for row in rows:
            table.add_row(*(str(value) for value in row))

        console.print(table)

    def dns(self):
        if not self.domain:
            console.print(
                "[red]DNS lookup requires a domain.[/]"
            )
            return False

        try:
            data = self.request_json(
                DNS_API,
                params={
                    "domain": self.domain,
                    "types": RECORD_TYPES
                }
            )

            records = data.get("records", [])
            rows = []

            if isinstance(records, dict):
                for record_type, values in records.items():
                    if not isinstance(values, list):
                        values = [values]

                    for value in values:
                        rows.append((record_type, value))

            elif isinstance(records, list):
                for record in records:
                    if isinstance(record, dict):
                        rows.append((
                            record.get("type", "Unknown"),
                            record.get(
                                "value",
                                record.get("data", "N/A")
                            )
                        ))
                    else:
                        rows.append(("Unknown", record))

            if not rows:
                console.print(
                    "[yellow]No DNS records returned.[/]"
                )
                return True

            self.show_table(
                "DNS Records",
                ("Type", "Value"),
                rows
            )
            return True

        except (requests.RequestException, ValueError) as exc:
            logger.error("DNS lookup failed: %s", exc)
            console.print(f"[red]DNS error:[/] {exc}")
            return False

    def resolve_ip(self):
        if self.ip is not None:
            return str(self.ip)

        try:
            addresses = socket.getaddrinfo(
                self.domain,
                None,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM
            )

            return addresses[0][4][0]

        except (socket.gaierror, IndexError) as exc:
            raise ValueError(
                f"Could not resolve {self.domain}"
            ) from exc

    def reverse_dns(self):
        try:
            ip = self.resolve_ip()

            try:
                hostname, aliases, addresses = (
                    socket.gethostbyaddr(ip)
                )

                rows = [
                    ("IP Address", ip),
                    ("Hostname", hostname),
                    ("Aliases", ", ".join(aliases) or "None"),
                    ("Addresses", ", ".join(addresses))
                ]

            except socket.herror:
                rows = [
                    ("IP Address", ip),
                    ("PTR Record", "Not found")
                ]

            self.show_table(
                "Reverse DNS",
                ("Field", "Result"),
                rows
            )
            return True

        except ValueError as exc:
            console.print(f"[red]Reverse DNS error:[/] {exc}")
            return False

    @staticmethod
    def rdap_entities(data):
        names = []

        for entity in data.get("entities", []):
            for entry in entity.get("vcardArray", [None, []])[1]:
                if (
                    isinstance(entry, list)
                    and len(entry) >= 4
                    and entry[0] == "fn"
                ):
                    names.append(str(entry[3]))

        return names

    def whois(self):
        if not self.domain:
            console.print(
                "[red]WHOIS/RDAP requires a domain.[/]"
            )
            return False

        try:
            data = self.request_json(
                RDAP_BOOTSTRAP + self.domain
            )

            rows = [
                ("Domain", data.get("ldhName", self.domain)),
                ("Handle", data.get("handle", "N/A")),
                ("Status", ", ".join(data.get("status", []))),
            ]

            for event in data.get("events", []):
                action = event.get("eventAction", "Unknown")
                date = event.get("eventDate", "N/A")
                rows.append((action.title(), date))

            for server in data.get("nameservers", []):
                rows.append((
                    "Nameserver",
                    server.get("ldhName", "N/A")
                ))

            for name in self.rdap_entities(data):
                rows.append(("Entity", name))

            self.show_table(
                "WHOIS / RDAP",
                ("Field", "Value"),
                rows
            )
            return True

        except (requests.RequestException, ValueError) as exc:
            logger.error("RDAP lookup failed: %s", exc)
            console.print(f"[red]RDAP error:[/] {exc}")
            return False

    def reverse_ip(self):
        try:
            ip = self.resolve_ip()

            if not ipaddress.ip_address(ip).is_global:
                console.print(
                    "[yellow]Reverse IP requires a public "
                    "IP address.[/]"
                )
                return False

            response = self.session.get(
                REVERSE_IP_API,
                params={"q": ip},
                timeout=TIMEOUT
            )
            response.raise_for_status()

            body = response.text.strip()

            if not body:
                console.print(
                    "[yellow]No reverse IP results.[/]"
                )
                return True

            if body.lower().startswith(
                ("error", "api count exceeded")
            ):
                console.print(
                    f"[red]Reverse IP API:[/] {body}"
                )
                return False

            domains = sorted({
                line.strip()
                for line in body.splitlines()
                if line.strip()
            })

            self.show_table(
                f"Reverse IP Results — {ip}",
                ("#", "Domain"),
                [
                    (index, domain)
                    for index, domain in enumerate(
                        domains, start=1
                    )
                ]
            )
            return True

        except (requests.RequestException, ValueError) as exc:
            logger.error("Reverse IP failed: %s", exc)
            console.print(f"[red]Reverse IP error:[/] {exc}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="DNS Recon Toolkit"
    )

    parser.add_argument(
        "target",
        help="Domain, URL, or IP address"
    )

    group = parser.add_mutually_exclusive_group(
        required=True
    )

    group.add_argument(
        "--dns",
        action="store_true",
        help="Retrieve DNS records"
    )

    group.add_argument(
        "--reverse-dns",
        action="store_true",
        help="Perform reverse DNS lookup"
    )

    group.add_argument(
        "--whois",
        action="store_true",
        help="Retrieve WHOIS/RDAP registration data"
    )

    group.add_argument(
        "--reverse-ip",
        action="store_true",
        help="Find domains associated with an IP"
    )

    group.add_argument(
        "--all",
        action="store_true",
        help="Run all applicable lookups"
    )

    args = parser.parse_args()

    try:
        lookup = DNS(args.target)
    except ValueError as exc:
        parser.error(str(exc))

    console.print(
        Panel(
            f"[bold white]Target:[/] {args.target}",
            title="[bold red]DNS RECON[/]",
            border_style="red"
        )
    )

    if args.dns:
        success = lookup.dns()

    elif args.reverse_dns:
        success = lookup.reverse_dns()

    elif args.whois:
        success = lookup.whois()

    elif args.reverse_ip:
        success = lookup.reverse_ip()

    else:
        results = []

        if lookup.domain:
            results.append(lookup.dns())
            results.append(lookup.whois())

        results.append(lookup.reverse_dns())
        results.append(lookup.reverse_ip())

        success = all(results)

    lookup.session.close()

    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
