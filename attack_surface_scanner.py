#!/usr/bin/env python3
import nmap
import dns.resolver
import requests
import ssl
import socket
import whois
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from typing import List, Dict, Any
import argparse
import sys

class AttackSurfaceScanner:
    def __init__(self, target: str):
        self.target = target
        self.console = Console()
        self.results = {
            'ports': [],
            'services': [],
            'dns_records': [],
            'ssl_info': {},
            'whois_info': {},
            'vulnerabilities': []
        }

    def port_scan(self, ports: str = "1-1024") -> None:
        """Perform port scanning using nmap"""
        self.console.print(f"[bold blue]Starting port scan on {self.target}...[/bold blue]")
        scanner = nmap.PortScanner()
        scanner.scan(self.target, ports)
        
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports:
                    state = scanner[host][proto][port]['state']
                    service = scanner[host][proto][port]['name']
                    self.results['ports'].append({
                        'port': port,
                        'state': state,
                        'service': service
                    })

    def dns_scan(self) -> None:
        """Perform DNS reconnaissance"""
        self.console.print(f"[bold blue]Starting DNS scan on {self.target}...[/bold blue]")
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                self.results['dns_records'].append({
                    'type': record_type,
                    'records': [str(rdata) for rdata in answers]
                })
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                self.console.print(f"[red]Domain {self.target} does not exist[/red]")
                sys.exit(1)

    def ssl_scan(self) -> None:
        """Analyze SSL/TLS configuration"""
        self.console.print(f"[bold blue]Starting SSL/TLS analysis on {self.target}...[/bold blue]")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    self.results['ssl_info'] = {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'expiry': datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z'),
                        'version': cert['version'],
                        'cipher': ssock.cipher()
                    }
        except Exception as e:
            self.console.print(f"[red]SSL/TLS scan failed: {str(e)}[/red]")

    def whois_lookup(self) -> None:
        """Perform WHOIS lookup"""
        self.console.print(f"[bold blue]Starting WHOIS lookup on {self.target}...[/bold blue]")
        try:
            w = whois.whois(self.target)
            self.results['whois_info'] = {
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date
            }
        except Exception as e:
            self.console.print(f"[red]WHOIS lookup failed: {str(e)}[/red]")

    def generate_report(self) -> None:
        """Generate a formatted report of findings"""
        self.console.print("\n[bold green]Attack Surface Assessment Report[/bold green]")
        self.console.print(f"Target: {self.target}")
        self.console.print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        # Port Scan Results
        if self.results['ports']:
            ports_table = Table(title="Open Ports and Services")
            ports_table.add_column("Port", style="cyan")
            ports_table.add_column("State", style="green")
            ports_table.add_column("Service", style="yellow")
            
            for port_info in self.results['ports']:
                ports_table.add_row(
                    str(port_info['port']),
                    port_info['state'],
                    port_info['service']
                )
            self.console.print(ports_table)

        # DNS Records
        if self.results['dns_records']:
            dns_table = Table(title="DNS Records")
            dns_table.add_column("Record Type", style="cyan")
            dns_table.add_column("Records", style="yellow")
            
            for record in self.results['dns_records']:
                dns_table.add_row(record['type'], "\n".join(record['records']))
            self.console.print(dns_table)

        # SSL/TLS Information
        if self.results['ssl_info']:
            ssl_info = self.results['ssl_info']
            self.console.print(Panel(f"""
SSL/TLS Information:
Issuer: {ssl_info['issuer']}
Expiry: {ssl_info['expiry']}
Version: {ssl_info['version']}
Cipher: {ssl_info['cipher']}
            """, title="SSL/TLS Analysis"))

        # WHOIS Information
        if self.results['whois_info']:
            whois_info = self.results['whois_info']
            self.console.print(Panel(f"""
WHOIS Information:
Registrar: {whois_info['registrar']}
Creation Date: {whois_info['creation_date']}
Expiration Date: {whois_info['expiration_date']}
            """, title="WHOIS Information"))

def main():
    parser = argparse.ArgumentParser(description='Attack Surface Assessment Tool')
    parser.add_argument('target', help='Target domain or IP address')
    parser.add_argument('--ports', default='1-1024', help='Port range to scan (default: 1-1024)')
    args = parser.parse_args()

    scanner = AttackSurfaceScanner(args.target)
    
    try:
        scanner.port_scan(args.ports)
        scanner.dns_scan()
        scanner.ssl_scan()
        scanner.whois_lookup()
        scanner.generate_report()
    except KeyboardInterrupt:
        print("\n[red]Scan interrupted by user[/red]")
        sys.exit(1)
    except Exception as e:
        print(f"\n[red]An error occurred: {str(e)}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main() 