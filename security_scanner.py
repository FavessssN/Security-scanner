#!/usr/bin/env python3
import os
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
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import aiohttp
import asyncio
from dotenv import load_dotenv
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

class EnhancedSecurityScanner:
    def __init__(self, target: str):
        load_dotenv()
        self.target = target
        self.console = Console()
        self.results = {
            'network_security': {},
            'dns_health': {},
            'endpoint_security': {},
            'application_security': {},
            'information_leakage': {},
            'social_engineering': {},
            'ports': [],
            'services': [],
            'dns_records': [],
            'ssl_info': {},
            'whois_info': {},
            'vulnerabilities': [],
            'cloud_security': {},
            'api_security': {},
            'container_security': {},
            'database_security': {}
        }
        
        # Initialize Slack client if token is available
        self.slack_client = None
        if os.getenv('SLACK_BOT_TOKEN'):
            self.slack_client = WebClient(token=os.getenv('SLACK_BOT_TOKEN'))

    async def assess_network_security(self) -> None:
        """Assess network security including firewall rules, open ports, and network services"""
        self.console.print(f"[bold blue]Starting network security assessment...[/bold blue]")
        
        # Use basic TCP connect scan
        scanner = nmap.PortScanner()
        try:
            scanner.scan(self.target, arguments='-sT -Pn -F')
            
            for host in scanner.all_hosts():
                self.results['network_security']['os_info'] = scanner[host].get('osmatch', [])
                for proto in scanner[host].all_protocols():
                    ports = scanner[host][proto].keys()
                    for port in ports:
                        service = scanner[host][proto][port]
                        self.results['ports'].append({
                            'port': port,
                            'state': service['state'],
                            'service': service['name'],
                            'version': service.get('version', 'unknown')
                        })
        except Exception as e:
            self.console.print(f"[yellow]Warning: Network security assessment error: {str(e)}[/yellow]")

    async def assess_dns_health(self) -> None:
        """Assess DNS health including DNSSEC, DNS records, and DNS security best practices"""
        self.console.print(f"[bold blue]Starting DNS health assessment...[/bold blue]")
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA']
        dns_health_issues = []
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                self.results['dns_records'].append({
                    'type': record_type,
                    'records': [str(rdata) for rdata in answers]
                })
            except dns.resolver.NoAnswer:
                dns_health_issues.append(f"No {record_type} records found")
            except Exception as e:
                dns_health_issues.append(f"Error checking {record_type} records: {str(e)}")
        
        self.results['dns_health']['issues'] = dns_health_issues

    async def assess_endpoint_security(self) -> None:
        """Assess endpoint security including open ports, services, and potential vulnerabilities"""
        self.console.print(f"[bold blue]Starting endpoint security assessment...[/bold blue]")
        
        # Use basic TCP connect scan with version detection
        scanner = nmap.PortScanner()
        try:
            scanner.scan(self.target, arguments='-sT -Pn -sV -F')
            
            vulnerabilities = []
            for host in scanner.all_hosts():
                for proto in scanner[host].all_protocols():
                    ports = scanner[host][proto].keys()
                    for port in ports:
                        service = scanner[host][proto][port]
                        if service.get('version', '') != '':
                            vulnerabilities.append({
                                'port': port,
                                'service': service['name'],
                                'version': service.get('version', 'unknown'),
                                'state': service['state']
                            })
            
            self.results['endpoint_security']['vulnerabilities'] = vulnerabilities
        except Exception as e:
            self.console.print(f"[yellow]Warning: Endpoint security assessment error: {str(e)}[/yellow]")

    async def assess_application_security(self) -> None:
        """Assess application security including web vulnerabilities and security headers"""
        self.console.print(f"[bold blue]Starting application security assessment...[/bold blue]")
        
        security_headers = {}
        web_vulnerabilities = []
        
        try:
            response = requests.get(f"https://{self.target}", verify=False)
            headers = response.headers
            
            # Check for important security headers
            important_headers = [
                'Strict-Transport-Security',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Content-Security-Policy'
            ]
            
            for header in important_headers:
                security_headers[header] = headers.get(header, 'Not Set')
                if header not in headers:
                    web_vulnerabilities.append(f"Missing security header: {header}")
            
            # Check for common web vulnerabilities
            if 'X-Frame-Options' not in headers:
                web_vulnerabilities.append("Potential Clickjacking vulnerability")
            if 'X-Content-Type-Options' not in headers:
                web_vulnerabilities.append("Potential MIME-type sniffing vulnerability")
            
            self.results['application_security']['headers'] = security_headers
            self.results['application_security']['vulnerabilities'] = web_vulnerabilities
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Application security assessment error: {str(e)}[/yellow]")

    async def assess_information_leakage(self) -> None:
        """Assess information leakage through various sources"""
        self.console.print(f"[bold blue]Starting information leakage assessment...[/bold blue]")
        
        leaks = []
        
        # Check for common information leakage sources
        try:
            # Check robots.txt
            robots_response = requests.get(f"https://{self.target}/robots.txt", verify=False)
            if robots_response.status_code == 200:
                leaks.append("robots.txt file accessible")
            
            # Check for common sensitive files
            sensitive_files = ['/.git', '/.env', '/config.php', '/wp-config.php']
            for file in sensitive_files:
                try:
                    response = requests.get(f"https://{self.target}{file}", verify=False)
                    if response.status_code == 200:
                        leaks.append(f"Sensitive file accessible: {file}")
                except:
                    continue
                    
            # Check for directory listing
            try:
                response = requests.get(f"https://{self.target}/images/", verify=False)
                if "Index of /images/" in response.text:
                    leaks.append("Directory listing enabled")
            except:
                pass
                
        except Exception as e:
            self.console.print(f"[yellow]Warning: Information leakage assessment error: {str(e)}[/yellow]")
        
        self.results['information_leakage']['findings'] = leaks

    async def assess_social_engineering(self) -> None:
        """Assess social engineering risks"""
        self.console.print(f"[bold blue]Starting social engineering assessment...[/bold blue]")
        
        risks = []
        
        try:
            # Check for email security (SPF, DKIM, DMARC)
            txt_records = dns.resolver.resolve(self.target, 'TXT')
            for record in txt_records:
                if 'v=spf1' in str(record):
                    risks.append("SPF record found")
                if 'v=DKIM1' in str(record):
                    risks.append("DKIM record found")
                if 'v=DMARC1' in str(record):
                    risks.append("DMARC record found")
                    
            # Check for missing email security records
            if not any('v=spf1' in str(record) for record in txt_records):
                risks.append("No SPF record found - email spoofing risk")
            if not any('v=DMARC1' in str(record) for record in txt_records):
                risks.append("No DMARC record found - email spoofing risk")
                
        except Exception as e:
            self.console.print(f"[yellow]Warning: Social engineering assessment error: {str(e)}[/yellow]")
        
        self.results['social_engineering']['risks'] = risks

    async def assess_ssl_security(self) -> None:
        """Assess SSL/TLS security including certificate validity, cipher suites, and protocols"""
        self.console.print(f"[bold blue]Starting SSL/TLS security assessment...[/bold blue]")
        
        ssl_info = {}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info['certificate'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'expiry': datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z'),
                        'version': cert['version'],
                        'serialNumber': cert['serialNumber']
                    }
                    ssl_info['cipher'] = ssock.cipher()
                    ssl_info['protocol'] = ssock.version()
                    
        except Exception as e:
            self.console.print(f"[yellow]Warning: SSL security assessment error: {str(e)}[/yellow]")
            
        self.results['ssl_info'] = ssl_info

    async def assess_cloud_security(self) -> None:
        """Assess cloud security including S3 buckets, storage exposure, and service misconfigurations"""
        self.console.print(f"[bold blue]Starting cloud security assessment...[/bold blue]")
        
        cloud_issues = []
        try:
            # Check for S3 bucket misconfigurations
            s3_urls = [
                f"https://{self.target}.s3.amazonaws.com",
                f"https://s3.amazonaws.com/{self.target}"
            ]
            for url in s3_urls:
                try:
                    response = requests.get(url, verify=False)
                    if response.status_code == 200:
                        cloud_issues.append(f"Potentially exposed S3 bucket: {url}")
                except:
                    continue
                    
            # Check for cloud storage exposure
            storage_urls = [
                f"https://storage.googleapis.com/{self.target}",
                f"https://{self.target}.blob.core.windows.net"
            ]
            for url in storage_urls:
                try:
                    response = requests.get(url, verify=False)
                    if response.status_code == 200:
                        cloud_issues.append(f"Potentially exposed cloud storage: {url}")
                except:
                    continue
                    
        except Exception as e:
            self.console.print(f"[yellow]Warning: Cloud security assessment error: {str(e)}[/yellow]")
            
        self.results['cloud_security'] = {'issues': cloud_issues}

    async def assess_api_security(self) -> None:
        """Assess API security including endpoint enumeration and authentication checks"""
        self.console.print(f"[bold blue]Starting API security assessment...[/bold blue]")
        
        api_issues = []
        common_endpoints = [
            '/api/v1',
            '/api/v2',
            '/api',
            '/graphql',
            '/swagger',
            '/swagger-ui.html',
            '/api-docs'
        ]
        
        try:
            for endpoint in common_endpoints:
                try:
                    response = requests.get(f"https://{self.target}{endpoint}", verify=False)
                    if response.status_code != 404:
                        api_issues.append(f"Potential API endpoint discovered: {endpoint}")
                        
                        # Check for authentication
                        if response.status_code == 401 or response.status_code == 403:
                            api_issues.append(f"Authentication required for endpoint: {endpoint}")
                        else:
                            api_issues.append(f"Potential unauthenticated endpoint: {endpoint}")
                            
                except:
                    continue
                    
        except Exception as e:
            self.console.print(f"[yellow]Warning: API security assessment error: {str(e)}[/yellow]")
            
        self.results['api_security'] = {'issues': api_issues}

    async def assess_container_security(self) -> None:
        """Assess container security including Docker and Kubernetes configurations"""
        self.console.print(f"[bold blue]Starting container security assessment...[/bold blue]")
        
        container_issues = []
        try:
            # Check for Docker registry exposure
            docker_urls = [
                f"https://{self.target}/v2/_catalog",
                f"https://registry.{self.target}/v2/_catalog"
            ]
            for url in docker_urls:
                try:
                    response = requests.get(url, verify=False)
                    if response.status_code == 200:
                        container_issues.append(f"Potentially exposed Docker registry: {url}")
                except:
                    continue
                    
            # Check for Kubernetes API exposure
            k8s_urls = [
                f"https://{self.target}/api/v1",
                f"https://k8s.{self.target}/api/v1"
            ]
            for url in k8s_urls:
                try:
                    response = requests.get(url, verify=False)
                    if response.status_code == 200:
                        container_issues.append(f"Potentially exposed Kubernetes API: {url}")
                except:
                    continue
                    
        except Exception as e:
            self.console.print(f"[yellow]Warning: Container security assessment error: {str(e)}[/yellow]")
            
        self.results['container_security'] = {'issues': container_issues}

    async def assess_database_security(self) -> None:
        """Assess database security including type detection and misconfigurations"""
        self.console.print(f"[bold blue]Starting database security assessment...[/bold blue]")
        
        db_issues = []
        try:
            # Check for common database ports
            db_ports = {
                3306: 'MySQL',
                5432: 'PostgreSQL',
                27017: 'MongoDB',
                6379: 'Redis',
                1433: 'MSSQL'
            }
            
            for port, db_type in db_ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((self.target, port))
                    if result == 0:
                        db_issues.append(f"Potential {db_type} database exposed on port {port}")
                    sock.close()
                except:
                    continue
                    
        except Exception as e:
            self.console.print(f"[yellow]Warning: Database security assessment error: {str(e)}[/yellow]")
            
        self.results['database_security'] = {'issues': db_issues}

    def generate_report(self) -> None:
        """Generate a comprehensive security assessment report"""
        self.console.print("\n[bold green]Enhanced Security Assessment Report[/bold green]")
        self.console.print(f"Target: {self.target}")
        self.console.print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        # Network Security
        if self.results['network_security']:
            self.console.print(Panel(f"""
Network Security Assessment:
OS Information: {self.results['network_security'].get('os_info', 'Unknown')}
Open Ports: {len(self.results['ports'])}
            """, title="Network Security"))

        # DNS Health
        if self.results['dns_health']:
            dns_issues = self.results['dns_health'].get('issues', [])
            self.console.print(Panel(f"""
DNS Health Assessment:
Issues Found: {len(dns_issues)}
Issues: {', '.join(dns_issues) if dns_issues else 'None'}
            """, title="DNS Health"))

        # Endpoint Security
        if self.results['endpoint_security']:
            vulns = self.results['endpoint_security'].get('vulnerabilities', [])
            self.console.print(Panel(f"""
Endpoint Security:
Vulnerabilities Found: {len(vulns)}
            """, title="Endpoint Security"))

        # Application Security
        if self.results['application_security']:
            headers = self.results['application_security'].get('headers', {})
            web_vulns = self.results['application_security'].get('vulnerabilities', [])
            self.console.print(Panel(f"""
Application Security:
Security Headers: {', '.join(headers.keys())}
Web Vulnerabilities: {len(web_vulns)}
            """, title="Application Security"))

        # Information Leakage
        if self.results['information_leakage']:
            leaks = self.results['information_leakage'].get('findings', [])
            self.console.print(Panel(f"""
Information Leakage:
Findings: {len(leaks)}
Issues: {', '.join(leaks) if leaks else 'None'}
            """, title="Information Leakage"))

        # Social Engineering
        if self.results['social_engineering']:
            risks = self.results['social_engineering'].get('risks', [])
            self.console.print(Panel(f"""
Social Engineering Risks:
Email Security Features: {', '.join(risks) if risks else 'None'}
            """, title="Social Engineering"))

        # SSL/TLS Security
        if self.results['ssl_info']:
            ssl_info = self.results['ssl_info']
            self.console.print(Panel(f"""
SSL/TLS Security Assessment:
Certificate:
Subject: {', '.join(f'{k}: {v}' for k, v in ssl_info['certificate'].items())}
Issuer: {', '.join(f'{k}: {v}' for k, v in ssl_info['certificate'].get('issuer', {}).items())}
Expiry: {ssl_info['certificate']['expiry'].strftime('%Y-%m-%d %H:%M:%S')}
Version: {ssl_info['certificate']['version']}
Serial Number: {ssl_info['certificate']['serialNumber']}
Cipher: {ssl_info['cipher']}
Protocol: {ssl_info['protocol']}
            """, title="SSL/TLS Security"))

        # Cloud Security
        if self.results['cloud_security']:
            issues = self.results['cloud_security'].get('issues', [])
            self.console.print(Panel(f"""
Cloud Security Assessment:
Issues Found: {len(issues)}
Issues: {', '.join(issues) if issues else 'None'}
            """, title="Cloud Security"))

        # API Security
        if self.results['api_security']:
            issues = self.results['api_security'].get('issues', [])
            self.console.print(Panel(f"""
API Security Assessment:
Issues Found: {len(issues)}
Issues: {', '.join(issues) if issues else 'None'}
            """, title="API Security"))

        # Container Security
        if self.results['container_security']:
            issues = self.results['container_security'].get('issues', [])
            self.console.print(Panel(f"""
Container Security Assessment:
Issues Found: {len(issues)}
Issues: {', '.join(issues) if issues else 'None'}
            """, title="Container Security"))

        # Database Security
        if self.results['database_security']:
            issues = self.results['database_security'].get('issues', [])
            self.console.print(Panel(f"""
Database Security Assessment:
Issues Found: {len(issues)}
Issues: {', '.join(issues) if issues else 'None'}
            """, title="Database Security"))

    async def send_slack_report(self) -> None:
        """Send the assessment report to Slack"""
        if not self.slack_client:
            self.console.print("[yellow]Skipping Slack report - no Slack token configured[/yellow]")
            return
            
        try:
            # Create a formatted message for Slack
            message = f"""
*Security Assessment Report for {self.target}*
Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

*Network Security*
• Open Ports: {len(self.results['ports'])}
• OS Information: {self.results['network_security'].get('os_info', 'Unknown')}

*DNS Health*
• Issues Found: {len(self.results['dns_health'].get('issues', []))}

*Endpoint Security*
• Vulnerabilities Found: {len(self.results['endpoint_security'].get('vulnerabilities', []))}

*Application Security*
• Security Headers: {', '.join(self.results['application_security'].get('headers', {}).keys())}
• Web Vulnerabilities: {len(self.results['application_security'].get('vulnerabilities', []))}

*Information Leakage*
• Findings: {len(self.results['information_leakage'].get('findings', []))}

*Social Engineering*
• Email Security Features: {', '.join(self.results['social_engineering'].get('risks', []))}

*SSL/TLS Security*
• Certificate:
  Subject: {', '.join(f'{k}: {v}' for k, v in self.results['ssl_info']['certificate'].items())}
  Issuer: {', '.join(f'{k}: {v}' for k, v in self.results['ssl_info']['certificate'].get('issuer', {}).items())}
  Expiry: {self.results['ssl_info']['certificate']['expiry'].strftime('%Y-%m-%d %H:%M:%S')}
  Version: {self.results['ssl_info']['certificate']['version']}
  Serial Number: {self.results['ssl_info']['certificate']['serialNumber']}
• Cipher: {self.results['ssl_info']['cipher']}
• Protocol: {self.results['ssl_info']['protocol']}

*Cloud Security*
• Issues Found: {len(self.results['cloud_security'].get('issues', []))}
• Issues: {', '.join(self.results['cloud_security'].get('issues', [])) if self.results['cloud_security'].get('issues', []) else 'None'}

*API Security*
• Issues Found: {len(self.results['api_security'].get('issues', []))}
• Issues: {', '.join(self.results['api_security'].get('issues', [])) if self.results['api_security'].get('issues', []) else 'None'}

*Container Security*
• Issues Found: {len(self.results['container_security'].get('issues', []))}
• Issues: {', '.join(self.results['container_security'].get('issues', [])) if self.results['container_security'].get('issues', []) else 'None'}

*Database Security*
• Issues Found: {len(self.results['database_security'].get('issues', []))}
• Issues: {', '.join(self.results['database_security'].get('issues', [])) if self.results['database_security'].get('issues', []) else 'None'}
"""
            
            # Send the message to Slack
            self.slack_client.chat_postMessage(
                channel=os.getenv('SLACK_CHANNEL'),
                text=message,
                parse='mrkdwn'
            )
        except SlackApiError as e:
            self.console.print(f"[red]Error sending Slack message: {str(e)}[/red]")

async def main():
    parser = argparse.ArgumentParser(description='Enhanced Security Assessment Tool')
    parser.add_argument('target', help='Target domain or IP address')
    parser.add_argument('--ports', default='1-1024', help='Port range to scan (default: 1-1024)')
    args = parser.parse_args()

    scanner = EnhancedSecurityScanner(args.target)
    
    try:
        # Run all assessments concurrently
        await asyncio.gather(
            scanner.assess_network_security(),
            scanner.assess_dns_health(),
            scanner.assess_endpoint_security(),
            scanner.assess_application_security(),
            scanner.assess_information_leakage(),
            scanner.assess_social_engineering(),
            scanner.assess_ssl_security(),
            scanner.assess_cloud_security(),
            scanner.assess_api_security(),
            scanner.assess_container_security(),
            scanner.assess_database_security()
        )
        
        # Generate and send reports
        scanner.generate_report()
        await scanner.send_slack_report()
        
    except KeyboardInterrupt:
        print("\n[red]Scan interrupted by user[/red]")
        sys.exit(1)
    except Exception as e:
        print(f"\n[red]An error occurred: {str(e)}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 