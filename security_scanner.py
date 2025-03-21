#!/usr/bin/env python3
import os
import dns.resolver
import requests
import socket
import whois
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from typing import List, Dict, Any
import argparse
import sys
import aiohttp
import asyncio
from dotenv import load_dotenv
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import ssl
import json
import threading
import queue
import time
from concurrent.futures import ThreadPoolExecutor
import sqlite3
from pathlib import Path
import re
import email
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import hashlib
import base64
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional

# Initialize FastAPI app
app = FastAPI(title="Security Scanner API")

class ScanRequest(BaseModel):
    target: Optional[str] = None
    email: Optional[str] = None
    profile: str = "standard"
    slack_channel: Optional[str] = None

class SecurityScanner:
    def __init__(self, target: str = None, email: str = None):
        load_dotenv()
        self.target = target
        self.email = email
        self.console = Console()
        self.results = {
            'network_security': {},
            'dns_health': {},
            'email_security': {},
            'endpoint_security': {},
            'application_security': {},
            'vulnerability_assessment': {},
            'ip_reputation': {},
            'ssl_tls_security': {},
            'cloud_security': {},
            'api_security': {},
            'container_security': {},
            'database_security': {},
            'patching_status': {},
            'compliance': {},
            'asset_inventory': {},
            'team_collaboration': {},
            'scan_profiles': {},
            'real_time_monitoring': {},
            'historical_data': {}
        }
        
        # Initialize database for historical data
        self.init_database()
        
        # Initialize Slack client if token is available
        self.slack_client = None
        if os.getenv('SLACK_BOT_TOKEN'):
            self.slack_client = WebClient(token=os.getenv('SLACK_BOT_TOKEN'))
            
        # Initialize scan profiles
        self.scan_profiles = {
            'quick': {
                'vuln_scan': False,
                'compliance': False
            },
            'standard': {
                'vuln_scan': True,
                'compliance': True
            },
            'comprehensive': {
                'vuln_scan': True,
                'compliance': True
            }
        }

    def init_database(self):
        """Initialize SQLite database for historical data"""
        db_path = Path('security_scanner.db')
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Create tables for historical data
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                scan_date DATETIME,
                scan_type TEXT,
                findings TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                vuln_type TEXT,
                description TEXT,
                severity TEXT,
                discovery_date DATETIME
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                asset_type TEXT,
                details TEXT,
                discovery_date DATETIME
            )
        ''')
        
        conn.commit()
        conn.close()

    async def assess_network_security(self) -> None:
        """Perform passive network security assessment"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting passive network security assessment...[/bold blue]")
        
        network_info = {
            'ip_info': {},
            'dns_info': {},
            'whois_info': {},
            'passive_port_info': {},
            'passive_service_info': {}
        }
        
        try:
            # Get IP information
            try:
                ip_info = socket.gethostbyname(self.target)
                network_info['ip_info']['ip'] = ip_info
                
                # Get ASN information using IP-API
                response = requests.get(f'http://ip-api.com/json/{ip_info}', timeout=5)
                if response.status_code == 200:
                    asn_info = response.json()
                    network_info['ip_info']['asn'] = asn_info.get('as')
                    network_info['ip_info']['isp'] = asn_info.get('isp')
                    network_info['ip_info']['country'] = asn_info.get('country')
            except Exception as e:
                network_info['ip_info']['error'] = str(e)
            
            # Get DNS information
            try:
                dns_records = {}
                record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA']
                
                for record_type in record_types:
                    try:
                        records = dns.resolver.resolve(self.target, record_type)
                        dns_records[record_type] = [str(r) for r in records]
                    except:
                        dns_records[record_type] = []
                
                network_info['dns_info'] = dns_records
            except Exception as e:
                network_info['dns_info']['error'] = str(e)
            
            # Get WHOIS information
            try:
                w = whois.whois(self.target)
                network_info['whois_info'] = {
                    'registrar': w.registrar,
                    'creation_date': str(w.creation_date),
                    'expiration_date': str(w.expiration_date),
                    'name_servers': w.name_servers
                }
            except Exception as e:
                network_info['whois_info']['error'] = str(e)
            
            # Get passive port and service information from Shodan
            try:
                shodan_api_key = os.getenv('SHODAN_API_KEY')
                if shodan_api_key:
                    response = requests.get(
                        f'https://api.shodan.io/shodan/host/{ip_info}',
                        params={'key': shodan_api_key},
                        timeout=5
                    )
                    if response.status_code == 200:
                        shodan_data = response.json()
                        network_info['passive_port_info'] = {
                            'ports': shodan_data.get('ports', []),
                            'hostnames': shodan_data.get('hostnames', []),
                            'vulns': shodan_data.get('vulns', [])
                        }
                        network_info['passive_service_info'] = {
                            'services': shodan_data.get('data', [])
                        }
            except Exception as e:
                network_info['passive_port_info']['error'] = str(e)
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Network security assessment error: {str(e)}[/yellow]")
            
        self.results['network_security'] = network_info

    async def assess_dns_health(self) -> None:
        """Perform DNS health assessment"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting DNS health assessment...[/bold blue]")
        
        dns_health = {
            'security_records': {},
            'issues': []
        }
        
        try:
            # Check for security records
            dns_records = {}
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA']
            
            for record_type in record_types:
                try:
                    records = dns.resolver.resolve(self.target, record_type)
                    dns_records[record_type] = [str(r) for r in records]
                except:
                    dns_records[record_type] = []
            
            dns_health['security_records'] = dns_records
            
            # Check for issues
            issues = []
            
            # Check for missing DNS records
            if not dns_records.get('A') or not dns_records.get('AAAA'):
                issues.append('Missing A or AAAA DNS records')
            
            # Check for missing MX records
            if not dns_records.get('MX'):
                issues.append('Missing MX DNS records')
            
            # Check for missing NS records
            if not dns_records.get('NS'):
                issues.append('Missing NS DNS records')
            
            # Check for missing TXT records
            if not dns_records.get('TXT'):
                issues.append('Missing TXT DNS records')
            
            # Check for missing SOA records
            if not dns_records.get('SOA'):
                issues.append('Missing SOA DNS records')
            
            # Check for missing CAA records
            if not dns_records.get('CAA'):
                issues.append('Missing CAA DNS records')
            
            dns_health['issues'] = issues
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: DNS health assessment error: {str(e)}[/yellow]")
            
        self.results['dns_health'] = dns_health

    async def assess_endpoint_security(self) -> None:
        """Perform endpoint security assessment"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting endpoint security assessment...[/bold blue]")
        
        endpoint_info = {
            'os_info': {},
            'security_headers': {},
            'issues': []
        }
        
        try:
            # Get OS information
            try:
                response = requests.get(f'http://{self.target}/', timeout=5)
                endpoint_info['os_info']['os'] = response.headers.get('Server', 'Unknown')
                endpoint_info['os_info']['version'] = response.headers.get('X-Powered-By', 'Unknown')
            except Exception as e:
                endpoint_info['os_info']['error'] = str(e)
            
            # Get security headers
            try:
                headers = {k.lower(): v for k, v in response.headers.items()}
                endpoint_info['security_headers'] = headers
            except Exception as e:
                endpoint_info['security_headers']['error'] = str(e)
            
            # Check for security issues
            issues = []
            
            # Check for exposed sensitive data
            if any(sensitive in str(response.text).lower() for sensitive in ['password', 'key', 'secret']):
                issues.append('Exposed sensitive data detected')
            
            endpoint_info['issues'] = issues
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Endpoint security assessment error: {str(e)}[/yellow]")
            
        self.results['endpoint_security'] = endpoint_info

    async def assess_vulnerability(self) -> None:
        """Perform vulnerability assessment"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting vulnerability assessment...[/bold blue]")
        
        vulnerability_info = {
            'common_vulnerabilities': [],
            'security_issues': []
        }
        
        try:
            # Check for common vulnerabilities
            vulnerabilities = []
            
            # Check for XSS
            xss_payloads = [
                '<script>alert(1)</script>',
                '"><script>alert(2)</script>',
                '"><img src=x onerror=alert(3)>'
            ]
            
            for payload in xss_payloads:
                try:
                    response = requests.get(
                        f"https://{self.target}/?q={payload}",
                        verify=False,
                        timeout=5
                    )
                    if payload in response.text:
                        vulnerabilities.append({
                            'type': 'XSS',
                            'payload': payload,
                            'severity': 'High'
                        })
                except:
                    continue
                    
            # Check for SQL Injection
            sql_payloads = [
                "' OR '1'='1",
                "1' OR '1'='1",
                "1 UNION SELECT NULL--"
            ]
            
            for payload in sql_payloads:
                try:
                    response = requests.get(
                        f"https://{self.target}/?id={payload}",
                        verify=False,
                        timeout=5
                    )
                    if any(error in response.text.lower() for error in ['sql', 'mysql', 'postgresql', 'oracle']):
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'payload': payload,
                            'severity': 'Critical'
                        })
                except:
                    continue
                    
            vulnerability_info['common_vulnerabilities'] = vulnerabilities
            
            # Check for security issues
            security_issues = []
            
            # Check for exposed sensitive data
            if any(sensitive in str(vulnerability).lower() for sensitive in ['password', 'key', 'secret']):
                security_issues.append({
                    'type': 'Sensitive Data Exposure',
                    'severity': 'High'
                })
            
            vulnerability_info['security_issues'] = security_issues
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Vulnerability assessment error: {str(e)}[/yellow]")
            
        self.results['vulnerability_assessment'] = vulnerability_info

    async def assess_ip_reputation(self) -> None:
        """Perform IP reputation assessment"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting IP reputation assessment...[/bold blue]")
        
        ip_info = {
            'ip_info': {},
            'reputation_data': {}
        }
        
        try:
            # Get IP information
            try:
                ip_info['ip_info']['ip'] = socket.gethostbyname(self.target)
            except Exception as e:
                ip_info['ip_info']['error'] = str(e)
            
            # Get reputation data using VirusTotal API
            try:
                vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
                if vt_api_key:
                    response = requests.get(
                        f'https://www.virustotal.com/vtapi/v2/ip-address/report',
                        params={'apikey': vt_api_key, 'ip': socket.gethostbyname(self.target)},
                        timeout=5
                    )
                    if response.status_code == 200:
                        ip_info['reputation_data'] = response.json()
            except Exception as e:
                ip_info['reputation_data']['error'] = str(e)
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: IP reputation assessment error: {str(e)}[/yellow]")
            
        self.results['ip_reputation'] = ip_info

    async def assess_ssl_tls_security(self) -> None:
        """Perform SSL/TLS security assessment"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting SSL/TLS security assessment...[/bold blue]")
        
        ssl_info = {
            'certificate_info': {},
            'security_issues': []
        }
        
        try:
            # Get certificate information
            try:
                context = ssl.create_default_context()
                with socket.create_connection((self.target, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        cert = ssock.getpeercert()
                        ssl_info['certificate_info'] = {
                            'issuer': cert['subject'][0][0][0],
                            'subject': cert['subject'][0][0][1],
                            'valid_from': cert['notBefore'],
                            'valid_to': cert['notAfter'],
                            'expiry': cert['notAfter'] < datetime.now().replace(tzinfo=None)
                        }
            except Exception as e:
                ssl_info['certificate_info']['error'] = str(e)
            
            # Check for security issues
            issues = []
            
            # Check for weak SSL/TLS versions
            if ssl_info['certificate_info'].get('expiry'):
                issues.append('SSL/TLS certificate expired')
            
            ssl_info['security_issues'] = issues
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: SSL/TLS security assessment error: {str(e)}[/yellow]")
            
        self.results['ssl_tls_security'] = ssl_info

    async def assess_cloud_security(self) -> None:
        """Perform cloud security assessment"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting cloud security assessment...[/bold blue]")
        
        cloud_info = {
            'issues': []
        }
        
        try:
            # Check for cloud-specific issues
            issues = []
            
            # Check for exposed sensitive data in cloud environment
            if any(sensitive in str(os.getenv('AWS_ACCESS_KEY_ID', '')).lower() for sensitive in ['password', 'key', 'secret']):
                issues.append('Exposed AWS access key')
            
            cloud_info['issues'] = issues
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Cloud security assessment error: {str(e)}[/yellow]")
            
        self.results['cloud_security'] = cloud_info

    async def assess_api_security(self) -> None:
        """Perform API security assessment"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting API security assessment...[/bold blue]")
        
        api_info = {
            'issues': []
        }
        
        try:
            # Check for API-specific issues
            issues = []
            
            # Check for exposed sensitive data in API responses
            if any(sensitive in str(response.text).lower() for sensitive in ['password', 'key', 'secret']):
                issues.append('Exposed sensitive data in API response')
            
            api_info['issues'] = issues
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: API security assessment error: {str(e)}[/yellow]")
            
        self.results['api_security'] = api_info

    async def assess_container_security(self) -> None:
        """Perform container security assessment"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting container security assessment...[/bold blue]")
        
        container_info = {
            'issues': []
        }
        
        try:
            # Check for container-specific issues
            issues = []
            
            # Check for exposed sensitive data in container environment
            if any(sensitive in str(os.getenv('DOCKER_IMAGE', '')).lower() for sensitive in ['password', 'key', 'secret']):
                issues.append('Exposed sensitive data in container environment')
            
            container_info['issues'] = issues
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Container security assessment error: {str(e)}[/yellow]")
            
        self.results['container_security'] = container_info

    async def assess_database_security(self) -> None:
        """Perform database security assessment"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting database security assessment...[/bold blue]")
        
        db_info = {
            'issues': []
        }
        
        try:
            # Check for database-specific issues
            issues = []
            
            # Check for exposed sensitive data in database
            if any(sensitive in str(os.getenv('DATABASE_URL', '')).lower() for sensitive in ['password', 'key', 'secret']):
                issues.append('Exposed sensitive data in database')
            
            db_info['issues'] = issues
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Database security assessment error: {str(e)}[/yellow]")
            
        self.results['database_security'] = db_info

    async def assess_patching_status(self) -> None:
        """Perform patching status assessment"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting patching status assessment...[/bold blue]")
        
        patch_info = {
            'server_info': {},
            'security_headers': {},
            'issues': []
        }
        
        try:
            # Get server information
            try:
                response = requests.get(f'http://{self.target}/', timeout=5)
                patch_info['server_info']['os'] = response.headers.get('Server', 'Unknown')
                patch_info['server_info']['version'] = response.headers.get('X-Powered-By', 'Unknown')
            except Exception as e:
                patch_info['server_info']['error'] = str(e)
            
            # Get security headers
            try:
                headers = {k.lower(): v for k, v in response.headers.items()}
                patch_info['security_headers'] = headers
            except Exception as e:
                patch_info['security_headers']['error'] = str(e)
            
            # Check for security issues
            issues = []
            
            # Check for outdated software
            if patch_info['server_info'].get('expired'):
                issues.append('Outdated software')
            
            patch_info['issues'] = issues
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Patching status assessment error: {str(e)}[/yellow]")
            
        self.results['patching_status'] = patch_info

    async def assess_compliance(self) -> None:
        """Assess compliance with security standards"""
        self.console.print(f"[bold blue]Starting compliance assessment...[/bold blue]")
        
        compliance_info = {
            'standards': {},
            'findings': [],
            'recommendations': []
        }
        
        try:
            # Check for PCI DSS compliance
            pci_findings = await self.check_pci_compliance()
            compliance_info['standards']['PCI DSS'] = pci_findings
            
            # Check for HIPAA compliance
            hipaa_findings = await self.check_hipaa_compliance()
            compliance_info['standards']['HIPAA'] = hipaa_findings
            
            # Check for GDPR compliance
            gdpr_findings = await self.check_gdpr_compliance()
            compliance_info['standards']['GDPR'] = gdpr_findings
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Compliance assessment error: {str(e)}[/yellow]")
            
        self.results['compliance'] = compliance_info

    async def check_pci_compliance(self) -> Dict:
        """Check PCI DSS compliance requirements"""
        findings = {
            'requirements': {},
            'status': 'Non-Compliant',
            'issues': []
        }
        
        try:
            # Check for SSL/TLS
            if not self.results['ssl_tls_security'].get('certificate_info'):
                findings['issues'].append('SSL/TLS not properly configured')
                
            # Check for security headers
            headers = self.results['endpoint_security'].get('security_headers', {})
            required_headers = [
                'Strict-Transport-Security',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection'
            ]
            
            for header in required_headers:
                if header not in headers:
                    findings['issues'].append(f'Missing required security header: {header}')
                    
            # Check for exposed sensitive data
            if self.results['vulnerability_assessment'].get('common_vulnerabilities'):
                findings['issues'].append('Sensitive data exposure detected')
                
        except Exception as e:
            findings['issues'].append(f'Error checking PCI compliance: {str(e)}')
            
        return findings

    async def check_hipaa_compliance(self) -> Dict:
        """Check HIPAA compliance requirements"""
        findings = {
            'requirements': {},
            'status': 'Non-Compliant',
            'issues': []
        }
        
        try:
            # Check for encryption
            if not self.results['ssl_tls_security'].get('certificate_info'):
                findings['issues'].append('Encryption not properly configured')
                
            # Check for access controls
            if self.results['vulnerability_assessment'].get('common_vulnerabilities'):
                findings['issues'].append('Access control issues detected')
                
            # Check for audit logging
            if not self.results['endpoint_security'].get('security_headers', {}).get('X-Audit-Log'):
                findings['issues'].append('Audit logging not configured')
                
        except Exception as e:
            findings['issues'].append(f'Error checking HIPAA compliance: {str(e)}')
            
        return findings

    async def check_gdpr_compliance(self) -> Dict:
        """Check GDPR compliance requirements"""
        findings = {
            'requirements': {},
            'status': 'Non-Compliant',
            'issues': []
        }
        
        try:
            # Check for data protection
            if not self.results['ssl_tls_security'].get('certificate_info'):
                findings['issues'].append('Data protection measures not properly configured')
                
            # Check for privacy headers
            headers = self.results['endpoint_security'].get('security_headers', {})
            if 'Privacy-Policy' not in headers:
                findings['issues'].append('Privacy policy not properly configured')
                
            # Check for data minimization
            if self.results['vulnerability_assessment'].get('common_vulnerabilities'):
                findings['issues'].append('Data minimization issues detected')
                
        except Exception as e:
            findings['issues'].append(f'Error checking GDPR compliance: {str(e)}')
            
        return findings

    async def manage_assets(self) -> None:
        """Manage and track discovered assets"""
        self.console.print(f"[bold blue]Starting asset management...[/bold blue]")
        
        asset_info = {
            'discovered_assets': [],
            'asset_types': {},
            'risk_levels': {}
        }
        
        try:
            # Collect assets from various assessments
            assets = []
            
            # Network assets
            if self.results['network_security'].get('port_scan'):
                for service in self.results['network_security']['port_scan']['services']:
                    assets.append({
                        'type': 'Network Service',
                        'name': service['name'],
                        'port': service['port'],
                        'version': service['version']
                    })
                    
            # Web assets
            if self.results['endpoint_security'].get('security_headers'):
                assets.append({
                    'type': 'Web Application',
                    'headers': self.results['endpoint_security']['security_headers']
                })
                
            # Cloud assets
            if self.results['cloud_security'].get('issues'):
                for issue in self.results['cloud_security']['issues']:
                    assets.append({
                        'type': 'Cloud Service',
                        'issue': issue
                    })
                    
            # Categorize assets
            for asset in assets:
                asset_type = asset['type']
                if asset_type not in asset_info['asset_types']:
                    asset_info['asset_types'][asset_type] = []
                asset_info['asset_types'][asset_type].append(asset)
                
            # Calculate risk levels
            for asset_type, asset_list in asset_info['asset_types'].items():
                risk_level = self.calculate_asset_risk(asset_list)
                asset_info['risk_levels'][asset_type] = risk_level
                
        except Exception as e:
            self.console.print(f"[yellow]Warning: Asset management error: {str(e)}[/yellow]")
            
        self.results['asset_inventory'] = asset_info

    def calculate_asset_risk(self, assets: List[Dict]) -> str:
        """Calculate risk level for a group of assets"""
        risk_score = 0
        
        for asset in assets:
            # Check for vulnerabilities
            if any(vuln in str(asset).lower() for vuln in ['vulnerability', 'exposed', 'weak']):
                risk_score += 3
                
            # Check for sensitive information
            if any(info in str(asset).lower() for info in ['password', 'key', 'secret']):
                risk_score += 2
                
            # Check for outdated versions
            if 'version' in asset and 'old' in str(asset['version']).lower():
                risk_score += 1
                
        if risk_score >= 5:
            return 'High'
        elif risk_score >= 3:
            return 'Medium'
        else:
            return 'Low'

    async def enable_team_collaboration(self) -> None:
        """Enable team collaboration features"""
        self.console.print(f"[bold blue]Starting team collaboration setup...[/bold blue]")
        
        collaboration_info = {
            'team_members': [],
            'scan_permissions': {},
            'findings_shared': [],
            'comments': []
        }
        
        try:
            # Load team members from environment
            team_members = os.getenv('TEAM_MEMBERS', '').split(',')
            collaboration_info['team_members'] = [
                {'name': member.strip(), 'role': 'viewer'}
                for member in team_members if member.strip()
            ]
            
            # Set up scan permissions
            collaboration_info['scan_permissions'] = {
                'view': team_members,
                'edit': os.getenv('ADMIN_MEMBERS', '').split(','),
                'delete': os.getenv('ADMIN_MEMBERS', '').split(',')
            }
            
            # Share findings
            for category, findings in self.results.items():
                if findings:
                    collaboration_info['findings_shared'].append({
                        'category': category,
                        'timestamp': datetime.now().isoformat()
                    })
                    
        except Exception as e:
            self.console.print(f"[yellow]Warning: Team collaboration setup error: {str(e)}[/yellow]")
            
        self.results['team_collaboration'] = collaboration_info

    async def enable_real_time_monitoring(self) -> None:
        """Enable real-time monitoring features"""
        self.console.print(f"[bold blue]Starting real-time monitoring...[/bold blue]")
        
        monitoring_info = {
            'active_monitors': [],
            'alerts': [],
            'metrics': {}
        }
        
        try:
            # Set up monitoring for various aspects
            monitoring_info['active_monitors'] = [
                {
                    'type': 'Port Changes',
                    'status': 'Active',
                    'threshold': 5
                },
                {
                    'type': 'Vulnerability Detection',
                    'status': 'Active',
                    'threshold': 1
                },
                {
                    'type': 'SSL Certificate',
                    'status': 'Active',
                    'threshold': 30
                }
            ]
            
            # Generate initial metrics
            monitoring_info['metrics'] = {
                'ports_monitored': len(self.results['network_security'].get('port_scan', {}).get('open_ports', [])),
                'vulnerabilities_found': len(self.results['vulnerability_assessment'].get('common_vulnerabilities', [])),
                'ssl_status': self.results['ssl_tls_security'].get('certificate_info', {}).get('expiry')
            }
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Real-time monitoring setup error: {str(e)}[/yellow]")
            
        self.results['real_time_monitoring'] = monitoring_info

    def save_historical_data(self) -> None:
        """Save scan results to historical database"""
        try:
            conn = sqlite3.connect('security_scanner.db')
            cursor = conn.cursor()
            
            # Save scan history
            cursor.execute('''
                INSERT INTO scan_history (target, scan_date, scan_type, findings)
                VALUES (?, ?, ?, ?)
            ''', (
                self.target,
                datetime.now().isoformat(),
                'comprehensive',
                json.dumps(self.results)
            ))
            
            # Save vulnerabilities
            for category, findings in self.results.items():
                if isinstance(findings, dict) and 'issues' in findings:
                    for issue in findings['issues']:
                        cursor.execute('''
                            INSERT INTO vulnerabilities (target, vuln_type, description, severity, discovery_date)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (
                            self.target,
                            category,
                            str(issue),
                            'High',  # Default severity
                            datetime.now().isoformat()
                        ))
                        
            # Save assets
            if 'asset_inventory' in self.results:
                for asset_type, assets in self.results['asset_inventory'].get('asset_types', {}).items():
                    for asset in assets:
                        cursor.execute('''
                            INSERT INTO assets (target, asset_type, details, discovery_date)
                            VALUES (?, ?, ?, ?)
                        ''', (
                            self.target,
                            asset_type,
                            json.dumps(asset),
                            datetime.now().isoformat()
                        ))
                        
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Historical data save error: {str(e)}[/yellow]")

    def generate_report(self) -> None:
        """Generate a comprehensive security assessment report"""
        self.console.print("\n[bold green]Security Assessment Report[/bold green]")
        if self.target:
            self.console.print(f"Target: {self.target}")
        if self.email:
            self.console.print(f"Email: {self.email}")
        self.console.print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        # Network Security
        if self.results['network_security']:
            network_info = self.results['network_security']
            self.console.print(Panel(f"""
Network Security Assessment:
IP Information: {network_info.get('ip_info', {})}
DNS Records: {network_info.get('dns_info', {})}
WHOIS Information: {network_info.get('whois_info', {})}
Open Ports: {len(network_info.get('port_scan', {}).get('open_ports', []))}
Services: {len(network_info.get('port_scan', {}).get('services', []))}
            """, title="Network Security"))

        # Email Security
        if self.results['email_security']:
            email_info = self.results['email_security']
            self.console.print(Panel(f"""
Email Security Assessment:
Validation: {email_info.get('validation', {})}
Domain Security: {email_info.get('domain_security', {})}
Server Configuration: {email_info.get('server_config', {})}
Security Headers: {email_info.get('security_headers', {})}
Authentication: {email_info.get('authentication', {})}
Reputation: {email_info.get('reputation', {})}
Best Practices: {email_info.get('best_practices', {})}
Phishing Risk Score: {email_info.get('phishing_risk', {}).get('score', 0)}
Phishing Risk Factors: {', '.join(email_info.get('phishing_risk', {}).get('factors', []))}
            """, title="Email Security"))

        # DNS Health
        if self.results['dns_health']:
            dns_health = self.results['dns_health']
            self.console.print(Panel(f"""
DNS Health Assessment:
Security Records: {dns_health.get('security_records', {})}
Issues: {', '.join(dns_health.get('issues', [])) if dns_health.get('issues', []) else 'None'}
            """, title="DNS Health"))

        # Endpoint Security
        if self.results['endpoint_security']:
            endpoint = self.results['endpoint_security']
            self.console.print(Panel(f"""
Endpoint Security Assessment:
OS Information: {endpoint.get('os_info', {})}
Security Headers: {', '.join(endpoint.get('security_headers', {}).keys())}
Issues: {', '.join(endpoint.get('issues', [])) if endpoint.get('issues', []) else 'None'}
            """, title="Endpoint Security"))

        # Vulnerability Assessment
        if self.results['vulnerability_assessment']:
            vuln = self.results['vulnerability_assessment']
            self.console.print(Panel(f"""
Vulnerability Assessment:
Common Vulnerabilities: {len(vuln.get('common_vulnerabilities', []))}
Security Issues: {len(vuln.get('security_issues', []))}
            """, title="Vulnerability Assessment"))

        # IP Reputation
        if self.results['ip_reputation']:
            rep = self.results['ip_reputation']
            self.console.print(Panel(f"""
IP Reputation Assessment:
IP Information: {rep.get('ip_info', {})}
Reputation Data: {rep.get('reputation_data', {})}
            """, title="IP Reputation"))

        # SSL/TLS Security
        if self.results['ssl_tls_security']:
            ssl = self.results['ssl_tls_security']
            self.console.print(Panel(f"""
SSL/TLS Security Assessment:
Certificate Information: {ssl.get('certificate_info', {})}
Security Issues: {', '.join(ssl.get('security_issues', [])) if ssl.get('security_issues', []) else 'None'}
            """, title="SSL/TLS Security"))

        # Cloud Security
        if self.results['cloud_security']:
            cloud = self.results['cloud_security']
            self.console.print(Panel(f"""
Cloud Security Assessment:
Issues Found: {len(cloud.get('issues', []))}
Issues: {', '.join(cloud.get('issues', [])) if cloud.get('issues', []) else 'None'}
            """, title="Cloud Security"))

        # API Security
        if self.results['api_security']:
            api = self.results['api_security']
            self.console.print(Panel(f"""
API Security Assessment:
Issues Found: {len(api.get('issues', []))}
Issues: {', '.join(api.get('issues', [])) if api.get('issues', []) else 'None'}
            """, title="API Security"))

        # Container Security
        if self.results['container_security']:
            container = self.results['container_security']
            self.console.print(Panel(f"""
Container Security Assessment:
Issues Found: {len(container.get('issues', []))}
Issues: {', '.join(container.get('issues', [])) if container.get('issues', []) else 'None'}
            """, title="Container Security"))

        # Database Security
        if self.results['database_security']:
            db = self.results['database_security']
            self.console.print(Panel(f"""
Database Security Assessment:
Issues Found: {len(db.get('issues', []))}
Issues: {', '.join(db.get('issues', [])) if db.get('issues', []) else 'None'}
            """, title="Database Security"))

        # Patching Status
        if self.results['patching_status']:
            patch = self.results['patching_status']
            self.console.print(Panel(f"""
Patching Status Assessment:
Server Information: {patch.get('server_info', {})}
Security Headers: {', '.join(patch.get('security_headers', {}).keys())}
Issues: {', '.join(patch.get('issues', [])) if patch.get('issues', []) else 'None'}
            """, title="Patching Status"))

        # Compliance
        if self.results['compliance']:
            compliance = self.results['compliance']
            self.console.print(Panel(f"""
Compliance Assessment:
Standards: {', '.join(compliance.get('standards', {}).keys())}
Findings: {len(compliance.get('findings', []))}
            """, title="Compliance"))

        # Asset Inventory
        if self.results['asset_inventory']:
            assets = self.results['asset_inventory']
            self.console.print(Panel(f"""
Asset Inventory:
Asset Types: {', '.join(assets.get('asset_types', {}).keys())}
Risk Levels: {assets.get('risk_levels', {})}
            """, title="Asset Inventory"))

        # Team Collaboration
        if self.results['team_collaboration']:
            team = self.results['team_collaboration']
            self.console.print(Panel(f"""
Team Collaboration:
Team Members: {len(team.get('team_members', []))}
Findings Shared: {len(team.get('findings_shared', []))}
            """, title="Team Collaboration"))

        # Real-time Monitoring
        if self.results['real_time_monitoring']:
            monitoring = self.results['real_time_monitoring']
            self.console.print(Panel(f"""
Real-time Monitoring:
Active Monitors: {len(monitoring.get('active_monitors', []))}
Metrics: {monitoring.get('metrics', {})}
            """, title="Real-time Monitoring"))

    async def send_slack_report(self, channel: str) -> None:
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
• IP Information: {self.results['network_security'].get('ip_info', {})}
• DNS Records: {self.results['network_security'].get('dns_info', {})}
• WHOIS Information: {self.results['network_security'].get('whois_info', {})}
• Open Ports: {len(self.results['network_security'].get('port_scan', {}).get('open_ports', []))}
• Services: {len(self.results['network_security'].get('port_scan', {}).get('services', []))}

*Email Security*
• Validation: {self.results['email_security'].get('validation', {})}
• Domain Security: {self.results['email_security'].get('domain_security', {})}
• Server Configuration: {self.results['email_security'].get('server_config', {})}
• Security Headers: {self.results['email_security'].get('security_headers', {})}
• Authentication: {self.results['email_security'].get('authentication', {})}
• Reputation: {self.results['email_security'].get('reputation', {})}
• Best Practices: {self.results['email_security'].get('best_practices', {})}
• Phishing Risk Score: {self.results['email_security'].get('phishing_risk', {}).get('score', 0)}
• Phishing Risk Factors: {', '.join(self.results['email_security'].get('phishing_risk', {}).get('factors', []))}

*DNS Health*
• Security Records: {self.results['dns_health'].get('security_records', {})}
• Issues: {', '.join(self.results['dns_health'].get('issues', [])) if self.results['dns_health'].get('issues', []) else 'None'}

*Endpoint Security*
• OS Information: {self.results['endpoint_security'].get('os_info', {})}
• Security Headers: {', '.join(self.results['endpoint_security'].get('security_headers', {}).keys())}
• Issues: {', '.join(self.results['endpoint_security'].get('issues', [])) if self.results['endpoint_security'].get('issues', []) else 'None'}

*Vulnerability Assessment*
• Common Vulnerabilities: {len(self.results['vulnerability_assessment'].get('common_vulnerabilities', []))}
• Security Issues: {len(self.results['vulnerability_assessment'].get('security_issues', []))}

*IP Reputation*
• IP Information: {self.results['ip_reputation'].get('ip_info', {})}
• Reputation Data: {self.results['ip_reputation'].get('reputation_data', {})}

*SSL/TLS Security*
• Certificate Information: {self.results['ssl_tls_security'].get('certificate_info', {})}
• Security Issues: {', '.join(self.results['ssl_tls_security'].get('security_issues', [])) if self.results['ssl_tls_security'].get('security_issues', []) else 'None'}

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

*Patching Status*
• Server Information: {self.results['patching_status'].get('server_info', {})}
• Security Headers: {', '.join(self.results['patching_status'].get('security_headers', {}).keys())}
• Issues: {', '.join(self.results['patching_status'].get('issues', [])) if self.results['patching_status'].get('issues', []) else 'None'}

*Compliance*
• Standards: {', '.join(self.results['compliance'].get('standards', {}).keys())}
• Findings: {len(self.results['compliance'].get('findings', []))}

*Asset Inventory*
• Asset Types: {', '.join(self.results['asset_inventory'].get('asset_types', {}).keys())}
• Risk Levels: {self.results['asset_inventory'].get('risk_levels', {})}

*Team Collaboration*
• Team Members: {len(self.results['team_collaboration'].get('team_members', []))}
• Findings Shared: {len(self.results['team_collaboration'].get('findings_shared', []))}

*Real-time Monitoring*
• Active Monitors: {len(self.results['real_time_monitoring'].get('active_monitors', []))}
• Metrics: {self.results['real_time_monitoring'].get('metrics', {})}
"""
            
            # Send the message to Slack
            self.slack_client.chat_postMessage(
                channel=channel,
                text=message,
                parse='mrkdwn'
            )
        except SlackApiError as e:
            self.console.print(f"[red]Error sending Slack message: {str(e)}[/red]")

    async def assess_email_security(self) -> None:
        """Assess email security for the provided email address"""
        if not self.email:
            return
            
        self.console.print(f"[bold blue]Starting email security assessment...[/bold blue]")
        
        email_info = {
            'validation': {},
            'domain_security': {},
            'server_config': {},
            'security_headers': {},
            'authentication': {},
            'reputation': {},
            'best_practices': {},
            'phishing_risk': {}
        }
        
        try:
            # Validate email format
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, self.email):
                email_info['validation']['format'] = 'Invalid'
            else:
                email_info['validation']['format'] = 'Valid'
                
                # Extract domain
                domain = self.email.split('@')[1]
                
                # Check domain security
                try:
                    # Check MX records
                    mx_records = dns.resolver.resolve(domain, 'MX')
                    email_info['domain_security']['mx_records'] = [str(x.exchange).rstrip('.') for x in mx_records]
                    
                    # Check SPF record
                    try:
                        spf_records = dns.resolver.resolve(domain, 'TXT')
                        for record in spf_records:
                            if 'v=spf1' in str(record):
                                email_info['domain_security']['spf'] = str(record)
                    except:
                        email_info['domain_security']['spf'] = 'Not found'
                        
                    # Check DMARC record
                    try:
                        dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                        for record in dmarc_records:
                            if 'v=DMARC1' in str(record):
                                email_info['domain_security']['dmarc'] = str(record)
                    except:
                        email_info['domain_security']['dmarc'] = 'Not found'
                        
                    # Check DKIM record
                    try:
                        dkim_records = dns.resolver.resolve(f'default._domainkey.{domain}', 'TXT')
                        for record in dkim_records:
                            if 'v=DKIM1' in str(record):
                                email_info['domain_security']['dkim'] = str(record)
                    except:
                        email_info['domain_security']['dkim'] = 'Not found'
                        
                except Exception as e:
                    email_info['domain_security']['error'] = str(e)
                    
                # Check email server configuration
                try:
                    # Get primary MX server
                    primary_mx = str(mx_records[0].exchange).rstrip('.')
                    
                    # Check SMTP server
                    smtp = smtplib.SMTP(primary_mx, 25, timeout=5)
                    smtp.helo('test.com')
                    
                    # Check STARTTLS support
                    try:
                        smtp.starttls()
                        email_info['server_config']['starttls'] = 'Supported'
                    except:
                        email_info['server_config']['starttls'] = 'Not supported'
                        
                    # Check SMTP authentication
                    try:
                        smtp.login('test', 'test')
                        email_info['server_config']['auth'] = 'Required'
                    except:
                        email_info['server_config']['auth'] = 'Not required'
                        
                    smtp.quit()
                    
                except Exception as e:
                    email_info['server_config']['error'] = str(e)
                    
                # Check email security headers
                try:
                    # Create test email
                    msg = MIMEMultipart()
                    msg['From'] = self.email
                    msg['To'] = 'test@example.com'
                    msg['Subject'] = 'Security Test'
                    msg.attach(MIMEText('Test content'))
                    
                    # Send test email
                    with smtplib.SMTP(primary_mx, 25, timeout=5) as server:
                        server.send_message(msg)
                        
                    # Check received headers
                    email_info['security_headers'] = {
                        'received': msg['Received'],
                        'received_spf': msg.get('Received-SPF', 'Not found'),
                        'authentication_results': msg.get('Authentication-Results', 'Not found')
                    }
                    
                except Exception as e:
                    email_info['security_headers']['error'] = str(e)
                    
                # Check email server reputation
                try:
                    # Use VirusTotal API to check IP reputation
                    vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
                    if vt_api_key:
                        response = requests.get(
                            f'https://www.virustotal.com/vtapi/v2/ip-address/report',
                            params={'apikey': vt_api_key, 'ip': socket.gethostbyname(primary_mx)},
                            timeout=5
                        )
                        if response.status_code == 200:
                            email_info['reputation'] = response.json()
                except Exception as e:
                    email_info['reputation']['error'] = str(e)
                    
                # Check email security best practices
                best_practices = []
                
                # Check SPF
                if email_info['domain_security'].get('spf') == 'Not found':
                    best_practices.append('SPF record missing')
                    
                # Check DMARC
                if email_info['domain_security'].get('dmarc') == 'Not found':
                    best_practices.append('DMARC record missing')
                    
                # Check DKIM
                if email_info['domain_security'].get('dkim') == 'Not found':
                    best_practices.append('DKIM record missing')
                    
                # Check STARTTLS
                if email_info['server_config'].get('starttls') == 'Not supported':
                    best_practices.append('STARTTLS not supported')
                    
                # Check SMTP Auth
                if email_info['server_config'].get('auth') == 'Not required':
                    best_practices.append('SMTP authentication not required')
                    
                email_info['best_practices']['issues'] = best_practices
                
                # Assess phishing risk
                phishing_risk = {
                    'score': 0,
                    'factors': []
                }
                
                # Check for common phishing indicators
                if not email_info['domain_security'].get('spf'):
                    phishing_risk['score'] += 2
                    phishing_risk['factors'].append('No SPF record')
                    
                if not email_info['domain_security'].get('dmarc'):
                    phishing_risk['score'] += 2
                    phishing_risk['factors'].append('No DMARC record')
                    
                if not email_info['domain_security'].get('dkim'):
                    phishing_risk['score'] += 1
                    phishing_risk['factors'].append('No DKIM record')
                    
                if email_info['server_config'].get('starttls') == 'Not supported':
                    phishing_risk['score'] += 1
                    phishing_risk['factors'].append('No STARTTLS support')
                    
                if email_info['server_config'].get('auth') == 'Not required':
                    phishing_risk['score'] += 1
                    phishing_risk['factors'].append('No SMTP authentication')
                    
                email_info['phishing_risk'] = phishing_risk
                
        except Exception as e:
            self.console.print(f"[yellow]Warning: Email security assessment error: {str(e)}[/yellow]")
            
        self.results['email_security'] = email_info

    async def run_scan(self) -> Dict:
        """Run all configured scans and return results"""
        try:
            # Run all assessments concurrently
            tasks = []
            
            if self.target:
                tasks.extend([
                    self.assess_network_security(),
                    self.assess_dns_health(),
                    self.assess_endpoint_security(),
                    self.assess_vulnerability(),
                    self.assess_ip_reputation(),
                    self.assess_ssl_tls_security(),
                    self.assess_cloud_security(),
                    self.assess_api_security(),
                    self.assess_container_security(),
                    self.assess_database_security(),
                    self.assess_patching_status(),
                    self.assess_compliance(),
                    self.manage_assets(),
                    self.enable_team_collaboration(),
                    self.enable_real_time_monitoring()
                ])
                
            if self.email:
                tasks.append(self.assess_email_security())
                
            await asyncio.gather(*tasks)
            
            # Save historical data
            self.save_historical_data()
            
            return self.results
            
        except Exception as e:
            raise Exception(f"Scan failed: {str(e)}")

# API endpoints
@app.post("/scan")
async def run_security_scan(request: ScanRequest):
    """API endpoint to run a security scan"""
    try:
        scanner = SecurityScanner(request.target, request.email)
        results = await scanner.run_scan()
        
        # If Slack channel is provided, send results
        if request.slack_channel and scanner.slack_client:
            await scanner.send_slack_report(request.slack_channel)
            
        return {
            "status": "success",
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """API endpoint to check service health"""
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 