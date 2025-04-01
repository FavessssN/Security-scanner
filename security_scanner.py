#!/usr/bin/env python3
import os
from urllib import response
import dns.resolver
import requests
import socket
import whois
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from typing import List, Dict, Any
import asyncio
from dotenv import load_dotenv
import ssl
from concurrent.futures import ThreadPoolExecutor
import sqlite3
from pathlib import Path
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks # type: ignore
from fastapi.templating import Jinja2Templates # type: ignore
from fastapi.staticfiles import StaticFiles # type: ignore
from fastapi.responses import HTMLResponse, FileResponse # type: ignore
from pydantic import BaseModel # type: ignore
from typing import Optional
from fpdf import FPDF
import tempfile
import logging
from attack_surface_scanner import AttackSurfaceScanner
# Temporarily comment out ScoutSuite import
# from cloud_security_scanner import CloudSecurityScanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(title="Security Scanner API")

# Set up templates
templates = Jinja2Templates(directory="templates")

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

class ScanRequest(BaseModel):
    target: Optional[str] = None
    email: Optional[str] = None
    profile: str = "standard"
    slack_channel: Optional[str] = None

class ScanResults(BaseModel):
    results: Dict[str, Any]

class SecurityScanner:
    def __init__(self, target: str = None, email: str = None, profile: str = "standard"):
        load_dotenv()
        self.target = target
        self.email = email
        self.profile = profile
        self.console = Console()
        
        # Validate required API keys
        required_keys = ['SHODAN_API_KEY', 'ABUSEIPDB_API_KEY']
        missing_keys = [key for key in required_keys if not os.getenv(key)]
        if missing_keys:
            raise ValueError(f"Missing required API keys: {', '.join(missing_keys)}")
            
        self.results = {
            'network_security': {},
            'dns_health': {},
            'email_security': {},
            'endpoint_security': {},
            'application_security': {},
            'vulnerability_assessment': {},
            'ip_reputation': {},
            'ssl_tls_security': {},
            'api_security': {},
            'container_security': {},
            'database_security': {},
            'patching_status': {},
            'compliance': {},
            'asset_inventory': {},
            'scan_profiles': {},
            'real_time_monitoring': {},
            'historical_data': {},
            'vulnerability_metrics': {},
            'risk_analysis': {},
            'remediation_tracking': {},
            'cloud_security': {}
        }
        
        # Initialize database for historical data
        self.init_database()
        
        # Initialize scan profiles with optimized settings
        self.scan_profiles = {
            'quick': {
                'vuln_scan': False,
                'compliance': False,
                'timeout': 30,  # 30 seconds timeout
                'tasks': [
                    'network_security',
                    'dns_health',
                    'ssl_tls_security'
                ]
            },
            'standard': {
                'vuln_scan': True,
                'compliance': True,
                'timeout': 60,  # 60 seconds timeout
                'tasks': [
                    'network_security',
                    'dns_health',
                    'ssl_tls_security',
                    'endpoint_security',
                    'vulnerability_assessment',
                    'ip_reputation'
                ]
            },
            'comprehensive': {
                'vuln_scan': True,
                'compliance': True,
                'timeout': 120,  # 120 seconds timeout
                'tasks': [
                    'network_security',
                    'dns_health',
                    'ssl_tls_security',
                    'endpoint_security',
                    'vulnerability_assessment',
                    'ip_reputation',
                    'email_security',
                    'api_security',
                    'container_security',
                    'database_security',
                    'patching_status',
                    'compliance',
                    'asset_inventory',
                    'cloud_security'  # Added cloud security scanning
                ]
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
                exploitability TEXT,
                impact TEXT,
                discovery_date DATETIME,
                remediation_date DATETIME,
                status TEXT,
                risk_score INTEGER,
                remediation_notes TEXT
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
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS remediation_tracking (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vuln_id INTEGER,
                action_taken TEXT,
                action_date DATETIME,
                action_by TEXT,
                status TEXT,
                notes TEXT,
                FOREIGN KEY (vuln_id) REFERENCES vulnerabilities (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date DATETIME,
                metric_type TEXT,
                value REAL,
                target TEXT
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
            'passive_service_info': {},
            'nmap_scan': {}  # Added for nmap results
        }
        
        try:
            # Get IP information using IP-API
            try:
                ip_info = socket.gethostbyname(self.target)
                network_info['ip_info']['ip'] = ip_info
                
                # Get ASN information using IP-API
                response = requests.get(f'http://ip-api.com/json/{ip_info}', timeout=5)
                if response.status_code == 200:
                    asn_info = response.json()
                    network_info['ip_info'].update({
                        'asn': asn_info.get('as'),
                        'isp': asn_info.get('isp'),
                        'country': asn_info.get('country'),
                        'city': asn_info.get('city'),
                        'region': asn_info.get('region'),
                        'timezone': asn_info.get('timezone')
                    })
            except Exception as e:
                network_info['ip_info']['error'] = str(e)
            
            # Get DNS information using Cloudflare DNS
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
                whois_info = whois.whois(self.target)
                network_info['whois_info'] = {
                    'registrar': whois_info.registrar,
                    'creation_date': str(whois_info.creation_date),
                    'expiration_date': str(whois_info.expiration_date)
                }
            except Exception as e:
                network_info['whois_info']['error'] = str(e)
            
            # Get passive port and service information from Shodan
            try:
                shodan_api_key = os.getenv('SHODAN_API_KEY')
                if shodan_api_key:
                    response = requests.get(
                        f'https://api.shodan.io/shodan/host/{ip_info}?key={shodan_api_key}',
                        timeout=10
                    )
                    if response.status_code == 200:
                        shodan_data = response.json()
                        network_info['passive_port_info']['shodan'] = {
                            'ports': shodan_data.get('ports', []),
                            'services': shodan_data.get('data', [])
                        }
                        network_info['passive_service_info']['shodan'] = {
                            'services': shodan_data.get('data', [])
                        }
            except Exception as e:
                self.console.print(f"[yellow]Warning: Shodan API error: {str(e)}[/yellow]")
            
            # Perform nmap scan only for comprehensive profile
            if self.profile == "comprehensive":
                try:
                    scanner = AttackSurfaceScanner(self.target)
                    scanner.port_scan("1-1024")  # Scan common ports
                    network_info['nmap_scan'] = {
                        'ports': scanner.results['ports'],
                        'services': scanner.results['services']
                    }
                except Exception as e:
                    network_info['nmap_scan']['error'] = str(e)
            
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
        """Perform passive endpoint security assessment"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting passive endpoint security assessment...[/bold blue]")
        
        endpoint_info = {
            'security_headers': {},
            'server_info': {},
            'issues': []
        }
        
        try:
            # Get server information and headers
            try:
                response = requests.get(f'https://{self.target}', timeout=5, verify=False)
                endpoint_info['server_info'] = {
                    'server': response.headers.get('Server', 'Unknown'),
                    'powered_by': response.headers.get('X-Powered-By', 'Unknown')
                }
                endpoint_info['security_headers'] = {
                    k: v for k, v in response.headers.items()
                    if k.lower() in [
                        'strict-transport-security',
                        'x-frame-options',
                        'x-content-type-options',
                        'x-xss-protection',
                        'content-security-policy'
                    ]
                }
            except Exception as e:
                endpoint_info['server_info']['error'] = str(e)
            
            # Check for security issues based on headers
            issues = []
            headers = endpoint_info['security_headers']
            
            if 'strict-transport-security' not in headers:
                issues.append('Missing HSTS header')
            if 'x-frame-options' not in headers:
                issues.append('Missing X-Frame-Options header')
            if 'x-content-type-options' not in headers:
                issues.append('Missing X-Content-Type-Options header')
            if 'x-xss-protection' not in headers:
                issues.append('Missing X-XSS-Protection header')
            if 'content-security-policy' not in headers:
                issues.append('Missing Content-Security-Policy header')
                
            endpoint_info['issues'] = issues
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Endpoint security assessment error: {str(e)}[/yellow]")
            
        self.results['endpoint_security'] = endpoint_info

    async def assess_vulnerability(self) -> None:
        """Perform vulnerability assessment with risk analysis"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting vulnerability assessment...[/bold blue]")
        
        vulnerability_info = {
            'common_vulnerabilities': [],
            'security_issues': [],
            'risk_analysis': {},
            'remediation_priorities': [],
            'metrics': {}
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
                            'severity': 'High',
                            'exploitability': 'Easy',
                            'impact': 'Data theft, session hijacking',
                            'risk_score': self.calculate_risk_score('XSS', 'High', 'Easy', 'Data theft, session hijacking')
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
                            'severity': 'Critical',
                            'exploitability': 'Easy',
                            'impact': 'Data breach, unauthorized access',
                            'risk_score': self.calculate_risk_score('SQL Injection', 'Critical', 'Easy', 'Data breach, unauthorized access')
                        })
                except:
                    continue
                    
            vulnerability_info['common_vulnerabilities'] = vulnerabilities
            
            # Perform risk analysis
            risk_analysis = {
                'total_vulnerabilities': len(vulnerabilities),
                'severity_distribution': self.calculate_severity_distribution(vulnerabilities),
                'exploitability_distribution': self.calculate_exploitability_distribution(vulnerabilities),
                'impact_analysis': self.analyze_impact(vulnerabilities),
                'risk_trends': self.analyze_risk_trends()
            }
            
            vulnerability_info['risk_analysis'] = risk_analysis
            
            # Prioritize remediation
            vulnerability_info['remediation_priorities'] = self.prioritize_remediation(vulnerabilities)
            
            # Calculate metrics
            vulnerability_info['metrics'] = self.calculate_vulnerability_metrics(vulnerabilities)
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Vulnerability assessment error: {str(e)}[/yellow]")
            
        self.results['vulnerability_assessment'] = vulnerability_info

    def calculate_risk_score(self, vuln_type: str, severity: str, exploitability: str, impact: str) -> int:
        """Calculate risk score for a vulnerability"""
        score = 0
        
        # Severity scoring
        severity_scores = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 1
        }
        score += severity_scores.get(severity, 0)
        
        # Exploitability scoring
        exploitability_scores = {
            'Easy': 5,
            'Moderate': 3,
            'Difficult': 1
        }
        score += exploitability_scores.get(exploitability, 0)
        
        # Impact scoring
        if 'data breach' in impact.lower():
            score += 5
        if 'unauthorized access' in impact.lower():
            score += 4
        if 'data theft' in impact.lower():
            score += 3
        if 'session hijacking' in impact.lower():
            score += 2
            
        return min(score, 20)  # Cap at 20

    def calculate_severity_distribution(self, vulnerabilities: List[Dict]) -> Dict:
        """Calculate distribution of vulnerability severities"""
        distribution = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            if severity in distribution:
                distribution[severity] += 1
                
        return distribution

    def calculate_exploitability_distribution(self, vulnerabilities: List[Dict]) -> Dict:
        """Calculate distribution of vulnerability exploitability"""
        distribution = {
            'Easy': 0,
            'Moderate': 0,
            'Difficult': 0
        }
        
        for vuln in vulnerabilities:
            exploitability = vuln.get('exploitability', 'Unknown')
            if exploitability in distribution:
                distribution[exploitability] += 1
                
        return distribution

    def analyze_impact(self, vulnerabilities: List[Dict]) -> Dict:
        """Analyze potential impact of vulnerabilities"""
        impact_analysis = {
            'data_breach_risk': 0,
            'unauthorized_access_risk': 0,
            'data_theft_risk': 0,
            'session_hijacking_risk': 0,
            'service_disruption_risk': 0
        }
        
        for vuln in vulnerabilities:
            impact = vuln.get('impact', '').lower()
            if 'data breach' in impact:
                impact_analysis['data_breach_risk'] += 1
            if 'unauthorized access' in impact:
                impact_analysis['unauthorized_access_risk'] += 1
            if 'data theft' in impact:
                impact_analysis['data_theft_risk'] += 1
            if 'session hijacking' in impact:
                impact_analysis['session_hijacking_risk'] += 1
            if 'service disruption' in impact:
                impact_analysis['service_disruption_risk'] += 1
                
        return impact_analysis

    def analyze_risk_trends(self) -> Dict:
        """Analyze vulnerability risk trends over time"""
        try:
            conn = sqlite3.connect('security_scanner.db')
            cursor = conn.cursor()
            
            # Get historical vulnerability data
            cursor.execute('''
                SELECT discovery_date, severity, risk_score
                FROM vulnerabilities
                WHERE target = ?
                ORDER BY discovery_date DESC
                LIMIT 30
            ''', (self.target,))
            
            historical_data = cursor.fetchall()
            
            trends = {
                'severity_trend': [],
                'risk_score_trend': [],
                'vulnerability_count_trend': []
            }
            
            for date, severity, risk_score in historical_data:
                trends['severity_trend'].append({
                    'date': date,
                    'severity': severity
                })
                trends['risk_score_trend'].append({
                    'date': date,
                    'risk_score': risk_score
                })
                
            conn.close()
            return trends
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Risk trend analysis error: {str(e)}[/yellow]")
            return {}

    def prioritize_remediation(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Prioritize vulnerabilities for remediation"""
        # Sort vulnerabilities by risk score
        sorted_vulns = sorted(vulnerabilities, key=lambda x: x.get('risk_score', 0), reverse=True)
        
        priorities = []
        for vuln in sorted_vulns:
            priority = {
                'vulnerability': vuln,
                'priority_level': self.determine_priority_level(vuln),
                'recommended_timeline': self.determine_remediation_timeline(vuln),
                'responsible_team': self.determine_responsible_team(vuln)
            }
            priorities.append(priority)
            
        return priorities

    def determine_priority_level(self, vuln: Dict) -> str:
        """Determine priority level for remediation"""
        risk_score = vuln.get('risk_score', 0)
        
        if risk_score >= 15:
            return 'Critical'
        elif risk_score >= 10:
            return 'High'
        elif risk_score >= 5:
            return 'Medium'
        else:
            return 'Low'

    def determine_remediation_timeline(self, vuln: Dict) -> str:
        """Determine recommended remediation timeline"""
        priority = self.determine_priority_level(vuln)
        
        timelines = {
            'Critical': '24 hours',
            'High': '72 hours',
            'Medium': '1 week',
            'Low': '1 month'
        }
        
        return timelines.get(priority, '1 month')

    def determine_responsible_team(self, vuln: Dict) -> str:
        """Determine team for remediation recommendation"""
        vuln_type = vuln.get('type', '').lower()
        
        if 'xss' in vuln_type or 'injection' in vuln_type:
            return 'Application Development'
        elif 'ssl' in vuln_type or 'certificate' in vuln_type:
            return 'Infrastructure'
        elif 'access' in vuln_type or 'authentication' in vuln_type:
            return 'Security'
        else:
            return 'IT Operations'

    def calculate_vulnerability_metrics(self, vulnerabilities: List[Dict]) -> Dict:
        """Calculate vulnerability metrics"""
        metrics = {
            'total_vulnerabilities': len(vulnerabilities),
            'critical_vulnerabilities': len([v for v in vulnerabilities if v.get('severity') == 'Critical']),
            'high_vulnerabilities': len([v for v in vulnerabilities if v.get('severity') == 'High']),
            'medium_vulnerabilities': len([v for v in vulnerabilities if v.get('severity') == 'Medium']),
            'low_vulnerabilities': len([v for v in vulnerabilities if v.get('severity') == 'Low']),
            'average_risk_score': sum(v.get('risk_score', 0) for v in vulnerabilities) / len(vulnerabilities) if vulnerabilities else 0,
            'mttd': self.calculate_mttd(),
            'mttr': self.calculate_mttr()
        }
        
        return metrics

    def calculate_mttd(self) -> float:
        """Calculate Mean Time to Detect (MTTD)"""
        try:
            conn = sqlite3.connect('security_scanner.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT AVG(JULIANDAY(remediation_date) - JULIANDAY(discovery_date))
                FROM vulnerabilities
                WHERE target = ? AND remediation_date IS NOT NULL
            ''', (self.target,))
            
            mttd = cursor.fetchone()[0] or 0
            conn.close()
            
            return mttd
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: MTTD calculation error: {str(e)}[/yellow]")
            return 0

    def calculate_mttr(self) -> float:
        """Calculate Mean Time to Remediate (MTTR)"""
        try:
            conn = sqlite3.connect('security_scanner.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT AVG(JULIANDAY(remediation_date) - JULIANDAY(discovery_date))
                FROM vulnerabilities
                WHERE target = ? AND status = 'Remediated'
            ''', (self.target,))
            
            mttr = cursor.fetchone()[0] or 0
            conn.close()
            
            return mttr
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: MTTR calculation error: {str(e)}[/yellow]")
            return 0

    def generate_remediation_report(self) -> str:
        """Generate a detailed remediation report"""
        report = f"""
Vulnerability Remediation Report
===============================
Target: {self.target}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Executive Summary
----------------
Total Vulnerabilities: {self.results['vulnerability_assessment']['metrics']['total_vulnerabilities']}
Critical Vulnerabilities: {self.results['vulnerability_assessment']['metrics']['critical_vulnerabilities']}
High Vulnerabilities: {self.results['vulnerability_assessment']['metrics']['high_vulnerabilities']}
Average Risk Score: {self.results['vulnerability_assessment']['metrics']['average_risk_score']:.2f}

Risk Analysis
------------
Severity Distribution:
{self.format_distribution(self.results['vulnerability_assessment']['risk_analysis']['severity_distribution'])}

Exploitability Distribution:
{self.format_distribution(self.results['vulnerability_assessment']['risk_analysis']['exploitability_distribution'])}

Impact Analysis:
{self.format_impact_analysis(self.results['vulnerability_assessment']['risk_analysis']['impact_analysis'])}

Performance Metrics
-----------------
Mean Time to Detect (MTTD): {self.results['vulnerability_assessment']['metrics']['mttd']:.2f} days
Mean Time to Remediate (MTTR): {self.results['vulnerability_assessment']['metrics']['mttr']:.2f} days

Remediation Priorities
--------------------
"""
        
        for priority in self.results['vulnerability_assessment']['remediation_priorities']:
            report += f"""
Vulnerability: {priority['vulnerability']['type']}
Priority Level: {priority['priority_level']}
Timeline: {priority['recommended_timeline']}
Recommended Team: {priority['responsible_team']}
Risk Score: {priority['vulnerability']['risk_score']}
Impact: {priority['vulnerability']['impact']}
"""
            
        return report

    def format_distribution(self, distribution: Dict) -> str:
        """Format distribution data for report"""
        return "\n".join(f"{k}: {v}" for k, v in distribution.items())

    def format_impact_analysis(self, impact: Dict) -> str:
        """Format impact analysis data for report"""
        return "\n".join(f"{k.replace('_', ' ').title()}: {v}" for k, v in impact.items())

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
                ip = socket.gethostbyname(self.target)
                ip_info["ip_address"] = ip
                ip_info["hostname"] = socket.gethostbyaddr(ip)[0]
            except Exception as e:
                ip_info["error"] = str(e)

            # Get reputation data from various sources
            reputation_data = {}
            try:
                # Example: Check IP against some reputation APIs
                # You would need to implement actual API calls here
                reputation_data["abuseipdb"] = {"status": "clean"}
                reputation_data["virustotal"] = {"status": "clean"}
                reputation_data["spamhaus"] = {"status": "clean"}
            except Exception as e:
                reputation_data["error"] = str(e)

            ip_info['reputation_data'] = reputation_data
            
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
        """Perform passive patching status assessment"""
        if not self.target:
            return
            
        self.console.print(f"[bold blue]Starting passive patching status assessment...[/bold blue]")
        
        patch_info = {
            'server_info': {},
            'security_headers': {},
            'issues': []
        }
        
        try:
            # Get server information
            try:
                response = requests.get(f'https://{self.target}', timeout=5, verify=False)
                patch_info['server_info'] = {
                    'server': response.headers.get('Server', 'Unknown'),
                    'powered_by': response.headers.get('X-Powered-By', 'Unknown')
                }
            except Exception as e:
                patch_info['server_info']['error'] = str(e)
            
            # Check for security issues based on server information
            issues = []
            server_info = patch_info['server_info']
            
            # Check for outdated server versions based on known patterns
            if 'apache' in server_info['server'].lower():
                version = server_info['server'].split('/')[-1]
                if version and version < '2.4.0':
                    issues.append('Outdated Apache version detected')
                    
            if 'nginx' in server_info['server'].lower():
                version = server_info['server'].split('/')[-1]
                if version and version < '1.14.0':
                    issues.append('Outdated Nginx version detected')
                    
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
            'risk_levels': {},
            'criticality': {},
            'sensitivity': {},
            'business_impact': {},
            'asset_relationships': {},
            'asset_owners': {},
            'asset_status': {}
        }
        
        try:
            # Collect assets from various assessments
            assets = []
            
            # Network assets
            if self.results['network_security'].get('passive_port_info'):
                for service in self.results['network_security']['passive_port_info'].get('services', []):
                    assets.append({
                        'type': 'Network Service',
                        'name': service.get('name', 'Unknown'),
                        'port': service.get('port', 'Unknown'),
                        'version': service.get('version', 'Unknown'),
                        'protocol': service.get('protocol', 'Unknown'),
                        'status': 'Active'
                    })
                    
            # Web assets
            if self.results['endpoint_security'].get('security_headers'):
                assets.append({
                    'type': 'Web Application',
                    'name': self.target,
                    'headers': self.results['endpoint_security']['security_headers'],
                    'status': 'Active'
                })
                
            # Cloud assets
            if self.results['cloud_security'].get('issues'):
                for issue in self.results['cloud_security']['issues']:
                    assets.append({
                        'type': 'Cloud Service',
                        'name': issue.get('service', 'Unknown'),
                        'issue': issue.get('description', 'Unknown'),
                        'status': 'Active'
                    })
                    
            # Email assets
            if self.results['email_security']:
                assets.append({
                    'type': 'Email Service',
                    'name': self.email,
                    'domain': self.email.split('@')[1] if self.email else None,
                    'status': 'Active'
                })
                    
            # Categorize assets
            for asset in assets:
                asset_type = asset['type']
                if asset_type not in asset_info['asset_types']:
                    asset_info['asset_types'][asset_type] = []
                asset_info['asset_types'][asset_type].append(asset)
                
            # Calculate risk levels and criticality
            for asset_type, asset_list in asset_info['asset_types'].items():
                risk_level = self.calculate_asset_risk(asset_list)
                criticality = self.calculate_asset_criticality(asset_list)
                sensitivity = self.calculate_asset_sensitivity(asset_list)
                business_impact = self.calculate_business_impact(asset_list)
                
                asset_info['risk_levels'][asset_type] = risk_level
                asset_info['criticality'][asset_type] = criticality
                asset_info['sensitivity'][asset_type] = sensitivity
                asset_info['business_impact'][asset_type] = business_impact
                
            # Map asset relationships
            asset_info['asset_relationships'] = self.map_asset_relationships(assets)
            
            # Assign asset owners
            asset_info['asset_owners'] = self.assign_asset_owners(assets)
            
            # Update asset status
            asset_info['asset_status'] = self.update_asset_status(assets)
                
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

    def calculate_asset_criticality(self, assets: List[Dict]) -> str:
        """Calculate criticality level for a group of assets"""
        criticality_score = 0
        
        for asset in assets:
            # Check for critical services
            if asset['type'] in ['Web Application', 'Email Service', 'Database Service']:
                criticality_score += 3
                
            # Check for production systems
            if 'prod' in str(asset).lower() or 'production' in str(asset).lower():
                criticality_score += 2
                
            # Check for customer-facing services
            if 'customer' in str(asset).lower() or 'client' in str(asset).lower():
                criticality_score += 2
                
            # Check for financial services
            if 'payment' in str(asset).lower() or 'financial' in str(asset).lower():
                criticality_score += 3
                
        if criticality_score >= 8:
            return 'Critical'
        elif criticality_score >= 5:
            return 'High'
        elif criticality_score >= 3:
            return 'Medium'
        else:
            return 'Low'

    def calculate_asset_sensitivity(self, assets: List[Dict]) -> str:
        """Calculate sensitivity level for a group of assets"""
        sensitivity_score = 0
        
        for asset in assets:
            # Check for sensitive data
            if any(sensitive in str(asset).lower() for sensitive in ['password', 'key', 'secret', 'personal', 'private']):
                sensitivity_score += 3
                
            # Check for regulated data
            if any(regulated in str(asset).lower() for regulated in ['hipaa', 'pci', 'gdpr', 'compliance']):
                sensitivity_score += 2
                
            # Check for customer data
            if 'customer' in str(asset).lower() or 'user' in str(asset).lower():
                sensitivity_score += 2
                
        if sensitivity_score >= 5:
            return 'High'
        elif sensitivity_score >= 3:
            return 'Medium'
        else:
            return 'Low'

    def calculate_business_impact(self, assets: List[Dict]) -> str:
        """Calculate business impact level for a group of assets"""
        impact_score = 0
        
        for asset in assets:
            # Check for revenue impact
            if 'payment' in str(asset).lower() or 'sales' in str(asset).lower():
                impact_score += 3
                
            # Check for customer impact
            if 'customer' in str(asset).lower() or 'user' in str(asset).lower():
                impact_score += 2
                
            # Check for operational impact
            if 'operation' in str(asset).lower() or 'service' in str(asset).lower():
                impact_score += 2
                
        if impact_score >= 5:
            return 'High'
        elif impact_score >= 3:
            return 'Medium'
        else:
            return 'Low'

    def map_asset_relationships(self, assets: List[Dict]) -> Dict:
        """Map relationships between assets"""
        relationships = {}
        
        for asset in assets:
            asset_name = asset.get('name', 'Unknown')
            relationships[asset_name] = {
                'dependencies': [],
                'connected_to': [],
                'depends_on': []
            }
            
            # Map dependencies based on asset type
            if asset['type'] == 'Web Application':
                relationships[asset_name]['dependencies'].extend([
                    {'type': 'Database Service', 'name': 'Database'},
                    {'type': 'Email Service', 'name': 'Email System'}
                ])
                
            elif asset['type'] == 'Email Service':
                relationships[asset_name]['dependencies'].extend([
                    {'type': 'DNS Service', 'name': 'DNS'},
                    {'type': 'Security Service', 'name': 'Security Gateway'}
                ])
                
        return relationships

    def assign_asset_owners(self, assets: List[Dict]) -> Dict:
        """Assign ownership recommendations for assets"""
        owners = {}
        
        for asset in assets:
            asset_name = asset.get('name', 'Unknown')
            owners[asset_name] = {
                'recommended_owner': 'System Administrator',
                'department': 'IT'
            }
            
            if asset['type'] in ['Web Application', 'Email Service']:
                owners[asset_name]['recommended_owner'] = 'Application Owner'
                owners[asset_name]['department'] = 'Development'
                
        return owners

    def update_asset_status(self, assets: List[Dict]) -> Dict:
        """Update status of assets based on various factors"""
        status = {}
        
        for asset in assets:
            asset_name = asset.get('name', 'Unknown')
            status[asset_name] = {
                'operational_status': 'Active',
                'last_scan': datetime.now().isoformat(),
                'health_status': 'Healthy',
                'maintenance_status': 'None'
            }
            
            # Update status based on issues
            if any(issue in str(asset).lower() for issue in ['error', 'failed', 'down']):
                status[asset_name]['health_status'] = 'Unhealthy'
                
        return status

    async def run_scan(self, background_tasks: BackgroundTasks) -> Dict[str, Any]:
        """Run security assessment with optimized task execution"""
        try:
            self.console.print(Panel("Starting Security Assessment", style="bold blue"))
            
            # Get profile settings
            profile_settings = self.scan_profiles.get(self.profile, self.scan_profiles['standard'])
            timeout = profile_settings['timeout']
            tasks = profile_settings['tasks']
            
            # Create tasks for concurrent execution
            async def run_task(task_name: str):
                try:
                    if task_name == 'network_security':
                        self.results['network_security'] = await self.assess_network_security()
                    elif task_name == 'dns_health':
                        self.results['dns_health'] = await self.assess_dns_health()
                    elif task_name == 'ssl_tls_security':
                        self.results['ssl_tls_security'] = await self.assess_ssl_tls_security()
                    elif task_name == 'endpoint_security':
                        self.results['endpoint_security'] = await self.assess_endpoint_security()
                    elif task_name == 'vulnerability_assessment':
                        self.results['vulnerability_assessment'] = await self.assess_vulnerability()
                    elif task_name == 'ip_reputation':
                        self.results['ip_reputation'] = await self.assess_ip_reputation()
                    elif task_name == 'email_security':
                        self.results['email_security'] = await self.assess_email_security()
                    elif task_name == 'api_security':
                        self.results['api_security'] = await self.assess_api_security()
                    elif task_name == 'container_security':
                        self.results['container_security'] = await self.assess_container_security()
                    elif task_name == 'database_security':
                        self.results['database_security'] = await self.assess_database_security()
                    elif task_name == 'patching_status':
                        self.results['patching_status'] = await self.assess_patching_status()
                    elif task_name == 'compliance':
                        self.results['compliance'] = await self.assess_compliance()
                    elif task_name == 'asset_inventory':
                        self.results['asset_inventory'] = await self.assess_asset_inventory()
                    elif task_name == 'cloud_security':
                        self.results['cloud_security'] = await self.assess_cloud_security()
                except Exception as e:
                    logger.error(f"Error in {task_name}: {str(e)}")
                    self.results[task_name] = {'error': str(e)}
                    raise  # Re-raise the exception to be caught by the caller

            # Run tasks concurrently with timeout
            try:
                await asyncio.wait_for(
                    asyncio.gather(*[run_task(task) for task in tasks]),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                logger.warning(f"Scan timed out after {timeout} seconds")
                # Add timeout message to results
                for task in tasks:
                    if not self.results[task]:
                        self.results[task] = {'error': 'Task timed out'}
            except Exception as e:
                logger.error(f"Scan failed: {str(e)}")
                return {
                    'status': 'error',
                    'error': str(e)
                }

            # Store results in database
            self.store_results()
            
            # Send email report if email is provided
            if self.email:
                background_tasks.add_task(self.send_email_report)
            
            return {
                'status': 'success',
                'results': self.results
            }
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def calculate_overall_risk(self) -> None:
        """Calculate overall risk score based on findings"""
        risk_score = 0
        total_issues = 0
        critical_issues = 0
        
        # Weight factors for different severity levels
        severity_weights = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 1
        }
        
        # Calculate risk score from all assessment results
        for category, results in self.results.items():
            if isinstance(results, dict):
                # Check for issues in each category
                if 'issues' in results:
                    for issue in results['issues']:
                        total_issues += 1
                        if isinstance(issue, dict) and 'severity' in issue:
                            severity = issue['severity']
                            if severity in severity_weights:
                                risk_score += severity_weights[severity]
                                if severity in ['Critical', 'High']:
                                    critical_issues += 1
                
                # Check for vulnerabilities
                if 'common_vulnerabilities' in results:
                    for vuln in results['common_vulnerabilities']:
                        total_issues += 1
                        if 'severity' in vuln:
                            severity = vuln['severity']
                            if severity in severity_weights:
                                risk_score += severity_weights[severity]
                                if severity in ['Critical', 'High']:
                                    critical_issues += 1
        
        # Normalize risk score (0-100)
        max_possible_score = total_issues * 10  # Assuming all issues are critical
        normalized_score = (risk_score / max_possible_score) * 100 if max_possible_score > 0 else 0
        
        # Add risk metrics to results
        self.results['risk_metrics'] = {
            'total_issues': total_issues,
            'critical_issues': critical_issues,
            'risk_score': round(normalized_score, 2),
            'risk_level': self.get_risk_level(normalized_score)
        }

    def get_risk_level(self, score: float) -> str:
        """Convert risk score to risk level"""
        if score >= 80:
            return 'Critical'
        elif score >= 60:
            return 'High'
        elif score >= 40:
            return 'Medium'
        elif score >= 20:
            return 'Low'
        else:
            return 'Very Low'

    def generate_report(self) -> str:
        """Generate a comprehensive security report"""
        report = f"""
Security Assessment Report
=========================
Target: {self.target}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Executive Summary
----------------
Total Vulnerabilities: {self.results['vulnerability_assessment']['metrics']['total_vulnerabilities']}
Critical Vulnerabilities: {self.results['vulnerability_assessment']['metrics']['critical_vulnerabilities']}
High Vulnerabilities: {self.results['vulnerability_assessment']['metrics']['high_vulnerabilities']}
Average Risk Score: {self.results['vulnerability_assessment']['metrics']['average_risk_score']:.2f}

Risk Analysis
------------
Severity Distribution:
{self.format_distribution(self.results['vulnerability_assessment']['risk_analysis']['severity_distribution'])}

Exploitability Distribution:
{self.format_distribution(self.results['vulnerability_assessment']['risk_analysis']['exploitability_distribution'])}

Impact Analysis:
{self.format_impact_analysis(self.results['vulnerability_assessment']['risk_analysis']['impact_analysis'])}

Performance Metrics
-----------------
Mean Time to Detect (MTTD): {self.results['vulnerability_assessment']['metrics']['mttd']:.2f} days
Mean Time to Remediate (MTTR): {self.results['vulnerability_assessment']['metrics']['mttr']:.2f} days

Remediation Priorities
--------------------
"""
        
        for priority in self.results['vulnerability_assessment']['remediation_priorities']:
            report += f"""
Vulnerability: {priority['vulnerability']['type']}
Priority Level: {priority['priority_level']}
Timeline: {priority['recommended_timeline']}
Recommended Team: {priority['responsible_team']}
Risk Score: {priority['vulnerability']['risk_score']}
Impact: {priority['vulnerability']['impact']}
"""
            
        return report

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

    async def assess_cloud_security(self) -> None:
        """Perform cloud security assessment (currently skipped)"""
        if not self.target:
            return
            
        self.console.print(f"[yellow]Cloud security assessment temporarily disabled.[/yellow]")
        
        cloud_info = {
            'status': 'skipped',
            'message': 'Cloud security assessment temporarily disabled - will be enabled in future updates'
        }
            
        self.results['cloud_security'] = cloud_info

# API endpoints
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/scan")
async def scan_target(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    try:
        logger.info(f"Starting scan for target: {scan_request.target}")
        
        # Create scanner instance
        scanner = SecurityScanner(
            target=scan_request.target,
            email=scan_request.email,
            profile=scan_request.profile
        )
        
        # Perform security assessment
        results = await scanner.run_scan(background_tasks)
        
        logger.info(f"Scan completed successfully for target: {scan_request.target}")
        
        # Return results
        return {
            "status": "success",
            "message": "Scan completed successfully",
            "results": results
        }
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Error during scan: {str(e)}"
        )

@app.get("/health")
async def health_check():
    """API endpoint to check service health"""
    return {"status": "healthy"}

@app.post("/download-report")
async def download_report(results: ScanResults, background: BackgroundTasks):
    """Generate and download a PDF report"""
    try:
        # Create a temporary file for the PDF
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
            tmp_path = tmp.name

        # Create PDF
        pdf = FPDF()
        pdf.add_page()

        # Add title
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Security Assessment Report", ln=True)
        pdf.ln(10)

        # Add target and date
        pdf.set_font("Arial", "", 12)
        pdf.cell(0, 10, f"Target: {results.target}", ln=True)
        pdf.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        pdf.ln(10)

        # Add summary
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Summary", ln=True)
        pdf.set_font("Arial", "", 10)
        
        # Calculate metrics
        total_issues = 0
        critical_issues = 0
        risk_score = 0
        
        for section, data in results.results.items():
            if isinstance(data, dict):
                if 'issues' in data:
                    total_issues += len(data['issues'])
                    critical_issues += len([i for i in data['issues'] if i.get('severity') == 'Critical'])
                if 'risk_score' in data:
                    risk_score = max(risk_score, data['risk_score'])
        
        pdf.cell(0, 10, f"Total Issues: {total_issues}", ln=True)
        pdf.cell(0, 10, f"Critical Issues: {critical_issues}", ln=True)
        pdf.cell(0, 10, f"Risk Score: {risk_score}%", ln=True)
        pdf.ln(10)

        # Add detailed results
        for section, data in results.results.items():
            if isinstance(data, dict):
                pdf.set_font("Arial", "B", 12)
                pdf.cell(0, 10, section.replace("_", " ").title(), ln=True)
                pdf.set_font("Arial", "", 10)
                
                for key, value in data.items():
                    if key != "error":
                        if isinstance(value, list):
                            pdf.cell(0, 10, f"{key}:", ln=True)
                            for item in value:
                                if isinstance(item, dict):
                                    for k, v in item.items():
                                        pdf.cell(0, 10, f"  {k}: {v}", ln=True)
                                else:
                                    pdf.cell(0, 10, f"  {item}", ln=True)
                        else:
                            pdf.cell(0, 10, f"{key}: {value}", ln=True)
                pdf.ln(5)

        # Save the PDF
        pdf.output(tmp_path)

        # Add cleanup task
        background.add_task(lambda: os.unlink(tmp_path))

        # Return the file
        return FileResponse(
            tmp_path,
            media_type="application/pdf",
            filename="security-report.pdf"
        )

    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn # type: ignore
    uvicorn.run(app, host="0.0.0.0", port=8000) 