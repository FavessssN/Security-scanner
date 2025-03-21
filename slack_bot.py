#!/usr/bin/env python3
import os
import logging
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from dotenv import load_dotenv
import aiohttp
import asyncio
import json

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Slack app
app = App(token=os.getenv("SLACK_BOT_TOKEN"))

# Security scanner API endpoint
SCANNER_API_URL = os.getenv("SCANNER_API_URL", "http://localhost:8000")

async def call_scanner_api(target=None, email=None, profile="standard"):
    """Make API call to security scanner"""
    async with aiohttp.ClientSession() as session:
        payload = {
            "target": target,
            "email": email,
            "profile": profile
        }
        
        try:
            async with session.post(f"{SCANNER_API_URL}/scan", json=payload) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_text = await response.text()
                    raise Exception(f"Scanner API error: {error_text}")
        except Exception as e:
            logger.error(f"Error calling scanner API: {str(e)}")
            raise

@app.command("/scan")
def handle_scan_command(ack, command, say):
    """Handle /scan command"""
    ack()
    
    try:
        # Parse command text
        args = command['text'].split()
        if not args:
            say("Please provide a target domain or email address.\nUsage: /scan [domain] [--email email@domain.com] [--profile quick|standard|comprehensive]")
            return
            
        # Parse arguments
        target = None
        email = None
        profile = "standard"
        
        i = 0
        while i < len(args):
            if args[i] == "--email" and i + 1 < len(args):
                email = args[i + 1]
                i += 2
            elif args[i] == "--profile" and i + 1 < len(args):
                profile = args[i + 1]
                i += 2
            else:
                target = args[i]
                i += 1
                
        if not target and not email:
            say("Please provide either a target domain or email address.")
            return
            
        # Start scan
        say(f"Starting security scan...\nTarget: {target if target else 'None'}\nEmail: {email if email else 'None'}\nProfile: {profile}")
        
        # Run scan asynchronously
        asyncio.create_task(run_scan_and_report(target, email, profile, say))
        
    except Exception as e:
        say(f"Error initiating scan: {str(e)}")

async def run_scan_and_report(target, email, profile, say):
    """Run scan and report results"""
    try:
        # Call scanner API
        results = await call_scanner_api(target, email, profile)
        
        if results["status"] == "success":
            # Format and send results
            message = format_results(results["results"])
            say(message)
        else:
            say("Scan completed with errors. Please check the logs for details.")
            
    except Exception as e:
        say(f"Error during scan: {str(e)}")

def format_results(results):
    """Format scan results for Slack message"""
    message = "*Security Scan Results*\n\n"
    
    # Network Security
    if results.get('network_security'):
        network = results['network_security']
        message += "*Network Security*\n"
        message += f"• Passive Port Information: {len(network.get('passive_port_info', {}).get('ports', []))}\n"
        message += f"• Passive Service Information: {len(network.get('passive_service_info', {}).get('services', []))}\n\n"
    
    # Email Security
    if results.get('email_security'):
        email = results['email_security']
        message += "*Email Security*\n"
        message += f"• Validation: {email.get('validation', {}).get('format', 'Unknown')}\n"
        message += f"• SPF: {'Configured' if email.get('domain_security', {}).get('spf') != 'Not found' else 'Missing'}\n"
        message += f"• DMARC: {'Configured' if email.get('domain_security', {}).get('dmarc') != 'Not found' else 'Missing'}\n"
        message += f"• DKIM: {'Configured' if email.get('domain_security', {}).get('dkim') != 'Not found' else 'Missing'}\n"
        message += f"• Phishing Risk Score: {email.get('phishing_risk', {}).get('score', 0)}/10\n\n"
    
    # DNS Health
    if results.get('dns_health'):
        dns = results['dns_health']
        message += "*DNS Health*\n"
        message += f"• Issues: {', '.join(dns.get('issues', [])) if dns.get('issues', []) else 'None'}\n\n"
    
    # Vulnerability Assessment
    if results.get('vulnerability_assessment'):
        vuln = results['vulnerability_assessment']
        message += "*Vulnerability Assessment*\n"
        message += f"• Common Vulnerabilities: {len(vuln.get('common_vulnerabilities', []))}\n"
        message += f"• Security Issues: {len(vuln.get('security_issues', []))}\n\n"
    
    # SSL/TLS Security
    if results.get('ssl_tls_security'):
        ssl = results['ssl_tls_security']
        message += "*SSL/TLS Security*\n"
        message += f"• Certificate Valid: {'Yes' if ssl.get('certificate_info', {}).get('valid') else 'No'}\n"
        message += f"• Issues: {', '.join(ssl.get('security_issues', [])) if ssl.get('security_issues', []) else 'None'}\n\n"
    
    return message

@app.event("app_mention")
def handle_mention(event, say):
    """Handle mentions of the bot"""
    say("Hello! I'm your security scanning assistant. Use `/scan` to start a security assessment.\n"
        "Usage: `/scan [domain] [--email email@domain.com] [--profile quick|standard|comprehensive]`")

if __name__ == "__main__":
    handler = SocketModeHandler(app, os.getenv("SLACK_APP_TOKEN"))
    handler.start() 