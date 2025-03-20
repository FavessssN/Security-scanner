#!/usr/bin/env python3
import os
import asyncio
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from dotenv import load_dotenv
from security_scanner import EnhancedSecurityScanner
from rich.console import Console

# Load environment variables
load_dotenv()

# Initialize the Slack app
app = App(token=os.getenv('SLACK_BOT_TOKEN'))
console = Console()

@app.command("/security-scan")
def handle_security_scan(ack, command, say):
    """Handle the /security-scan command"""
    # Acknowledge the command request
    ack()
    
    # Get the target from the command text
    target = command['text'].strip()
    if not target:
        say("Please provide a target domain or IP address. Usage: /security-scan example.com")
        return
    
    # Send initial message
    say(f"Starting security scan for {target}...")
    
    try:
        # Create and run the scanner
        scanner = EnhancedSecurityScanner(target)
        
        # Run all assessments
        asyncio.run(scanner.run_all_assessments())
        
        # Generate and send the report
        scanner.generate_report()
        asyncio.run(scanner.send_slack_report())
        
        say("Security scan completed! Check the channel for the detailed report.")
        
    except Exception as e:
        console.print(f"[red]Error during security scan: {str(e)}[/red]")
        say(f"An error occurred during the security scan: {str(e)}")

@app.event("app_mention")
def handle_mentions(event, say):
    """Handle when the bot is mentioned"""
    text = event['text'].lower()
    
    if "help" in text:
        help_text = """
*Security Scanner Bot Commands*
• `/security-scan <target>` - Run a comprehensive security scan on the specified target
• `@bot help` - Show this help message

The security scan includes:
• Network Security Assessment
• DNS Health Check
• Endpoint Security
• Application Security
• Information Leakage Detection
• Social Engineering Risks
• SSL/TLS Security
• Cloud Security
• API Security
• Container Security
• Database Security
"""
        say(help_text)
    else:
        say("Hi! I'm the security scanner bot. Use `@bot help` to see available commands.")

def main():
    """Start the Slack bot"""
    try:
        # Start the app using Socket Mode
        handler = SocketModeHandler(app, os.getenv('SLACK_APP_TOKEN'))
        handler.start()
    except Exception as e:
        console.print(f"[red]Error starting Slack bot: {str(e)}[/red]")

if __name__ == "__main__":
    main() 