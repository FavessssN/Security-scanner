# Enhanced Attack Surface Assessment Tool

A comprehensive security assessment tool that evaluates various aspects of a target system's security posture, including network security, DNS health, patching status, endpoint security, IP reputation, application security, information leakage, and social engineering risks.

## Features

The security scanner performs the following assessments:

1. **Network Security**
   - Port scanning
   - Service enumeration
   - OS detection
   - Network service identification

- **DNS Health Assessment**
  - DNSSEC validation
  - DNS record analysis (A, AAAA, MX, NS, TXT, SOA, CAA)
  - DNS security best practices check

- **Patching Status Assessment**
  - Known vulnerability scanning
  - CVE database integration
  - Version checking
  - Patch status reporting

- **Endpoint Security Assessment**
  - Shodan integration for exposed services
  - Vulnerability scanning
  - Service enumeration
  - Security misconfiguration detection

- **IP Reputation Assessment**
  - VirusTotal integration
  - Malware scanning
  - Reputation checking
  - Historical data analysis

- **Application Security Assessment**
  - Security headers analysis
  - Web vulnerability scanning
  - SSL/TLS configuration check
  - Security best practices validation

- **Information Leakage Assessment**
  - Sensitive file detection
  - Directory traversal testing
  - Information disclosure checks
  - Robots.txt analysis

- **Social Engineering Assessment**
  - Email security (SPF, DKIM, DMARC)
  - Social media presence analysis
  - Information exposure checks
  - Security awareness indicators

- **Slack Integration**
  - Automated report delivery
  - Real-time notifications
  - Customizable reporting
  - Team collaboration features

## Prerequisites

- Python 3.7 or higher
- Nmap installed on your system
  - On macOS: `brew install nmap`
  - On Ubuntu/Debian: `sudo apt-get install nmap`
  - On Windows: Download from [Nmap's official website](https://nmap.org/download.html)

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd attack-surface-scanner
```

2. Install the required Python packages:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
```bash
cp .env.example .env
```
Edit the `.env` file with your API keys and Slack configuration.

## API Keys Required

- Shodan API Key: [Get it here](https://account.shodan.io/register)
- VirusTotal API Key: [Get it here](https://www.virustotal.com/gui/join-us)
- Slack Bot Token: [Create a Slack App](https://api.slack.com/apps)

## Usage

Basic usage:
```bash
python security_scanner.py example.com
```

Specify a custom port range:
```bash
python security_scanner.py example.com --ports 1-65535
```

## Output

The tool generates comprehensive reports in two formats:
1. Console output with formatted tables and panels
2. Slack messages with categorized findings

## Security Note

This tool is intended for legitimate security assessment purposes only. Always ensure you have proper authorization before scanning any systems or domains.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License

## Acknowledgments

- Nmap for network scanning capabilities
- Shodan for internet-wide scanning data
- VirusTotal for malware and reputation data
- NVD for vulnerability database
- Slack for messaging platform 