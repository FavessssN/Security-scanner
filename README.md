# Security Scanner

A comprehensive passive security assessment tool that performs various security checks without intrusive scanning.

## Features

### Core Security Assessments
- Network Security (Passive)
- DNS Health
- Email Security
- Endpoint Security
- Vulnerability Assessment
- IP Reputation
- SSL/TLS Security
- Cloud Security
- API Security
- Container Security
- Database Security
- Patching Status
- Compliance (PCI DSS, HIPAA, GDPR)
- Asset Inventory
- Team Collaboration
- Real-time Monitoring

### Advanced Features
- Configuration Management (YAML)
- Comprehensive Logging
- PDF Report Generation
- Continuous Monitoring
- Change Detection
- Alert Generation
- API Rate Limiting
- Caching
- Authentication & Authorization
- Historical Data Tracking

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/security-scanner.git
cd security-scanner
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Initialize the database:
```bash
python -c "from security_scanner import SecurityScanner; SecurityScanner().init_database()"
```

## Configuration

The scanner uses a YAML configuration file (`config.yaml`) for:
- Scan profiles
- API keys
- Scan options
- Logging settings

Example configuration:
```yaml
scan_profiles:
  quick:
    vuln_scan: false
    compliance: false
  standard:
    vuln_scan: true
    compliance: true
  comprehensive:
    vuln_scan: true
    compliance: true
    cloud_check: true
```

## Usage

### Command Line
```bash
python security_scanner.py --target example.com --email user@example.com --profile standard
```

### API
```bash
curl -X POST "http://localhost:8000/scan" \
     -H "Content-Type: application/json" \
     -d '{"target": "example.com", "email": "user@example.com", "profile": "standard"}'
```

### Slack Integration
Use the `/scan` command in Slack:
```
/scan example.com --email user@example.com --profile standard
```

## Security Considerations

- No active exploitation or intrusive scanning
- No port scanning or active service enumeration
- All scans are performed passively
- API keys and sensitive data are stored securely
- Rate limiting and caching implemented
- Authentication required for API access

## Logging

Logs are stored in `security_scanner.log` with rotation:
- Maximum size: 1MB
- Backup count: 5 files
- Log level: INFO (configurable)

## Reports

The scanner generates reports in multiple formats:
- Console output (rich formatting)
- PDF reports
- Slack messages
- Historical data in SQLite database

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 