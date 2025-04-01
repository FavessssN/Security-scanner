import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# API Configuration
API_CONFIG = {
    'ABUSEIPDB': {
        'key': os.getenv('ABUSEIPDB_API_KEY'),
        'base_url': 'https://api.abuseipdb.com/api/v2',
        'rate_limit': 60  # requests per minute
    },
    'CENSYS': {
        'key': os.getenv('CENSYS_API_KEY'),
        'base_url': 'https://search.censys.io/api/v2',
        'rate_limit': 30  # requests per minute
    },
    'SHODAN': {
        'key': os.getenv('SHODAN_API_KEY'),
        'base_url': 'https://api.shodan.io',
        'rate_limit': 1  # requests per second
    }
}

# Slack Configuration
SLACK_CONFIG = {
    'bot_token': os.getenv('SLACK_BOT_TOKEN'),
    'app_token': os.getenv('SLACK_APP_TOKEN'),
    'rate_limit': 50  # messages per minute
}

# Scanner Configuration
SCANNER_CONFIG = {
    'timeout': 30,  # seconds
    'max_retries': 3,
    'retry_delay': 5,  # seconds
    'scan_profiles': {
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
}

# Database Configuration
DB_CONFIG = {
    'path': 'security_scanner.db',
    'backup_path': 'security_scanner_backup.db',
    'backup_interval': 24 * 60 * 60  # 24 hours in seconds
}

# Logging Configuration
LOG_CONFIG = {
    'level': 'INFO',
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'file': 'security_scanner.log'
}

# Rate Limiting Configuration
RATE_LIMIT_CONFIG = {
    'window': 60,  # seconds
    'max_requests': 100  # requests per window
} 