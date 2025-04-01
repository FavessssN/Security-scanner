import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# API Configuration
API_CONFIG = {
    'SHODAN': {
        'key': os.getenv('SHODAN_API_KEY'),
        'base_url': 'https://api.shodan.io',
    },
    'ABUSEIPDB': {
        'key': os.getenv('ABUSEIPDB_API_KEY'),
        'base_url': 'https://api.abuseipdb.com/api/v2',
    }
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