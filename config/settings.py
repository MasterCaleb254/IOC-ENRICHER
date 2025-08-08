import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# API Keys
VT_API_KEY = os.getenv('VT_API_KEY')
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
OTX_API_KEY = os.getenv('OTX_API_KEY')

# Cache settings
CACHE_ENABLED = True
CACHE_TTL = 86400  # 24 hours in seconds
CACHE_PATH = BASE_DIR / 'cache' / 'ioc_cache.db'

# Output settings
DEFAULT_OUTPUT_FORMAT = 'json'
OUTPUT_DIR = BASE_DIR / 'output'