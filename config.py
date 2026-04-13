"""
Configuration settings for the AI-Powered Secure Code Analysis Tool.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# OpenAI Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = "gpt-4o"

# Flask Configuration
SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "change-me-in-production")
FLASK_ENV = os.getenv("FLASK_ENV", "production")
DEBUG = FLASK_ENV == "development"

# File Upload Configuration
MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "5"))
MAX_CONTENT_LENGTH = MAX_FILE_SIZE_MB * 1024 * 1024
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {
    "py", "js", "ts", "java", "c", "cpp", "cs", "go",
    "rb", "php", "swift", "kt", "rs", "html", "sql",
}

# Severity levels
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

SEVERITY_ORDER = {
    SEVERITY_CRITICAL: 0,
    SEVERITY_HIGH: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 3,
    SEVERITY_INFO: 4,
}
