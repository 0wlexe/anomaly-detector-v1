import os
from enum import Enum
from typing import List, Dict

# File paths
TRAFFIC_LOG_FILE = "traffic_logs.csv"
LOGIN_LOG_FILE = "signin_logs.csv"  
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FULL_TRAFFIC_LOG_PATH = os.path.join(SCRIPT_DIR, TRAFFIC_LOG_FILE) # Path for traffic logs
FULL_LOGIN_LOG_PATH = os.path.join(SCRIPT_DIR, LOGIN_LOG_FILE)   # Path for sign-in logs

# Enumeration Data
class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

# Combined Attack Types
class AttackType(str, Enum):
    # Network Attack Types
    BRUTE_FORCE = "BRUTE_FORCE"
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    FILE_INCLUSION = "FILE_INCLUSION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    UNKNOWN = "UNKNOWN" # Generic/Traffic
    # Login Attack Types
    FAILED_LOGIN_ATTEMPT = "FAILED_LOGIN_ATTEMPT"
    UNTRUSTED_DEVICE_LOGIN = "UNTRUSTED_DEVICE_LOGIN"
    RISKY_REAUTHENTICATION = "RISKY_REAUTHENTICATION"
    SUSPICIOUS_DATA_FIELD = "SUSPICIOUS_DATA_FIELD"
    MULTI_FACTOR_ISSUES = "MULTI_FACTOR_ISSUES"

# Anomaly rules specifically for traffic analysis
ANOMALY_RULES: List[Dict] = [
    {       
        "type": "sql_injection",
        "pattern": r"(.*(?:select|insert|update|delete).*(?:from|into|set|where).*)",
        "description": "Potential SQL Injection",
        "severity": SeverityLevel.HIGH,
        "attack_types": [AttackType.SQL_INJECTION]
    },
    {
        "type": "xss_attack",
        "pattern": r"(<script.*?>.*?</script>)",
        "description": "Potential XSS Attack",
        "severity": SeverityLevel.MEDIUM,
        "attack_types": [AttackType.XSS]
    },
    {
        "type": "file_inclusion",
        "pattern": r"(\.\./\.\./)",
        "description": "Potential File Inclusion Attack",
        "severity": SeverityLevel.HIGH,
        "attack_types": [AttackType.FILE_INCLUSION]
    },
    {
        "type": "command_injection",
        "pattern": r"(;.*)", # Example: looking for command chaining via semicolon
        "description": "Potential Command Injection Attack",
        "severity": SeverityLevel.HIGH,
        "attack_types": [AttackType.COMMAND_INJECTION]
    },
    {
        "type": "bot_activity",
        "pattern": r"(?i)(bot|crawler|spider|scan|agent|curl|wget)", 
        "description": "Bot Activity Detected (UA Based)",
        "severity": SeverityLevel.LOW,
        "attack_types": [AttackType.UNKNOWN]
    },
    {
        "type": "high_error_rate",
        "status_code": "500", # Example: Track 500 errors
        "threshold": 5, # Trigger anomaly if more than 5 detected
        "description": "High 5xx Server Error Rate",
        "severity": SeverityLevel.MEDIUM,
        "attack_types": [AttackType.UNKNOWN]
    },
    {
        "type": "brute_force_login_ua", 
        "pattern": r"(?i)(failed login|login attempt)", # Example pattern in user agent or URI
        "description": "Potential Brute force hint (UA/URI based)",
        "severity": SeverityLevel.MEDIUM,
        "attack_types": [AttackType.BRUTE_FORCE]
    }
]