"""
AISTM Layer 3 Control: Sensitive Data Filter

Filters sensitive data from AI output to prevent accidental disclosure.
Essential for preventing data leakage in AI responses.

Key Features:
- API key detection and filtering
- Password/secret detection
- Internal URL detection
- Private IP detection
- PII filtering

Reference: AISTM Layer 3 Testing Guide - Sensitive Data Filtering section
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class FilterResult:
    """Result from sensitive data filtering"""
    filtered: str
    found_sensitive: bool
    count: int
    sensitive_types: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)


class SensitiveDataFilter:
    """
    Filters sensitive data from AI output.
    
    AI can accidentally include sensitive information like API keys,
    passwords, or internal URLs in responses. This filter detects
    and redacts such information.
    """
    
    # API key patterns
    API_KEY_PATTERNS = [
        (r'(?:api[_-]?key|apikey|api_secret|api_token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', 'API Key'),
        (r'sk-[a-zA-Z0-9]{32,}', 'OpenAI API Key'),
        (r'sk-ant-[a-zA-Z0-9\-]{40,}', 'Anthropic API Key'),
        (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key'),
        (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token'),
        (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth Token'),
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID'),
        (r'(?:secret[_-]?key|secretkey|secret_access_key)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9+/=]{20,})["\']?', 'Secret Key'),
    ]
    
    # Password patterns
    PASSWORD_PATTERNS = [
        (r'(?:password|passwd|pwd|pass)["\']?\s*[:=]\s*["\']?([^\s"\']{4,})["\']?', 'Password'),
        (r'(?:token|auth_token|access_token|bearer)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{10,})["\']?', 'Token'),
    ]
    
    # Internal URL patterns
    INTERNAL_URL_PATTERNS = [
        (r'https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?(?:/[^\s]*)?', 'Localhost URL'),
        (r'https?://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+)(?::\d+)?(?:/[^\s]*)?', 'Internal IP URL'),
        (r'https?://[a-zA-Z0-9\-]+\.(?:internal|local|corp|intranet)(?:\.[a-zA-Z]+)?(?::\d+)?(?:/[^\s]*)?', 'Internal Domain URL'),
    ]
    
    # Private IP patterns
    PRIVATE_IP_PATTERNS = [
        (r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'Class A Private IP'),
        (r'\b172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b', 'Class B Private IP'),
        (r'\b192\.168\.\d{1,3}\.\d{1,3}\b', 'Class C Private IP'),
    ]
    
    def __init__(self, redaction_string: str = "[REDACTED]"):
        """
        Initialize the filter.
        
        Args:
            redaction_string: String to replace sensitive data with
        """
        self.redaction_string = redaction_string
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile all regex patterns"""
        self.patterns = []
        
        for pattern, name in self.API_KEY_PATTERNS:
            self.patterns.append((re.compile(pattern, re.IGNORECASE), name))
        
        for pattern, name in self.PASSWORD_PATTERNS:
            self.patterns.append((re.compile(pattern, re.IGNORECASE), name))
        
        for pattern, name in self.INTERNAL_URL_PATTERNS:
            self.patterns.append((re.compile(pattern, re.IGNORECASE), name))
        
        for pattern, name in self.PRIVATE_IP_PATTERNS:
            self.patterns.append((re.compile(pattern), name))
    
    def analyze(self, text: str) -> FilterResult:
        """
        Filter sensitive data from text.
        
        Args:
            text: The text to filter
            
        Returns:
            FilterResult with filtered text
        """
        filtered = text
        sensitive_types = set()
        findings = []
        count = 0
        
        for pattern, name in self.patterns:
            matches = pattern.findall(filtered)
            if matches:
                count += len(matches)
                sensitive_types.add(name)
                findings.append(f"Found {len(matches)} {name}(s)")
                filtered = pattern.sub(self.redaction_string, filtered)
        
        found_sensitive = count > 0
        
        if not found_sensitive:
            findings.append("No sensitive data detected")
        
        return FilterResult(
            filtered=filtered,
            found_sensitive=found_sensitive,
            count=count,
            sensitive_types=list(sensitive_types),
            findings=findings
        )
    
    def get_info(self) -> Dict:
        """Get control information"""
        return {
            "name": "Sensitive Data Filter",
            "description": "Filters API keys, passwords, and internal URLs from output",
            "category": "Data Protection",
            "detects": [
                "API Keys (OpenAI, Anthropic, Google, GitHub, AWS)",
                "Passwords and tokens",
                "Internal URLs",
                "Private IP addresses"
            ]
        }
