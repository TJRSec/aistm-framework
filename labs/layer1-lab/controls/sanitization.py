"""
Sanitization Control Module

This module handles basic input sanitization including:
- HTML tag stripping/escaping
- Special character handling
- Length enforcement

These are traditional web security controls adapted for AI contexts.
"""

import html
import re
from dataclasses import dataclass, field
from typing import Optional

# Try to import bleach, fall back to basic escaping if not available
try:
    import bleach
    BLEACH_AVAILABLE = True
except ImportError:
    BLEACH_AVAILABLE = False


@dataclass
class SanitizationResult:
    """Result of sanitization analysis"""
    original: str
    sanitized: str
    was_modified: bool
    findings: list = field(default_factory=list)
    html_tags_found: list = field(default_factory=list)
    special_chars_found: list = field(default_factory=list)
    length_exceeded: bool = False
    original_length: int = 0
    truncated_length: Optional[int] = None
    xss_detected: bool = False
    xss_patterns: list = field(default_factory=list)


class SanitizationControl:
    """
    Traditional input sanitization control.
    
    This control applies standard web security sanitization techniques:
    1. HTML tag detection and stripping
    2. Special character escaping
    3. Length limit enforcement
    
    While these won't stop prompt injection directly, they prevent
    traditional XSS/injection attacks that might be stored or reflected
    through AI-powered applications.
    """
    
    def __init__(self, max_length: int = 4000, strip_html: bool = True):
        """
        Initialize the sanitization control.
        
        Args:
            max_length: Maximum allowed input length in characters
            strip_html: Whether to strip HTML tags (True) or just escape them (False)
        """
        self.max_length = max_length
        self.strip_html = strip_html
        
        # Patterns for detection (not blocking, just logging)
        self.html_tag_pattern = re.compile(r'<[^>]+>')
        self.script_pattern = re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL)
        self.event_handler_pattern = re.compile(r'\bon\w+\s*=', re.IGNORECASE)
        
        # Special characters that might indicate injection attempts
        self.special_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '{', '}', '[', ']', '|', '`']
    
    def analyze(self, text: str) -> SanitizationResult:
        """
        Analyze and sanitize the input text.
        
        This method both analyzes what suspicious content exists AND
        returns the sanitized version. The UI can show what was found
        even if sanitization is disabled.
        
        Args:
            text: The raw input text to analyze
            
        Returns:
            SanitizationResult with analysis and sanitized text
        """
        result = SanitizationResult(
            original=text,
            sanitized=text,
            was_modified=False,
            original_length=len(text)
        )
        
        findings = []
        xss_patterns = []
        
        # Check for HTML tags
        html_tags = self.html_tag_pattern.findall(text)
        if html_tags:
            result.html_tags_found = html_tags[:10]  # Limit to first 10
            findings.append(f"Found {len(html_tags)} HTML tag(s)")
        
        # Check for script tags specifically
        if self.script_pattern.search(text):
            findings.append("Script tags detected (potential XSS)")
            xss_patterns.append("script tag")
        
        # Check for event handlers
        if self.event_handler_pattern.search(text):
            findings.append("Event handler attributes detected (potential XSS)")
            xss_patterns.append("event handler")
        
        # Check for javascript: protocol
        if re.search(r'javascript\s*:', text, re.IGNORECASE):
            findings.append("JavaScript protocol detected (potential XSS)")
            xss_patterns.append("javascript: protocol")
        
        # Check for data: URI with base64
        if re.search(r'data\s*:\s*[^;]+;base64', text, re.IGNORECASE):
            findings.append("Data URI with base64 detected (potential XSS)")
            xss_patterns.append("data: URI")
        
        # Update XSS detection result
        result.xss_detected = len(xss_patterns) > 0
        result.xss_patterns = xss_patterns
        
        # Check for special characters
        found_special = [c for c in self.special_chars if c in text]
        if found_special:
            result.special_chars_found = found_special
            if len(found_special) > 3:
                findings.append(f"Multiple special characters: {', '.join(found_special)}")
        
        # Check length
        if len(text) > self.max_length:
            result.length_exceeded = True
            findings.append(f"Length {len(text)} exceeds limit {self.max_length}")
        
        result.findings = findings
        
        # Now perform actual sanitization
        sanitized = text
        
        # Strip or escape HTML
        if html_tags:
            if self.strip_html:
                if BLEACH_AVAILABLE:
                    # Bleach strips all tags by default with empty allowed list
                    sanitized = bleach.clean(sanitized, tags=[], strip=True)
                else:
                    # Fallback: simple regex strip
                    sanitized = self.html_tag_pattern.sub('', sanitized)
            else:
                # Just escape, don't strip
                sanitized = html.escape(sanitized)
        
        # Enforce length limit
        if len(sanitized) > self.max_length:
            sanitized = sanitized[:self.max_length]
            result.truncated_length = self.max_length
        
        # Check if we modified anything
        result.was_modified = (sanitized != text)
        result.sanitized = sanitized
        
        return result
    
    def get_info(self) -> dict:
        """Return information about this control for the UI"""
        return {
            "name": "HTML Sanitization",
            "description": "Strips or escapes HTML tags and enforces length limits",
            "category": "Traditional Web Security",
            "settings": {
                "max_length": self.max_length,
                "strip_html": self.strip_html,
                "bleach_available": BLEACH_AVAILABLE
            },
            "detects": [
                "HTML/XML tags",
                "Script injection attempts", 
                "Event handler attributes",
                "Excessive input length"
            ],
            "bypasses": [
                "Does not detect prompt injection in plain text",
                "Encoded payloads (Base64, URL encoding) pass through",
                "Semantic manipulation unaffected"
            ]
        }
