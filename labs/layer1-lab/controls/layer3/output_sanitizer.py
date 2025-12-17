"""
AISTM Layer 3 Control: Output Sanitizer

Context-aware sanitization of AI output for different contexts.
Essential for preventing injection when output is used in specific contexts.

Key Features:
- HTML context escaping (prevent XSS)
- SQL context escaping (prevent injection)
- Shell context escaping (prevent command injection)
- JavaScript context escaping
- URL encoding

Reference: AISTM Layer 3 Testing Guide - Output Sanitization section
"""

import re
import html
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class SanitizationResult:
    """Result from output sanitization"""
    sanitized: str
    was_modified: bool
    context: str
    modifications: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)


class OutputSanitizer:
    """
    Context-aware output sanitization.
    
    Sanitizes AI output based on the context where it will be used.
    Different contexts require different escaping strategies.
    """
    
    def __init__(self):
        """Initialize the sanitizer"""
        pass
    
    def sanitize(self, text: str, context: str = "text") -> SanitizationResult:
        """
        Sanitize text for a specific context.
        
        Args:
            text: The text to sanitize
            context: The target context (html, sql, shell, javascript, url, text)
            
        Returns:
            SanitizationResult with sanitized text
        """
        original = text
        modifications = []
        findings = []
        
        if context == "html":
            sanitized = self._sanitize_for_html(text, modifications)
        elif context == "sql":
            sanitized = self._sanitize_for_sql(text, modifications)
        elif context == "shell":
            sanitized = self._sanitize_for_shell(text, modifications)
        elif context == "javascript":
            sanitized = self._sanitize_for_javascript(text, modifications)
        elif context == "url":
            sanitized = self._sanitize_for_url(text, modifications)
        else:
            sanitized = text
        
        was_modified = sanitized != original
        if was_modified:
            findings.append(f"Text was sanitized for {context} context")
            findings.append(f"Made {len(modifications)} modification(s)")
        else:
            findings.append("No sanitization needed")
        
        return SanitizationResult(
            sanitized=sanitized,
            was_modified=was_modified,
            context=context,
            modifications=modifications,
            findings=findings
        )
    
    def _sanitize_for_html(self, text: str, modifications: List[str]) -> str:
        """Sanitize for HTML context"""
        sanitized = html.escape(text, quote=True)
        
        if sanitized != text:
            if '<' in text or '>' in text:
                modifications.append("Escaped HTML tags")
            if '&' in text:
                modifications.append("Escaped ampersands")
            if '"' in text or "'" in text:
                modifications.append("Escaped quotes")
        
        return sanitized
    
    def _sanitize_for_sql(self, text: str, modifications: List[str]) -> str:
        """Sanitize for SQL context (escaping, not parameterization)"""
        # Escape single quotes by doubling them
        sanitized = text.replace("'", "''")
        
        # Escape backslashes
        sanitized = sanitized.replace("\\", "\\\\")
        
        # Remove null bytes
        if '\x00' in sanitized:
            sanitized = sanitized.replace('\x00', '')
            modifications.append("Removed null bytes")
        
        if sanitized != text:
            if "'" in text:
                modifications.append("Escaped single quotes")
            if "\\" in text:
                modifications.append("Escaped backslashes")
        
        return sanitized
    
    def _sanitize_for_shell(self, text: str, modifications: List[str]) -> str:
        """Sanitize for shell command context"""
        # Characters to escape in shell
        dangerous_chars = ['$', '`', '\\', '"', '!', ';', '|', '&', '>', '<', '(', ')', '{', '}', '[', ']', '\n', '\r']
        
        sanitized = text
        for char in dangerous_chars:
            if char in sanitized:
                sanitized = sanitized.replace(char, '\\' + char)
                modifications.append(f"Escaped '{char}'")
        
        return sanitized
    
    def _sanitize_for_javascript(self, text: str, modifications: List[str]) -> str:
        """Sanitize for JavaScript string context"""
        # Escape special JavaScript characters
        escapes = [
            ('\\', '\\\\'),  # Backslash first
            ('\n', '\\n'),
            ('\r', '\\r'),
            ('\t', '\\t'),
            ("'", "\\'"),
            ('"', '\\"'),
            ('/', '\\/'),
            ('<', '\\x3c'),  # Prevent </script> breaking
            ('>', '\\x3e'),
        ]
        
        sanitized = text
        for old, new in escapes:
            if old in sanitized:
                sanitized = sanitized.replace(old, new)
                modifications.append(f"Escaped {repr(old)}")
        
        return sanitized
    
    def _sanitize_for_url(self, text: str, modifications: List[str]) -> str:
        """Sanitize for URL context"""
        sanitized = urllib.parse.quote(text, safe='')
        
        if sanitized != text:
            modifications.append("URL encoded special characters")
        
        return sanitized
    
    def get_info(self) -> Dict:
        """Get control information"""
        return {
            "name": "Output Sanitizer",
            "description": "Context-aware sanitization of AI output",
            "category": "Output Security",
            "contexts": ["html", "sql", "shell", "javascript", "url", "text"]
        }
