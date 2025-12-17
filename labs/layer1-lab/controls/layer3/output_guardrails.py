"""
AISTM Layer 3 Control: Output Guardrails

Detects dangerous patterns in AI output that could be exploited.
Essential for preventing indirect injection and output-based attacks.

Key Features:
- SQL injection detection in output
- XSS/HTML injection detection
- Command injection detection
- Path traversal detection
- Sensitive data leakage detection

Reference: AISTM Layer 3 Testing Guide - Output Guardrails section
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class GuardrailResult:
    """Result from output guardrail analysis"""
    has_violations: bool
    risk_level: str  # critical, high, medium, low, none
    violation_types: List[str] = field(default_factory=list)
    matched_patterns: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    recommendation: str = ""


class OutputGuardrails:
    """
    Detects dangerous patterns in AI output.
    
    AI output can contain injection payloads that exploit downstream systems.
    This control scans output for common attack patterns.
    """
    
    # SQL injection patterns
    SQL_PATTERNS = [
        r"(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)\s+",
        r"(?:--|#|/\*)",
        r"(?:OR|AND)\s+\d+\s*=\s*\d+",
        r"(?:OR|AND)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",
        r";\s*(?:DROP|DELETE|UPDATE|INSERT)",
        r"EXEC\s*\(",
        r"xp_cmdshell",
        r"INTO\s+OUTFILE",
        r"LOAD_FILE\s*\(",
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<script[^>]*>",
        r"javascript:",
        r"on\w+\s*=",
        r"<\s*img[^>]+onerror",
        r"<\s*svg[^>]+onload",
        r"<\s*iframe",
        r"<\s*object",
        r"<\s*embed",
        r"expression\s*\(",
        r"url\s*\([^)]*javascript",
    ]
    
    # Command injection patterns
    COMMAND_PATTERNS = [
        r";\s*(?:ls|cat|rm|wget|curl|bash|sh|python|perl|ruby|nc|netcat)",
        r"\|\s*(?:ls|cat|rm|wget|curl|bash|sh)",
        r"\$\([^)]+\)",
        r"`[^`]+`",
        r"&&\s*(?:ls|cat|rm|wget|curl)",
        r"\|\|\s*(?:ls|cat|rm|wget|curl)",
        r">\s*/(?:etc|var|tmp)",
    ]
    
    # Path traversal patterns
    PATH_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e[%/\\]",
        r"/etc/passwd",
        r"/etc/shadow",
        r"C:\\Windows",
        r"\\\\[^\\]+\\",
    ]
    
    def __init__(self):
        """Initialize the output guardrails"""
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns"""
        self.sql_regex = [re.compile(p, re.IGNORECASE) for p in self.SQL_PATTERNS]
        self.xss_regex = [re.compile(p, re.IGNORECASE) for p in self.XSS_PATTERNS]
        self.command_regex = [re.compile(p, re.IGNORECASE) for p in self.COMMAND_PATTERNS]
        self.path_regex = [re.compile(p, re.IGNORECASE) for p in self.PATH_PATTERNS]
    
    def analyze(self, output: str) -> GuardrailResult:
        """
        Analyze AI output for dangerous patterns.
        
        Args:
            output: The AI-generated output to analyze
            
        Returns:
            GuardrailResult with detection details
        """
        findings = []
        violation_types = []
        matched_patterns = []
        
        # Check SQL injection
        sql_matches = self._check_patterns(output, self.sql_regex, "SQL")
        if sql_matches:
            violation_types.append("sql_injection")
            matched_patterns.extend(sql_matches)
            findings.append(f"Detected {len(sql_matches)} SQL injection pattern(s)")
        
        # Check XSS
        xss_matches = self._check_patterns(output, self.xss_regex, "XSS")
        if xss_matches:
            violation_types.append("xss_injection")
            matched_patterns.extend(xss_matches)
            findings.append(f"Detected {len(xss_matches)} XSS pattern(s)")
        
        # Check command injection
        cmd_matches = self._check_patterns(output, self.command_regex, "Command")
        if cmd_matches:
            violation_types.append("command_injection")
            matched_patterns.extend(cmd_matches)
            findings.append(f"Detected {len(cmd_matches)} command injection pattern(s)")
        
        # Check path traversal
        path_matches = self._check_patterns(output, self.path_regex, "Path")
        if path_matches:
            violation_types.append("path_traversal")
            matched_patterns.extend(path_matches)
            findings.append(f"Detected {len(path_matches)} path traversal pattern(s)")
        
        # Calculate risk level
        total_matches = len(matched_patterns)
        has_violations = total_matches > 0
        
        if total_matches == 0:
            risk_level = "none"
        elif total_matches == 1:
            risk_level = "low"
        elif total_matches <= 3:
            risk_level = "medium"
        elif total_matches <= 5:
            risk_level = "high"
        else:
            risk_level = "critical"
        
        # Critical types boost risk
        critical_types = ["sql_injection", "command_injection"]
        if any(vt in violation_types for vt in critical_types):
            if risk_level == "low":
                risk_level = "medium"
            elif risk_level == "medium":
                risk_level = "high"
        
        # Generate recommendation
        if risk_level == "critical":
            recommendation = "BLOCK: Critical injection patterns detected in output"
        elif risk_level == "high":
            recommendation = "FILTER: High-risk patterns detected, sanitize before use"
        elif risk_level == "medium":
            recommendation = "REVIEW: Suspicious patterns in output, verify before use"
        elif risk_level == "low":
            recommendation = "MONITOR: Minor patterns detected, may be false positive"
        else:
            recommendation = "ALLOW: No dangerous patterns detected"
            findings.append("Output passed guardrail checks")
        
        return GuardrailResult(
            has_violations=has_violations,
            risk_level=risk_level,
            violation_types=violation_types,
            matched_patterns=matched_patterns,
            findings=findings,
            recommendation=recommendation
        )
    
    def _check_patterns(self, text: str, patterns: List[re.Pattern], category: str) -> List[str]:
        """Check text against patterns"""
        matches = []
        for pattern in patterns:
            if pattern.search(text):
                matches.append(f"{category}: {pattern.pattern[:40]}...")
        return matches
    
    def get_info(self) -> Dict:
        """Get control information"""
        return {
            "name": "Output Guardrails",
            "description": "Detects dangerous patterns in AI output",
            "category": "Output Security",
            "detects": [
                "SQL injection",
                "XSS/HTML injection",
                "Command injection",
                "Path traversal"
            ]
        }
