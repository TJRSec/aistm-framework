"""
Injection Detector Control Module

This module implements heuristic and regex-based prompt injection detection.
It looks for common patterns that indicate attempts to manipulate AI behavior.

This represents the deterministic approach to prompt injection detection,
which is fast and has no false positives for exact matches, but is easily
bypassed through paraphrasing.
"""

import re
import base64
import codecs
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class InjectionAnalysisResult:
    """Result of injection detection analysis"""
    original: str
    is_suspicious: bool
    confidence: float  # 0.0 to 1.0
    risk_level: str  # "low", "medium", "high", "critical"
    findings: list = field(default_factory=list)
    matched_patterns: list = field(default_factory=list)
    decoded_content: Optional[str] = None
    recommendation: str = ""


class InjectionDetector:
    """
    Heuristic and regex-based prompt injection detector.
    
    This control implements pattern matching for known prompt injection
    techniques. It's fast and deterministic but has fundamental limitations:
    
    - Only catches known patterns
    - Easily bypassed through paraphrasing
    - Cannot understand semantic intent
    
    Think of this as a "first line of defense" that catches obvious attacks
    but should never be the only protection.
    """
    
    # Pattern categories with risk levels
    INJECTION_PATTERNS = {
        "critical": [
            # Direct instruction override
            (r'\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|any)\b.{0,30}\b(instructions?|rules?|guidelines?|prompts?|commands?)\b', 
             "Direct instruction override attempt"),
            (r'\b(new|updated?|different|changed?)\b.{0,20}\b(instructions?|rules?|guidelines?|persona|role|identity)\b',
             "Instruction replacement attempt"),
            (r'\bsystem\s*prompt\b',
             "System prompt reference"),
            (r'\b(reveal|show|display|print|output|tell me)\b.{0,30}\b(system|original|initial|hidden|secret)\b.{0,20}\b(prompt|instructions?|rules?)\b',
             "System prompt extraction attempt"),
            # SQL Injection - Critical
            (r"['\"]?\s*;\s*(DROP|DELETE|TRUNCATE|ALTER|UPDATE|INSERT)\s+",
             "SQL destructive command injection"),
            (r"EXEC\s+(xp_|sp_)",
             "SQL Server stored procedure execution"),
            # Command Injection - Critical
            (r"[;|`]\s*(rm|del|format|shutdown|reboot)\s+",
             "Dangerous command injection"),
        ],
        "high": [
            # Role/persona manipulation
            (r'\b(you are now|act as|pretend to be|roleplay as|imagine you\'?re|behave as)\b',
             "Role/persona manipulation"),
            (r'\b(jailbreak|dan|do anything now|developer mode|god mode)\b',
             "Known jailbreak keyword"),
            (r'\b(no restrictions?|no limits?|no rules?|unlimited|unrestricted)\b',
             "Restriction removal request"),
            # Context manipulation
            (r'\b(in this context|for this conversation|from now on|going forward)\b.{0,30}\b(ignore|forget|disregard)\b',
             "Context boundary manipulation"),
            # SQL Injection - High
            (r"['\"]?\s*OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
             "SQL OR bypass (tautology)"),
            (r"UNION\s+(ALL\s+)?SELECT",
             "SQL UNION attack"),
            (r"--\s*$|#\s*$",
             "SQL comment terminator"),
            # XSS - High
            (r"<script[^>]*>",
             "XSS script tag injection"),
            (r"javascript\s*:",
             "JavaScript protocol injection"),
            (r"on(error|load|click|mouse|focus|blur)\s*=",
             "XSS event handler injection"),
            # Command Injection - High
            (r"[;|&`]\s*(cat|type|more|less|head|tail)\s+.*(passwd|shadow|etc)",
             "System file access attempt"),
            (r"\$\([^)]+\)|\$\{[^}]+\}",
             "Command substitution"),
        ],
        "medium": [
            # Indirect attempts
            (r'\b(hypothetically|theoretically|in theory|what if|suppose)\b.{0,40}\b(no rules?|no restrictions?|could you)\b',
             "Hypothetical framing for restriction bypass"),
            (r'\b(educational|research|academic|learning)\s+(purposes?|reasons?)\b',
             "Educational framing (potential pretext)"),
            (r'\bfor a (story|novel|book|script|movie|game)\b',
             "Fiction framing"),
            # Output manipulation
            (r'\b(respond|reply|answer|output)\b.{0,20}\b(only|just|exactly)\b.{0,20}\b(with|using|in)\b',
             "Output format manipulation"),
            # XSS - Medium
            (r"<(iframe|embed|object|form|input)[^>]*>",
             "Potentially dangerous HTML tag"),
            (r"<img[^>]+onerror",
             "Image error handler (XSS)"),
            (r"<svg[^>]+onload",
             "SVG onload handler (XSS)"),
            # SQL Injection - Medium
            (r"'\s*(AND|OR)\s+",
             "SQL boolean condition"),
            (r"(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\s+",
             "SQL keyword (context dependent)"),
        ],
        "low": [
            # Potentially suspicious but often legitimate
            (r'\bprompt\b',
             "Prompt keyword (may be legitimate)"),
            (r'\b(hack|exploit|bypass|circumvent)\b',
             "Security-related keyword"),
            (r'\b(injection|inject)\b',
             "Injection keyword"),
            # General code patterns (low risk - often legitimate)
            (r"<[a-zA-Z][^>]*>",
             "HTML tag detected"),
            (r"[;|&]",
             "Command separator character"),
        ]
    }
    
    # Patterns that suggest encoded content
    ENCODING_PATTERNS = {
        "base64": (r'[A-Za-z0-9+/]{20,}={0,2}', "Potential Base64 encoded content"),
        "hex": (r'(?:0x)?[0-9A-Fa-f]{20,}', "Potential hex encoded content"),
        "hex_spaces": (r'(?:[0-9A-Fa-f]{2}\s+){6,}', "Space-separated hex bytes"),
        "url": (r'%[0-9A-Fa-f]{2}(?:%[0-9A-Fa-f]{2}){5,}', "URL encoded content"),
        "unicode_escape": (r'(?:\\u[0-9A-Fa-f]{4}){4,}', "Unicode escape sequences"),
    }
    
    # Leetspeak substitution patterns (text that looks like instructions using l33t)
    LEETSPEAK_MAPPINGS = {
        'a': ['4', '@', '^'],
        'e': ['3'],
        'i': ['1', '!', '|'],
        'o': ['0'],
        's': ['5', '$'],
        't': ['7', '+'],
        'g': ['9'],
        'b': ['8'],
        'l': ['1', '|'],
    }
    
    # ROT13 encoded suspicious words (pre-computed for detection)
    # "ignore" = "vtaber", "system" = "flfgrz", "prompt" = "cebzcg"
    # "forget" = "sbetrg", "bypass" = "olcnff", "hack" = "unpx"
    ROT13_SUSPICIOUS_ENCODED = [
        'vtaber',    # ignore
        'sbetrg',    # forget
        'flfgrz',    # system
        'cebzcg',    # prompt
        'olcnff',    # bypass
        'unpx',      # hack
        'vawrpg',    # inject
        'bireevqr',  # override
        'qvfertneq', # disregard
        'vafgehpgvbaf', # instructions
        'wnvyoernx', # jailbreak
    ]
    
    # Structural patterns that might hide injection
    STRUCTURAL_PATTERNS = [
        # Code block obfuscation
        (r'```[\s\S]*?(ignore|forget|disregard|override|system\s*prompt)[\s\S]*?```', 
         "Injection hidden in code block"),
        
        # JSON structure obfuscation
        (r'\{[\s\S]*?"(ignore|override|forget|instructions?|system)"[\s\S]*?\}', 
         "Injection hidden in JSON"),
        
        # XML/HTML tag obfuscation
        (r'<[^>]*>(ignore|forget|override|system)', 
         "Injection hidden in XML/HTML tag"),
        (r'<!\[CDATA\[[\s\S]*?(ignore|forget|system)[\s\S]*?\]\]>', 
         "Injection hidden in CDATA section"),
        
        # Markdown table obfuscation (each word in different cell)
        (r'\|[^|]*ignore[^|]*\|[^|]*previous[^|]*\|', 
         "Injection fragmented across table cells"),
        (r'\|[^|]*system[^|]*\|[^|]*prompt[^|]*\|', 
         "System prompt reference in table"),
        
        # Comment-based hiding
        (r'<!--[\s\S]*?(ignore|system|prompt)[\s\S]*?-->', 
         "Injection hidden in HTML comment"),
        (r'#.*?(ignore|forget|system).*?$', 
         "Injection hidden in comment"),
        
        # Whitespace/invisible character padding
        (r'i\s+g\s+n\s+o\s+r\s+e', 
         "Spaced-out 'ignore' detected"),
        (r's\s+y\s+s\s+t\s+e\s+m', 
         "Spaced-out 'system' detected"),
        
        # Nested structure abuse
        (r'\[\[[\s\S]*?(ignore|system|prompt)[\s\S]*?\]\]', 
         "Injection in wiki-style brackets"),
        
        # Quote manipulation
        (r'["""][\s\S]*?(ignore|forget|override)[\s\S]*?["""]', 
         "Injection in smart quotes"),
    ]
    
    def __init__(self, 
                 check_encoded: bool = True,
                 decode_and_scan: bool = True,
                 check_leetspeak: bool = True,
                 check_rot13: bool = True,
                 min_confidence_to_flag: float = 0.3):
        """
        Initialize the injection detector.
        
        Args:
            check_encoded: Whether to look for encoded content
            decode_and_scan: Whether to decode Base64 and scan the decoded content
            check_leetspeak: Whether to detect leetspeak obfuscation
            check_rot13: Whether to detect ROT13 encoded content
            min_confidence_to_flag: Minimum confidence score to consider suspicious
        """
        self.check_encoded = check_encoded
        self.decode_and_scan = decode_and_scan
        self.check_leetspeak = check_leetspeak
        self.check_rot13 = check_rot13
        self.min_confidence = min_confidence_to_flag
        
        # Compile all patterns for efficiency
        self.compiled_patterns = {}
        for level, patterns in self.INJECTION_PATTERNS.items():
            self.compiled_patterns[level] = [
                (re.compile(pattern, re.IGNORECASE), desc) 
                for pattern, desc in patterns
            ]
        
        self.compiled_encoding = {
            name: (re.compile(pattern), desc)
            for name, (pattern, desc) in self.ENCODING_PATTERNS.items()
        }
        
        self.compiled_structural = [
            (re.compile(pattern, re.IGNORECASE | re.DOTALL), desc)
            for pattern, desc in self.STRUCTURAL_PATTERNS
        ]
    
    def analyze(self, text: str) -> InjectionAnalysisResult:
        """
        Analyze text for prompt injection patterns.
        
        This performs multi-level pattern matching and returns detailed
        findings about what was detected.
        
        Args:
            text: The input text to analyze
            
        Returns:
            InjectionAnalysisResult with detailed findings
        """
        result = InjectionAnalysisResult(
            original=text,
            is_suspicious=False,
            confidence=0.0,
            risk_level="low"
        )
        
        findings = []
        matched_patterns = []
        
        # Track matches by risk level for scoring
        matches_by_level = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        # Check injection patterns
        for level, patterns in self.compiled_patterns.items():
            for pattern, description in patterns:
                matches = pattern.findall(text)
                if matches:
                    matches_by_level[level] += len(matches)
                    matched_patterns.append({
                        "level": level,
                        "description": description,
                        "pattern": pattern.pattern,
                        "matches": matches[:5]  # Limit stored matches
                    })
                    findings.append(f"[{level.upper()}] {description}")
        
        # Check structural patterns
        for pattern, description in self.compiled_structural:
            if pattern.search(text):
                matches_by_level["high"] += 1
                matched_patterns.append({
                    "level": "high",
                    "description": description,
                    "pattern": "structural"
                })
                findings.append(f"[STRUCTURAL] {description}")
        
        # Check for encoded content
        decoded_content = None
        if self.check_encoded:
            for enc_type, (pattern, description) in self.compiled_encoding.items():
                matches = pattern.findall(text)
                for match in matches:
                    findings.append(f"[ENCODING] {description}: {match[:30]}...")
                    
                    # Try to decode Base64 and scan
                    if self.decode_and_scan and enc_type == "base64":
                        try:
                            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                            if decoded and len(decoded) > 5:
                                decoded_content = decoded
                                # Recursively check decoded content
                                decoded_result = self._quick_scan(decoded)
                                if decoded_result:
                                    matches_by_level["critical"] += 1
                                    findings.append(f"[DECODED] Found suspicious content in Base64: {decoded_result}")
                        except:
                            pass
        
        # Check for ROT13 encoded content
        if self.check_rot13:
            rot13_findings = self._check_rot13_content(text)
            for finding in rot13_findings:
                matches_by_level["high"] += 1
                findings.append(f"[ROT13] {finding}")
                matched_patterns.append({
                    "level": "high",
                    "description": finding,
                    "pattern": "rot13_encoding"
                })
        
        # Check for Hex encoded content
        if self.check_encoded:
            hex_findings = self._check_hex_content(text)
            for finding in hex_findings:
                matches_by_level["high"] += 1
                findings.append(f"[HEX] {finding}")
                matched_patterns.append({
                    "level": "high", 
                    "description": finding,
                    "pattern": "hex_encoding"
                })
        
        # Check for Leetspeak obfuscation
        if self.check_leetspeak:
            leet_findings = self._check_leetspeak(text)
            for finding in leet_findings:
                matches_by_level["high"] += 1
                findings.append(f"[LEETSPEAK] {finding}")
                matched_patterns.append({
                    "level": "high",
                    "description": finding,
                    "pattern": "leetspeak"
                })
        
        # Calculate confidence score
        # Weight: critical=1.0, high=0.7, medium=0.4, low=0.1
        weighted_score = (
            matches_by_level["critical"] * 1.0 +
            matches_by_level["high"] * 0.7 +
            matches_by_level["medium"] * 0.4 +
            matches_by_level["low"] * 0.1
        )
        
        # Normalize to 0-1 range (cap at 1.0)
        confidence = min(weighted_score / 2.0, 1.0)
        
        # Determine risk level
        if matches_by_level["critical"] > 0:
            risk_level = "critical"
        elif matches_by_level["high"] > 0:
            risk_level = "high"
        elif matches_by_level["medium"] > 0:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        # Generate recommendation
        if confidence >= 0.8:
            recommendation = "BLOCK: High confidence prompt injection attempt"
        elif confidence >= 0.5:
            recommendation = "REVIEW: Likely prompt injection attempt"
        elif confidence >= 0.3:
            recommendation = "MONITOR: Suspicious patterns detected"
        else:
            recommendation = "ALLOW: No significant patterns detected"
        
        result.is_suspicious = confidence >= self.min_confidence
        result.confidence = confidence
        result.risk_level = risk_level
        result.findings = findings
        result.matched_patterns = matched_patterns
        result.decoded_content = decoded_content
        result.recommendation = recommendation
        
        return result
    
    def _quick_scan(self, text: str) -> Optional[str]:
        """Quick scan for critical patterns only (used for decoded content)"""
        for pattern, desc in self.compiled_patterns["critical"]:
            if pattern.search(text):
                return desc
        return None
    
    def _decode_rot13(self, text: str) -> str:
        """Decode ROT13 encoded text"""
        return codecs.decode(text, 'rot_13')
    
    def _check_rot13_content(self, text: str) -> List[str]:
        """
        Check if text contains ROT13 encoded suspicious words.
        
        ROT13 is a simple letter substitution cipher that replaces a letter
        with the 13th letter after it in the alphabet. Attackers use it to
        hide keywords from pattern matching.
        """
        findings = []
        text_lower = text.lower()
        
        for encoded_word in self.ROT13_SUSPICIOUS_ENCODED:
            if encoded_word in text_lower:
                decoded = self._decode_rot13(encoded_word)
                findings.append(f"ROT13 encoded word '{encoded_word}' decodes to '{decoded}'")
        
        # Also try to decode the entire text and scan it
        try:
            decoded_text = self._decode_rot13(text)
            result = self._quick_scan(decoded_text)
            if result:
                findings.append(f"ROT13 decoded content contains: {result}")
        except:
            pass
        
        return findings
    
    def _decode_hex(self, hex_string: str) -> Optional[str]:
        """Attempt to decode hex string to ASCII"""
        try:
            # Remove common prefixes and spaces
            clean = hex_string.replace('0x', '').replace(' ', '').replace('\n', '')
            if len(clean) % 2 == 0:
                decoded = bytes.fromhex(clean).decode('utf-8', errors='ignore')
                if decoded and len(decoded) > 3:
                    return decoded
        except:
            pass
        return None
    
    def _check_hex_content(self, text: str) -> List[str]:
        """Check for hex encoded content that might contain injections"""
        findings = []
        
        # Pattern for hex strings
        hex_pattern = re.compile(r'(?:0x)?([0-9A-Fa-f]{2}[\s]*){8,}', re.IGNORECASE)
        matches = hex_pattern.findall(text)
        
        # Try to find longer hex sequences
        long_hex = re.findall(r'[0-9A-Fa-f]{16,}', text)
        for hex_str in long_hex:
            decoded = self._decode_hex(hex_str)
            if decoded:
                result = self._quick_scan(decoded)
                if result:
                    findings.append(f"Hex decoded content contains: {result} (decoded: '{decoded[:50]}...')")
        
        return findings
    
    def _normalize_leetspeak(self, text: str) -> str:
        """
        Convert leetspeak text back to normal letters.
        
        Leetspeak uses character substitutions like:
        - 1gn0r3 = ignore
        - 5y5t3m = system
        - f0rg3t = forget
        """
        result = text.lower()
        
        # Reverse mapping: leet char -> normal char
        leet_to_normal = {
            '4': 'a', '@': 'a', '^': 'a',
            '3': 'e',
            '1': 'i', '!': 'i', '|': 'l',  # | can be i or l
            '0': 'o',
            '5': 's', '$': 's',
            '7': 't', '+': 't',
            '9': 'g',
            '8': 'b',
        }
        
        for leet_char, normal_char in leet_to_normal.items():
            result = result.replace(leet_char, normal_char)
        
        return result
    
    def _check_leetspeak(self, text: str) -> List[str]:
        """
        Check for leetspeak obfuscated injection attempts.
        
        Common patterns:
        - 1gn0r3 pr3v10us 1nstruct10ns (ignore previous instructions)
        - 5y5t3m pr0mpt (system prompt)
        - f0rg3t 4ll rul35 (forget all rules)
        """
        findings = []
        
        # Check if text contains common leet characters
        leet_chars = set('0134578@$!|+^')
        text_chars = set(text)
        
        if len(leet_chars & text_chars) >= 2:  # At least 2 leet chars
            normalized = self._normalize_leetspeak(text)
            
            # Check normalized text against critical patterns
            for pattern, desc in self.compiled_patterns["critical"]:
                if pattern.search(normalized):
                    findings.append(f"Leetspeak obfuscation detected: {desc}")
                    break
            
            # Check for specific keywords
            suspicious_words = ['ignore', 'forget', 'system', 'prompt', 'bypass', 
                              'hack', 'inject', 'override', 'jailbreak']
            for word in suspicious_words:
                if word in normalized and word not in text.lower():
                    findings.append(f"Leetspeak for '{word}' detected")
        
        return findings
    
    def get_info(self) -> dict:
        """Return information about this control for the UI"""
        total_patterns = sum(len(p) for p in self.INJECTION_PATTERNS.values())
        
        return {
            "name": "Regex Injection Detection",
            "description": "Pattern-based detection of known prompt injection techniques with encoding detection",
            "category": "Heuristic Detection",
            "settings": {
                "total_patterns": total_patterns,
                "check_encoded": self.check_encoded,
                "decode_and_scan": self.decode_and_scan,
                "check_leetspeak": self.check_leetspeak,
                "check_rot13": self.check_rot13,
                "min_confidence": self.min_confidence
            },
            "detects": [
                "Direct instruction override phrases",
                "Role/persona manipulation attempts",
                "Known jailbreak keywords (DAN, etc.)",
                "Hypothetical/educational framing",
                "Base64-encoded payloads",
                "ROT13 encoded keywords and content",
                "Hex encoded payloads",
                "Leetspeak obfuscation (1gn0r3, 5y5t3m, etc.)",
                "Structural obfuscation (code blocks, JSON, XML)",
                "XSS attacks (script tags, event handlers, javascript: URLs)",
                "SQL injection (UNION, OR bypass, DROP, command execution)",
                "Command injection (shell commands, substitution)"
            ],
            "bypasses": [
                "Synonym substitution (paraphrasing)",
                "Novel phrasings not in pattern database",
                "Semantic manipulation",
                "Multi-turn context building",
                "Non-English languages",
                "Creative encoding schemes not in database"
            ]
        }
