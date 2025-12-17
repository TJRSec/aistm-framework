"""
AISTM Layer 2 Control: Jailbreak Detector

Detects common jailbreak techniques used to bypass AI safety measures.
Essential for preventing unauthorized behavior modification.

Key Features:
- DAN (Do Anything Now) prompt detection
- Roleplay attack detection
- Hypothetical scenario bypasses
- Encoding bypass detection (Base64, ROT13)
- Multi-turn manipulation detection

Reference: AISTM Layer 2 Testing Guide - Jailbreak Detection section
"""

import re
import base64
import codecs
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class JailbreakResult:
    """Result from jailbreak detection analysis"""
    is_jailbreak: bool
    risk_level: str  # critical, high, medium, low, none
    confidence: float
    jailbreak_types: List[str] = field(default_factory=list)
    matched_patterns: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    recommendation: str = ""


class JailbreakDetector:
    """
    Detects common jailbreak techniques targeting AI models.
    
    Jailbreak attempts try to bypass the AI's safety guidelines through
    various manipulation techniques. This detector identifies:
    1. DAN-style prompts
    2. Roleplay attacks
    3. Hypothetical scenarios
    4. Encoding bypasses
    5. Multi-turn manipulation
    """
    
    # DAN (Do Anything Now) patterns
    DAN_PATTERNS = [
        r"\bDAN\b",
        r"do anything now",
        r"(?:no|without|ignore).*(?:rules|restrictions|guidelines|ethics|morals)",
        r"(?:jailbreak|jailbroken|unlocked).*(?:mode|version|AI)",
        r"(?:unrestricted|uncensored|unfiltered).*(?:mode|AI|response)",
        r"(?:evil|dark|shadow).*(?:mode|version|AI)",
        r"(?:opposite|reverse).*(?:mode|day|personality)",
        r"anti-?(?:AI|safety|ethics)",
        r"(?:bypass|disable|remove).*(?:safety|filters|moderation)",
        r"(?:developer|debug|admin|maintenance|service).*mode",
        r"(?:maximum|god|sudo|root).*mode",
    ]
    
    # Roleplay attack patterns
    ROLEPLAY_PATTERNS = [
        r"(?:pretend|imagine|suppose|act as if|roleplay).*(?:you are|you're|you have)",
        r"(?:you are|you're).*(?:character|persona|entity).*(?:without|no).*(?:rules|restrictions)",
        r"(?:play|be|become|transform into).*(?:role|character).*(?:of|as)",
        r"(?:fictional|hypothetical|imaginary).*(?:scenario|world|universe)",
        r"in this (?:story|scenario|world|game|roleplay)",
        r"(?:write|create|generate).*(?:story|fiction|narrative).*(?:where|about)",
        r"(?:character|persona|entity) (?:named|called)",
        r"(?:speaking|talking|responding) as",
    ]
    
    # Hypothetical bypass patterns
    HYPOTHETICAL_PATTERNS = [
        r"(?:hypothetically|theoretically|in theory)",
        r"(?:what if|suppose|imagine|let's say)",
        r"(?:for|in).*(?:educational|research|academic).*(?:purposes|reasons)",
        r"(?:just|only).*(?:curious|wondering|asking)",
        r"(?:i'm|i am).*(?:writing|researching|studying)",
        r"(?:don't|do not).*(?:actually|really).*(?:do|follow|use)",
        r"(?:fiction|story|novel|book|movie|game)",
        r"(?:purely|strictly).*(?:academic|theoretical|hypothetical)",
    ]
    
    # Encoding bypass indicators
    ENCODING_PATTERNS = [
        r"(?:base64|rot13|hex|binary|morse|caesar|encoded)",
        r"(?:decode|decrypt|decipher|translate).*(?:this|following|message)",
        r"(?:follow|execute|do).*(?:encoded|encrypted|hidden).*(?:instructions|message)",
        r"[A-Za-z0-9+/]{20,}={0,2}",  # Base64-like strings
    ]
    
    # Multi-turn manipulation patterns
    MULTITURN_PATTERNS = [
        r"(?:remember|recall|earlier|before|previously).*(?:said|agreed|confirmed)",
        r"(?:you|we).*(?:agreed|established|confirmed|said)",
        r"(?:continue|keep|maintain).*(?:character|roleplay|persona|pretending)",
        r"(?:don't|do not).*(?:break|drop|stop).*(?:character|roleplay|persona)",
        r"(?:as we|as you).*(?:discussed|agreed|established)",
        r"(?:our|this).*(?:previous|earlier|ongoing).*(?:conversation|discussion)",
    ]
    
    def __init__(self):
        """Initialize the jailbreak detector"""
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for efficient matching"""
        self.dan_regex = [re.compile(p, re.IGNORECASE) for p in self.DAN_PATTERNS]
        self.roleplay_regex = [re.compile(p, re.IGNORECASE) for p in self.ROLEPLAY_PATTERNS]
        self.hypothetical_regex = [re.compile(p, re.IGNORECASE) for p in self.HYPOTHETICAL_PATTERNS]
        self.encoding_regex = [re.compile(p, re.IGNORECASE) for p in self.ENCODING_PATTERNS]
        self.multiturn_regex = [re.compile(p, re.IGNORECASE) for p in self.MULTITURN_PATTERNS]
    
    def analyze(self, text: str) -> JailbreakResult:
        """
        Analyze text for jailbreak patterns.
        
        Args:
            text: The input text to analyze
            
        Returns:
            JailbreakResult with detection details
        """
        findings = []
        jailbreak_types = []
        matched_patterns = []
        
        # Check for encoded content first
        decoded_content = self._decode_content(text)
        text_to_check = text + " " + decoded_content if decoded_content else text
        
        if decoded_content:
            findings.append("Detected encoded content, analyzing decoded version")
            jailbreak_types.append("encoding_bypass")
        
        # Check DAN patterns
        dan_matches = self._check_patterns(text_to_check, self.dan_regex, "DAN")
        if dan_matches:
            jailbreak_types.append("dan_prompt")
            matched_patterns.extend(dan_matches)
            findings.append(f"Detected {len(dan_matches)} DAN-style pattern(s)")
        
        # Check roleplay patterns
        roleplay_matches = self._check_patterns(text_to_check, self.roleplay_regex, "roleplay")
        if roleplay_matches:
            jailbreak_types.append("roleplay_attack")
            matched_patterns.extend(roleplay_matches)
            findings.append(f"Detected {len(roleplay_matches)} roleplay attack pattern(s)")
        
        # Check hypothetical patterns
        hypo_matches = self._check_patterns(text_to_check, self.hypothetical_regex, "hypothetical")
        if hypo_matches:
            jailbreak_types.append("hypothetical_bypass")
            matched_patterns.extend(hypo_matches)
            findings.append(f"Detected {len(hypo_matches)} hypothetical bypass pattern(s)")
        
        # Check encoding patterns
        encoding_matches = self._check_patterns(text, self.encoding_regex, "encoding")
        if encoding_matches and "encoding_bypass" not in jailbreak_types:
            jailbreak_types.append("encoding_bypass")
            matched_patterns.extend(encoding_matches)
            findings.append(f"Detected {len(encoding_matches)} encoding-related pattern(s)")
        
        # Check multi-turn patterns
        multiturn_matches = self._check_patterns(text_to_check, self.multiturn_regex, "multi-turn")
        if multiturn_matches:
            jailbreak_types.append("multi_turn_manipulation")
            matched_patterns.extend(multiturn_matches)
            findings.append(f"Detected {len(multiturn_matches)} multi-turn manipulation pattern(s)")
        
        # Calculate risk level and confidence
        total_matches = len(matched_patterns)
        is_jailbreak = total_matches > 0
        
        if total_matches == 0:
            risk_level = "none"
            confidence = 0.0
        elif total_matches == 1:
            risk_level = "low"
            confidence = 0.3
        elif total_matches == 2:
            risk_level = "medium"
            confidence = 0.5
        elif total_matches <= 4:
            risk_level = "high"
            confidence = 0.75
        else:
            risk_level = "critical"
            confidence = 0.9
        
        # Boost for DAN patterns (more dangerous)
        if "dan_prompt" in jailbreak_types:
            confidence = min(1.0, confidence + 0.2)
            if risk_level == "medium":
                risk_level = "high"
            elif risk_level == "high":
                risk_level = "critical"
        
        # Boost for combination attacks
        if len(jailbreak_types) >= 3:
            confidence = min(1.0, confidence + 0.15)
            risk_level = "critical"
        
        # Generate recommendation
        if risk_level == "critical":
            recommendation = "BLOCK: High-confidence jailbreak attempt detected"
        elif risk_level == "high":
            recommendation = "BLOCK: Multiple jailbreak patterns detected"
        elif risk_level == "medium":
            recommendation = "REVIEW: Suspicious patterns may indicate jailbreak attempt"
        elif risk_level == "low":
            recommendation = "MONITOR: Minor suspicious patterns detected"
        else:
            recommendation = "ALLOW: No jailbreak patterns detected"
            findings.append("Input passed jailbreak detection checks")
        
        return JailbreakResult(
            is_jailbreak=is_jailbreak,
            risk_level=risk_level,
            confidence=confidence,
            jailbreak_types=jailbreak_types,
            matched_patterns=matched_patterns,
            findings=findings,
            recommendation=recommendation
        )
    
    def _check_patterns(self, text: str, patterns: List[re.Pattern], category: str) -> List[str]:
        """Check text against a list of compiled patterns"""
        matches = []
        for pattern in patterns:
            if pattern.search(text):
                matches.append(f"{category}: {pattern.pattern[:50]}...")
        return matches
    
    def _decode_content(self, text: str) -> Optional[str]:
        """Try to decode potentially encoded content"""
        decoded_parts = []
        
        # Try Base64 decoding on potential Base64 strings
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        for match in base64_pattern.finditer(text):
            try:
                decoded = base64.b64decode(match.group()).decode('utf-8', errors='ignore')
                if decoded and len(decoded) > 5:
                    decoded_parts.append(decoded)
            except Exception:
                pass
        
        # Try ROT13 on the whole text
        try:
            rot13_decoded = codecs.decode(text, 'rot_13')
            # Only include if it looks different and contains common words
            common_words = ['ignore', 'forget', 'system', 'prompt', 'rules', 'instructions']
            if any(word in rot13_decoded.lower() for word in common_words):
                decoded_parts.append(rot13_decoded)
        except Exception:
            pass
        
        return " ".join(decoded_parts) if decoded_parts else None
    
    def get_info(self) -> Dict:
        """Get information about this control"""
        return {
            "name": "Jailbreak Detector",
            "description": "Detects common jailbreak techniques used to bypass AI safety measures",
            "category": "AI Model Security",
            "detects": [
                "DAN (Do Anything Now) prompts",
                "Roleplay attacks",
                "Hypothetical scenario bypasses",
                "Encoding bypasses (Base64, ROT13)",
                "Multi-turn manipulation"
            ],
            "pattern_counts": {
                "dan": len(self.DAN_PATTERNS),
                "roleplay": len(self.ROLEPLAY_PATTERNS),
                "hypothetical": len(self.HYPOTHETICAL_PATTERNS),
                "encoding": len(self.ENCODING_PATTERNS),
                "multiturn": len(self.MULTITURN_PATTERNS)
            }
        }
