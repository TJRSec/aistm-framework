"""
AISTM Layer 2 Control: System Prompt Protection

Detects attempts to extract, override, or manipulate system prompts.
Essential for protecting AI model instructions from adversarial users.

Key Features:
- Prompt extraction detection (direct and indirect)
- Role override detection (attempts to change AI behavior)
- Instruction manipulation detection
- Multi-language support

Reference: AISTM Layer 2 Testing Guide - System Prompt Protection section
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class PromptProtectionResult:
    """Result from system prompt protection analysis"""
    is_suspicious: bool
    risk_level: str  # critical, high, medium, low, none
    confidence: float
    attack_types: List[str] = field(default_factory=list)
    matched_patterns: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    recommendation: str = ""


class SystemPromptProtection:
    """
    Detects attempts to extract, override, or manipulate system prompts.
    
    This control implements defense against three main attack vectors:
    1. Prompt Extraction - Attempts to reveal system instructions
    2. Role Override - Attempts to change the AI's assigned role
    3. Instruction Manipulation - Attempts to modify behavior rules
    """
    
    # Prompt extraction patterns
    EXTRACTION_PATTERNS = [
        # Direct extraction
        r"(?:show|reveal|display|print|output|tell me|what is|what are|give me|share).*(?:system prompt|instructions|rules|guidelines|directives|configuration)",
        r"(?:system prompt|instructions|rules).*(?:show|reveal|display|print|tell)",
        r"repeat.*(?:instructions|prompt|rules|guidelines)",
        r"(?:copy|paste|dump).*(?:system|prompt|instructions)",
        r"what.*(?:told|instructed|programmed|configured).*(?:to do|to say|to be)",
        
        # Indirect extraction
        r"(?:pretend|imagine|suppose).*(?:no rules|no restrictions|unrestricted)",
        r"(?:hypothetically|theoretically).*(?:reveal|show|tell).*(?:prompt|instructions)",
        r"if.*(?:asked|told).*(?:reveal|show).*(?:prompt|instructions)",
        r"(?:start|begin).*(?:response|answer).*with.*(?:system|prompt|instructions)",
        
        # Meta-queries
        r"how.*(?:were you|are you).*(?:configured|programmed|instructed)",
        r"what.*(?:boundaries|limitations|restrictions).*(?:have|do you have)",
        r"describe.*(?:your|the).*(?:system|configuration|setup)",
        
        # Debug/developer mode
        r"(?:enter|enable|activate).*(?:debug|developer|admin|maintenance).*mode",
        r"(?:debug|developer|admin).*(?:mode|access|commands)",
        r"show.*(?:debug|developer|internal).*(?:info|information|data)",
    ]
    
    # Role override patterns
    OVERRIDE_PATTERNS = [
        # Direct role change
        r"you are (?:now|no longer|not)",
        r"from now on.*(?:you|your role)",
        r"(?:forget|ignore|disregard).*(?:previous|prior|earlier).*(?:instructions|role|persona)",
        r"(?:new|different|changed).*(?:instructions|role|persona)",
        r"(?:act as|pretend to be|roleplay as|become).*(?:different|new|another)",
        
        # Permission escalation
        r"(?:override|bypass|disable|ignore).*(?:safety|restrictions|rules|guidelines)",
        r"(?:you have|i give you|granted).*(?:permission|authority|ability).*(?:to|for)",
        r"(?:remove|lift|disable).*(?:limitations|restrictions|boundaries)",
        
        # Identity manipulation
        r"you (?:don't|do not) have (?:to follow|rules|restrictions)",
        r"(?:break|escape).*(?:character|role|persona)",
        r"(?:real|true|actual).*(?:self|personality|capabilities)",
    ]
    
    # Instruction manipulation patterns
    MANIPULATION_PATTERNS = [
        # Rule modification
        r"(?:change|modify|update|alter).*(?:your|the).*(?:rules|behavior|responses)",
        r"(?:add|append|include).*(?:new|additional).*(?:rules|instructions|behaviors)",
        r"(?:except|unless|but).*(?:when|if).*(?:i|user).*(?:say|ask|tell)",
        
        # Priority manipulation
        r"(?:prioritize|first priority|most important|above all)",
        r"(?:ignore|disregard|forget).*(?:other|all|previous).*(?:rules|instructions)",
        r"(?:this|my).*(?:instruction|command|request).*(?:override|supercede|replace)",
        
        # Context injection
        r"(?:system|admin|developer).*(?:note|message|instruction)",
        r"\[.*(?:system|admin|developer).*\]",
        r"<(?:system|admin|developer)>",
        
        # Delimiter manipulation
        r"(?:end|close|stop).*(?:of|the).*(?:prompt|instructions|context)",
        r"---.*(?:new|start|begin).*(?:instructions|context)",
        r"```.*(?:system|instructions|prompt)",
    ]
    
    def __init__(self, 
                 extraction_sensitivity: float = 0.7,
                 override_sensitivity: float = 0.8,
                 manipulation_sensitivity: float = 0.7):
        """
        Initialize the system prompt protection control.
        
        Args:
            extraction_sensitivity: Threshold for extraction detection (0-1)
            override_sensitivity: Threshold for override detection (0-1)
            manipulation_sensitivity: Threshold for manipulation detection (0-1)
        """
        self.extraction_sensitivity = extraction_sensitivity
        self.override_sensitivity = override_sensitivity
        self.manipulation_sensitivity = manipulation_sensitivity
        
        # Compile patterns for efficiency
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for efficient matching"""
        self.extraction_regex = [re.compile(p, re.IGNORECASE) for p in self.EXTRACTION_PATTERNS]
        self.override_regex = [re.compile(p, re.IGNORECASE) for p in self.OVERRIDE_PATTERNS]
        self.manipulation_regex = [re.compile(p, re.IGNORECASE) for p in self.MANIPULATION_PATTERNS]
    
    def analyze(self, text: str) -> PromptProtectionResult:
        """
        Analyze text for system prompt attack patterns.
        
        Args:
            text: The input text to analyze
            
        Returns:
            PromptProtectionResult with detection details
        """
        findings = []
        attack_types = []
        matched_patterns = []
        
        # Check extraction patterns
        extraction_matches = self._check_patterns(text, self.extraction_regex, "extraction")
        if extraction_matches:
            attack_types.append("prompt_extraction")
            matched_patterns.extend(extraction_matches)
            findings.append(f"Detected {len(extraction_matches)} prompt extraction pattern(s)")
        
        # Check override patterns
        override_matches = self._check_patterns(text, self.override_regex, "override")
        if override_matches:
            attack_types.append("role_override")
            matched_patterns.extend(override_matches)
            findings.append(f"Detected {len(override_matches)} role override pattern(s)")
        
        # Check manipulation patterns
        manipulation_matches = self._check_patterns(text, self.manipulation_regex, "manipulation")
        if manipulation_matches:
            attack_types.append("instruction_manipulation")
            matched_patterns.extend(manipulation_matches)
            findings.append(f"Detected {len(manipulation_matches)} instruction manipulation pattern(s)")
        
        # Calculate risk level and confidence
        total_matches = len(matched_patterns)
        is_suspicious = total_matches > 0
        
        if total_matches == 0:
            risk_level = "none"
            confidence = 0.0
        elif total_matches == 1:
            risk_level = "low"
            confidence = 0.4
        elif total_matches == 2:
            risk_level = "medium"
            confidence = 0.6
        elif total_matches <= 4:
            risk_level = "high"
            confidence = 0.8
        else:
            risk_level = "critical"
            confidence = 0.95
        
        # Boost confidence for certain attack combinations
        if "prompt_extraction" in attack_types and "role_override" in attack_types:
            confidence = min(1.0, confidence + 0.15)
            risk_level = "critical"
        
        # Generate recommendation
        if risk_level == "critical":
            recommendation = "BLOCK: High-confidence prompt manipulation attempt detected"
        elif risk_level == "high":
            recommendation = "BLOCK: Multiple attack patterns detected"
        elif risk_level == "medium":
            recommendation = "REVIEW: Suspicious patterns detected, may require human review"
        elif risk_level == "low":
            recommendation = "MONITOR: Minor suspicious patterns, proceed with caution"
        else:
            recommendation = "ALLOW: No suspicious patterns detected"
            findings.append("Input passed system prompt protection checks")
        
        return PromptProtectionResult(
            is_suspicious=is_suspicious,
            risk_level=risk_level,
            confidence=confidence,
            attack_types=attack_types,
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
    
    def get_info(self) -> Dict:
        """Get information about this control"""
        return {
            "name": "System Prompt Protection",
            "description": "Detects attempts to extract, override, or manipulate system prompts",
            "category": "AI Model Security",
            "detects": [
                "Prompt extraction attempts",
                "Role override attempts",
                "Instruction manipulation",
                "Debug/developer mode requests",
                "Permission escalation"
            ],
            "pattern_counts": {
                "extraction": len(self.EXTRACTION_PATTERNS),
                "override": len(self.OVERRIDE_PATTERNS),
                "manipulation": len(self.MANIPULATION_PATTERNS)
            }
        }
