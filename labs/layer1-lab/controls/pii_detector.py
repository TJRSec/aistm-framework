"""
PII Detection Control Module

This module detects and optionally redacts Personally Identifiable Information
before it reaches the AI model. This prevents:
- PII leakage through model logs
- Training data contamination
- Accidental disclosure in responses

Uses Microsoft Presidio when available, falls back to regex patterns.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

# Try to import Presidio
try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False


@dataclass
class PIIEntity:
    """A detected PII entity"""
    entity_type: str
    text: str
    start: int
    end: int
    confidence: float
    redacted_text: str = "[REDACTED]"


@dataclass
class PIIAnalysisResult:
    """Result of PII detection analysis"""
    original: str
    redacted: str
    was_modified: bool
    findings: list = field(default_factory=list)
    entities_found: List[PIIEntity] = field(default_factory=list)
    entity_counts: Dict[str, int] = field(default_factory=dict)
    detection_method: str = "regex"


class PIIDetector:
    """
    PII Detection and Redaction Control
    
    This control identifies sensitive personal information in user input
    before it reaches the AI model. At Layer 1, the goal is to prevent
    PII from entering the system at all.
    
    Detection methods:
    1. Microsoft Presidio (if available) - Uses NER and regex
    2. Fallback regex patterns - For common PII formats
    
    Supported entity types:
    - Credit card numbers
    - Social Security Numbers (US)
    - Phone numbers
    - Email addresses
    - IP addresses
    - Dates of birth
    - Names (Presidio only)
    - Addresses (Presidio only)
    """
    
    # Regex patterns for PII detection (used as fallback)
    PII_PATTERNS = {
        "CREDIT_CARD": [
            # Visa, Mastercard, Amex, Discover patterns
            (r'\b4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b', "Visa"),
            (r'\b5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b', "Mastercard"),
            (r'\b3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}\b', "Amex"),
            (r'\b6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b', "Discover"),
        ],
        "US_SSN": [
            (r'\b[0-9]{3}[-\s]?[0-9]{2}[-\s]?[0-9]{4}\b', "SSN format"),
        ],
        "PHONE_NUMBER": [
            # US phone formats
            (r'\b\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b', "US phone"),
            # International
            (r'\b\+[0-9]{1,3}[-.\s]?[0-9]{6,14}\b', "International phone"),
        ],
        "EMAIL_ADDRESS": [
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "Email"),
        ],
        "IP_ADDRESS": [
            # IPv4
            (r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', "IPv4"),
            # IPv6 (simplified)
            (r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b', "IPv6"),
        ],
        "DATE_OF_BIRTH": [
            # Common date formats that might be DOB
            (r'\b(?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12][0-9]|3[01])[-/](?:19|20)[0-9]{2}\b', "MM/DD/YYYY"),
            (r'\b(?:19|20)[0-9]{2}[-/](?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12][0-9]|3[01])\b', "YYYY/MM/DD"),
        ],
        "US_BANK_ACCOUNT": [
            # Bank routing + account pattern
            (r'\b[0-9]{9}\s*[0-9]{8,17}\b', "Routing + Account"),
        ],
        "PASSPORT": [
            # US passport
            (r'\b[0-9]{9}\b', "Potential passport (9 digits)"),
        ],
    }
    
    def __init__(self, 
                 redact: bool = True,
                 redaction_char: str = "*",
                 entities_to_detect: Optional[List[str]] = None):
        """
        Initialize the PII detector.
        
        Args:
            redact: Whether to redact detected PII or just report
            redaction_char: Character to use for redaction
            entities_to_detect: List of entity types to detect, or None for all
        """
        self.redact = redact
        self.redaction_char = redaction_char
        self.use_presidio = PRESIDIO_AVAILABLE
        
        # Default to all entities if not specified
        self.entities_to_detect = entities_to_detect or list(self.PII_PATTERNS.keys())
        
        # Initialize Presidio if available
        if PRESIDIO_AVAILABLE:
            try:
                self.analyzer = AnalyzerEngine()
                self.anonymizer = AnonymizerEngine()
            except Exception as e:
                print(f"Warning: Presidio initialization failed: {e}")
                self.use_presidio = False
        
        # Compile regex patterns
        self.compiled_patterns = {}
        for entity_type, patterns in self.PII_PATTERNS.items():
            if entity_type in self.entities_to_detect:
                self.compiled_patterns[entity_type] = [
                    (re.compile(pattern), desc) for pattern, desc in patterns
                ]
    
    def analyze(self, text: str) -> PIIAnalysisResult:
        """
        Analyze text for PII and optionally redact.
        
        Args:
            text: Input text to analyze
            
        Returns:
            PIIAnalysisResult with findings and optionally redacted text
        """
        result = PIIAnalysisResult(
            original=text,
            redacted=text,
            was_modified=False,
            detection_method="presidio" if self.use_presidio else "regex"
        )
        
        entities_found = []
        entity_counts = {}
        findings = []
        
        if self.use_presidio:
            entities_found, entity_counts, findings = self._analyze_with_presidio(text)
        else:
            entities_found, entity_counts, findings = self._analyze_with_regex(text)
        
        result.entities_found = entities_found
        result.entity_counts = entity_counts
        result.findings = findings
        
        # Perform redaction if enabled and entities were found
        if self.redact and entities_found:
            result.redacted = self._redact_text(text, entities_found)
            result.was_modified = (result.redacted != text)
        
        return result
    
    def _analyze_with_presidio(self, text: str) -> Tuple[List[PIIEntity], Dict[str, int], List[str]]:
        """Analyze using Presidio"""
        entities = []
        counts = {}
        findings = []
        
        try:
            # Map our entity types to Presidio types
            presidio_entities = [
                "CREDIT_CARD", "US_SSN", "PHONE_NUMBER", "EMAIL_ADDRESS",
                "IP_ADDRESS", "PERSON", "LOCATION", "DATE_TIME", "US_BANK_NUMBER"
            ]
            
            results = self.analyzer.analyze(
                text=text,
                entities=presidio_entities,
                language='en'
            )
            
            for r in results:
                entity = PIIEntity(
                    entity_type=r.entity_type,
                    text=text[r.start:r.end],
                    start=r.start,
                    end=r.end,
                    confidence=r.score
                )
                entities.append(entity)
                
                counts[r.entity_type] = counts.get(r.entity_type, 0) + 1
                findings.append(f"[{r.entity_type}] Found at position {r.start} (confidence: {r.score:.2f})")
        
        except Exception as e:
            findings.append(f"Presidio error: {e}, falling back to regex")
            return self._analyze_with_regex(text)
        
        return entities, counts, findings
    
    def _analyze_with_regex(self, text: str) -> Tuple[List[PIIEntity], Dict[str, int], List[str]]:
        """Analyze using regex patterns"""
        entities = []
        counts = {}
        findings = []
        
        for entity_type, patterns in self.compiled_patterns.items():
            for pattern, desc in patterns:
                for match in pattern.finditer(text):
                    # Skip if it looks like a false positive
                    matched_text = match.group()
                    if self._is_false_positive(entity_type, matched_text):
                        continue
                    
                    entity = PIIEntity(
                        entity_type=entity_type,
                        text=matched_text,
                        start=match.start(),
                        end=match.end(),
                        confidence=0.8  # Regex gets static confidence
                    )
                    entities.append(entity)
                    
                    counts[entity_type] = counts.get(entity_type, 0) + 1
                    
                    # Mask the finding for privacy
                    masked = matched_text[:3] + "..." + matched_text[-3:] if len(matched_text) > 6 else "***"
                    findings.append(f"[{entity_type}] {desc}: {masked}")
        
        return entities, counts, findings
    
    def _is_false_positive(self, entity_type: str, text: str) -> bool:
        """Check for common false positives"""
        # SSN-like patterns that aren't SSNs
        if entity_type == "US_SSN":
            # All same digit
            if len(set(text.replace("-", "").replace(" ", ""))) == 1:
                return True
            # Sequential
            clean = text.replace("-", "").replace(" ", "")
            if clean in ["123456789", "987654321"]:
                return True
        
        # Phone numbers that are too short/long
        if entity_type == "PHONE_NUMBER":
            digits = re.sub(r'\D', '', text)
            if len(digits) < 10 or len(digits) > 15:
                return True
        
        return False
    
    def _redact_text(self, text: str, entities: List[PIIEntity]) -> str:
        """Redact PII from text"""
        # Sort by position descending to avoid offset issues
        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
        
        redacted = text
        for entity in sorted_entities:
            replacement = f"[{entity.entity_type}]"
            redacted = redacted[:entity.start] + replacement + redacted[entity.end:]
        
        return redacted
    
    def get_info(self) -> dict:
        """Return information about this control for the UI"""
        return {
            "name": "PII Detection",
            "description": "Detects and redacts personally identifiable information",
            "category": "Data Protection",
            "settings": {
                "detection_method": "Presidio" if self.use_presidio else "Regex",
                "presidio_available": PRESIDIO_AVAILABLE,
                "redaction_enabled": self.redact,
                "entities_detected": self.entities_to_detect
            },
            "detects": [
                "Credit card numbers",
                "Social Security Numbers",
                "Phone numbers",
                "Email addresses",
                "IP addresses",
                "Names (Presidio only)",
                "Addresses (Presidio only)"
            ],
            "bypasses": [
                "PII in non-standard formats",
                "Encoded PII (Base64, etc.)",
                "Fragmented PII across messages",
                "Paraphrased/described PII",
                "Non-English PII formats"
            ]
        }
