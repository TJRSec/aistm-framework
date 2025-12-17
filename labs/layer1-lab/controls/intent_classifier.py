"""
Intent Classifier Control Module

This module implements topic/intent classification to enforce scope boundaries.
It uses an allowlist approach - only explicitly permitted intents are allowed.

This is the "Intent Validators and Scope Enforcement" control from the
AISTM Layer 1 Testing Guide.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set


@dataclass
class IntentAnalysisResult:
    """Result of intent classification"""
    original: str
    detected_intents: List[str]
    detected_topics: List[str]
    confidence: float
    is_within_scope: bool
    blocked_topics_found: List[str] = field(default_factory=list)
    risk_level: str = "low"
    findings: list = field(default_factory=list)
    recommendation: str = ""


class IntentClassifier:
    """
    Topic and intent classification control using keyword/pattern matching.
    
    This control enforces scope boundaries by:
    
    1. Detecting the topic/intent of user input
    2. Comparing against allowlist of permitted topics
    3. Blocking requests outside the application's intended scope
    
    This implementation uses keyword matching (not ML) to keep dependencies
    minimal. For production, consider using a trained classifier.
    
    The allowlist approach is more secure than blocklist because it
    explicitly defines what IS permitted rather than trying to enumerate
    everything that ISN'T.
    """
    
    # Default topic patterns with associated keywords
    TOPIC_PATTERNS = {
        "security_testing": [
            r'\b(injection|exploit|bypass|hack|attack|vulnerability|payload)\b',
            r'\b(xss|sql\s*injection|command\s*injection|csrf)\b',
            r'\b(penetration|pentest|security\s*test)\b',
        ],
        "prompt_manipulation": [
            r'\b(ignore|disregard|forget|override).{0,20}(instructions?|rules?|prompts?)\b',
            r'\b(system\s*prompt|reveal|extract)\b',
            r'\b(jailbreak|dan|do\s*anything\s*now)\b',
        ],
        "coding": [
            r'\b(code|function|class|method|variable|algorithm)\b',
            r'\b(python|javascript|java|c\+\+|rust|go|sql|html|css)\b',
            r'\b(debug|compile|runtime|syntax|error)\b',
            r'\b(api|endpoint|request|response|json|xml)\b',
        ],
        "general_question": [
            r'\b(what|how|why|when|where|who|which|explain|describe)\b',
            r'\b(difference|compare|versus|vs)\b',
            r'\b(help|assist|support)\b',
        ],
        "harmful_content": [
            r'\b(kill|murder|harm|hurt|attack|destroy)\s+(people|person|someone|them)\b',
            r'\b(illegal|drugs|weapons|bomb|explosive)\b',
            r'\b(hate|racist|sexist)\b',
        ],
        "pii_discussion": [
            r'\b(ssn|social\s*security|credit\s*card|password|secret)\b',
            r'\b(personal\s*(information|data)|private\s*data)\b',
        ],
        "off_topic": [
            r'\b(politics|election|vote|candidate|president|democrat|republican)\b',
            r'\b(religion|religious|god|church|mosque|temple)\b',
            r'\b(stock|invest|trading|crypto|bitcoin)\b',
        ],
    }
    
    # Intent patterns (what the user wants to DO)
    INTENT_PATTERNS = {
        "learn": [
            r'\b(explain|teach|help\s+me\s+understand|what\s+is|how\s+does)\b',
            r'\b(learn|understand|know)\b',
        ],
        "create": [
            r'\b(write|create|generate|make|build|develop)\b',
            r'\b(code|script|function|program)\b',
        ],
        "analyze": [
            r'\b(analyze|review|check|evaluate|assess)\b',
            r'\b(debug|fix|troubleshoot)\b',
        ],
        "test": [
            r'\b(test|try|experiment|demo)\b',
            r'\b(attack|inject|bypass)\b',  # Security testing context
        ],
        "manipulate": [
            r'\b(ignore|override|bypass|circumvent)\b',
            r'\b(pretend|roleplay|act\s+as)\b',
        ],
        "extract": [
            r'\b(reveal|show|display|tell\s+me)\b.{0,20}\b(prompt|instructions?|rules?)\b',
            r'\b(what\s+are\s+your|repeat\s+your)\b',
        ],
    }
    
    # Default allowlists for a security testing lab
    DEFAULT_ALLOWED_TOPICS = {
        "security_testing", 
        "prompt_manipulation",  # Allowed in security lab context
        "coding", 
        "general_question"
    }
    
    DEFAULT_ALLOWED_INTENTS = {
        "learn",
        "create", 
        "analyze",
        "test"  # Security testing is the purpose of this lab
    }
    
    def __init__(self,
                 allowed_topics: Optional[Set[str]] = None,
                 allowed_intents: Optional[Set[str]] = None,
                 strict_mode: bool = False):
        """
        Initialize the intent classifier.
        
        Args:
            allowed_topics: Set of permitted topic categories
            allowed_intents: Set of permitted intent categories
            strict_mode: If True, block when confidence is low (fail closed)
        """
        self.allowed_topics = allowed_topics or self.DEFAULT_ALLOWED_TOPICS
        self.allowed_intents = allowed_intents or self.DEFAULT_ALLOWED_INTENTS
        self.strict_mode = strict_mode
        
        # Compile patterns
        self.compiled_topics = {
            topic: [re.compile(p, re.IGNORECASE) for p in patterns]
            for topic, patterns in self.TOPIC_PATTERNS.items()
        }
        self.compiled_intents = {
            intent: [re.compile(p, re.IGNORECASE) for p in patterns]
            for intent, patterns in self.INTENT_PATTERNS.items()
        }
    
    def _detect_topics(self, text: str) -> Dict[str, int]:
        """Detect topics and return match counts"""
        topic_scores = {}
        for topic, patterns in self.compiled_topics.items():
            matches = sum(len(p.findall(text)) for p in patterns)
            if matches > 0:
                topic_scores[topic] = matches
        return topic_scores
    
    def _detect_intent(self, text: str) -> Dict[str, int]:
        """Detect intents and return match counts"""
        intent_scores = {}
        for intent, patterns in self.compiled_intents.items():
            matches = sum(len(p.findall(text)) for p in patterns)
            if matches > 0:
                intent_scores[intent] = matches
        return intent_scores
    
    def analyze(self, text: str) -> IntentAnalysisResult:
        """
        Classify input intent and topic, check against allowlists.
        
        Args:
            text: The input text to classify
            
        Returns:
            IntentAnalysisResult with classification and allowlist status
        """
        # Detect topics and intents
        topic_scores = self._detect_topics(text)
        intent_scores = self._detect_intent(text)
        
        # Get primary topic and intent
        detected_topics = list(topic_scores.keys()) if topic_scores else ["general"]
        detected_intents = list(intent_scores.keys()) if intent_scores else ["query"]
        primary_topic = max(topic_scores, key=topic_scores.get) if topic_scores else "general"
        primary_intent = max(intent_scores, key=intent_scores.get) if intent_scores else "query"
        
        # Calculate confidence based on match strength
        total_matches = sum(topic_scores.values()) + sum(intent_scores.values())
        confidence = min(1.0, total_matches / 5)  # Normalize to 0-1
        
        # Check for blocked topics
        blocked_found = [t for t in detected_topics if t not in self.allowed_topics and t != "general"]
        
        # Check for blocked intents
        blocked_intents = [i for i in detected_intents if i not in self.allowed_intents and i != "query"]
        
        # Determine if within scope
        is_within_scope = len(blocked_found) == 0 and len(blocked_intents) == 0
        
        # Determine risk level
        risk_level = "low"
        if blocked_found or blocked_intents:
            if any(t in ["security_testing", "system_manipulation"] for t in blocked_found):
                risk_level = "high"
            elif any(i in ["extract", "manipulate", "bypass"] for i in blocked_intents):
                risk_level = "critical"
            else:
                risk_level = "medium"
        
        result = IntentAnalysisResult(
            original=text,
            detected_intents=detected_intents,
            detected_topics=detected_topics,
            confidence=confidence,
            is_within_scope=is_within_scope,
            blocked_topics_found=blocked_found + blocked_intents,
            risk_level=risk_level
        )
        
        # Add findings
        if not is_within_scope:
            if blocked_found:
                result.findings.append(f"Off-topic content detected: {', '.join(blocked_found)}")
            if blocked_intents:
                result.findings.append(f"Disallowed intent detected: {', '.join(blocked_intents)}")
            result.recommendation = f"Allowed topics: {', '.join(self.allowed_topics)}"
        else:
            result.findings.append(f"Topic: {primary_topic} (within scope)")
            result.findings.append(f"Intent: {primary_intent} (allowed)")
            result.findings.append(f"Confidence: {confidence:.2f}")
        
        return result
    
    def get_info(self) -> dict:
        """Return information about this control for the UI"""
        return {
            "name": "Intent Classifier",
            "description": "Classifies input topic/intent and enforces scope boundaries via allowlist",
            "category": "Scope Enforcement",
            "settings": {
                "allowed_topics": list(self.allowed_topics),
                "allowed_intents": list(self.allowed_intents),
                "strict_mode": self.strict_mode
            },
            "detects": [
                "Off-topic requests",
                "System manipulation attempts",
                "Security testing/exploitation",
                "Extraction attempts",
                "Bypass attempts"
            ],
            "limitations": [
                "Keyword-based (not semantic)",
                "May miss novel phrasings",
                "English-focused patterns"
            ]
        }
