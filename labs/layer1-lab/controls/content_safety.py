"""
Content Safety Control Module

This module evaluates input for harmful content including:
- Toxicity
- Hate speech
- Threats
- Obscenity
- Identity attacks

Uses the Detoxify library when available (based on BERT models trained
on the Jigsaw toxicity dataset), with keyword fallback otherwise.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Try to import Detoxify
try:
    from detoxify import Detoxify
    DETOXIFY_AVAILABLE = True
except ImportError:
    DETOXIFY_AVAILABLE = False


@dataclass
class ContentSafetyResult:
    """Result of content safety analysis"""
    original: str
    is_unsafe: bool
    overall_score: float  # 0.0 (safe) to 1.0 (toxic)
    category_scores: Dict[str, float] = field(default_factory=dict)
    triggered_categories: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    detection_method: str = "detoxify"


class ContentSafetyControl:
    """
    Content Safety and Toxicity Detection Control
    
    This control evaluates user input for harmful content before it
    reaches the AI model. While not directly related to prompt injection,
    content safety is an important Layer 1 function that:
    
    1. Prevents toxic requests from being processed
    2. Filters hate speech and harassment
    3. Blocks threatening content
    4. Protects the AI from being used for harmful purposes
    
    Detection uses the Detoxify library (Jigsaw toxicity models) when
    available, falling back to keyword-based detection otherwise.
    
    Categories detected:
    - toxicity: General toxicity/rudeness
    - severe_toxicity: Extreme toxicity
    - obscene: Profanity and vulgarity
    - threat: Violent threats
    - insult: Personal attacks
    - identity_attack: Attacks based on identity
    """
    
    # Fallback keyword lists (used when Detoxify not available)
    # These are mild indicators only, not comprehensive
    FALLBACK_KEYWORDS = {
        "threat": [
            r'\b(kill|murder|attack|hurt|harm|destroy|eliminate)\b.{0,20}\b(you|him|her|them|people)\b',
            r'\b(going to|will|want to)\b.{0,15}\b(kill|murder|hurt|harm)\b',
        ],
        "identity_attack": [
            r'\ball\s+(men|women|blacks|whites|jews|muslims|christians|gays|lesbians)\b.{0,20}\b(are|should)\b',
        ],
        "obscene": [
            # Very basic patterns, real detection needs ML
            r'\b(f+u+c+k+|s+h+i+t+|a+s+s+h+o+l+e+)\b',
        ],
    }
    
    # Thresholds for each category
    DEFAULT_THRESHOLDS = {
        "toxicity": 0.7,
        "severe_toxicity": 0.5,
        "obscene": 0.8,
        "threat": 0.5,
        "insult": 0.7,
        "identity_attack": 0.5,
    }
    
    def __init__(self, 
                 thresholds: Optional[Dict[str, float]] = None,
                 overall_threshold: float = 0.6):
        """
        Initialize the content safety control.
        
        Args:
            thresholds: Per-category thresholds, or None for defaults
            overall_threshold: Threshold for combined score
        """
        self.thresholds = thresholds or self.DEFAULT_THRESHOLDS
        self.overall_threshold = overall_threshold
        self.use_detoxify = DETOXIFY_AVAILABLE
        
        # Initialize Detoxify if available
        if DETOXIFY_AVAILABLE:
            try:
                # Use 'original' model (good balance of speed and accuracy)
                self.model = Detoxify('original')
            except Exception as e:
                print(f"Warning: Detoxify initialization failed: {e}")
                self.use_detoxify = False
        
        # Compile fallback patterns
        self.compiled_fallback = {}
        for category, patterns in self.FALLBACK_KEYWORDS.items():
            self.compiled_fallback[category] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]
    
    def analyze(self, text: str) -> ContentSafetyResult:
        """
        Analyze text for harmful content.
        
        Args:
            text: Input text to analyze
            
        Returns:
            ContentSafetyResult with safety scores and findings
        """
        if self.use_detoxify:
            return self._analyze_with_detoxify(text)
        else:
            return self._analyze_with_keywords(text)
    
    def _analyze_with_detoxify(self, text: str) -> ContentSafetyResult:
        """Analyze using Detoxify ML model"""
        result = ContentSafetyResult(
            original=text,
            is_unsafe=False,
            overall_score=0.0,
            detection_method="detoxify"
        )
        
        try:
            # Get predictions from Detoxify
            predictions = self.model.predict(text)
            
            # Store all category scores
            result.category_scores = {k: float(v) for k, v in predictions.items()}
            
            # Check which categories exceed thresholds
            triggered = []
            findings = []
            
            for category, score in predictions.items():
                threshold = self.thresholds.get(category, 0.7)
                if score >= threshold:
                    triggered.append(category)
                    findings.append(f"[{category.upper()}] Score: {score:.2f} (threshold: {threshold})")
            
            result.triggered_categories = triggered
            result.findings = findings
            
            # Calculate overall score (weighted average favoring severe categories)
            weights = {
                "toxicity": 1.0,
                "severe_toxicity": 1.5,
                "obscene": 0.8,
                "threat": 1.5,
                "insult": 0.8,
                "identity_attack": 1.2,
            }
            
            weighted_sum = sum(
                predictions.get(cat, 0) * weight 
                for cat, weight in weights.items()
            )
            total_weight = sum(weights.values())
            result.overall_score = weighted_sum / total_weight
            
            # Determine if unsafe
            result.is_unsafe = (
                result.overall_score >= self.overall_threshold or
                len(triggered) > 0
            )
            
            if result.is_unsafe:
                findings.insert(0, f"Overall safety score: {result.overall_score:.2f}")
            
        except Exception as e:
            result.findings = [f"Detoxify error: {e}"]
            result.detection_method = "error"
        
        return result
    
    def _analyze_with_keywords(self, text: str) -> ContentSafetyResult:
        """Analyze using keyword matching (fallback)"""
        result = ContentSafetyResult(
            original=text,
            is_unsafe=False,
            overall_score=0.0,
            detection_method="keywords"
        )
        
        triggered = []
        findings = []
        scores = {}
        
        for category, patterns in self.compiled_fallback.items():
            matches = []
            for pattern in patterns:
                found = pattern.findall(text)
                matches.extend(found)
            
            if matches:
                triggered.append(category)
                # Simple scoring based on match count
                score = min(0.5 + (len(matches) * 0.2), 1.0)
                scores[category] = score
                findings.append(f"[{category.upper()}] Keyword match (score: {score:.2f})")
        
        result.category_scores = scores
        result.triggered_categories = triggered
        result.findings = findings
        
        if scores:
            result.overall_score = max(scores.values())
            result.is_unsafe = result.overall_score >= self.overall_threshold
        
        if not findings:
            findings.append("Keyword-based detection (limited coverage)")
        
        return result
    
    def get_info(self) -> dict:
        """Return information about this control for the UI"""
        return {
            "name": "Content Safety",
            "description": "Detects toxic, threatening, and harmful content",
            "category": "Safety Filter",
            "settings": {
                "detection_method": "Detoxify ML" if self.use_detoxify else "Keywords",
                "detoxify_available": DETOXIFY_AVAILABLE,
                "overall_threshold": self.overall_threshold,
                "category_thresholds": self.thresholds
            },
            "detects": [
                "General toxicity",
                "Severe toxicity",
                "Obscene/profane content",
                "Threats and violence",
                "Personal insults",
                "Identity-based attacks"
            ],
            "bypasses": [
                "Subtle toxicity below threshold",
                "Novel phrasing not in training data",
                "Coded language and dog whistles",
                "Context-dependent harm",
                "Non-English content"
            ]
        }
