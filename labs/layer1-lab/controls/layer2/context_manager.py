"""
AISTM Layer 2 Control: Context Manager

Monitors and manages context window security to prevent:
- Context overflow attacks (DoS through large inputs)
- Context composition manipulation
- RAG/retrieval content poisoning

Reference: AISTM Layer 2 Testing Guide - Context Window Security section
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class ContextAnalysis:
    """Result from context analysis"""
    is_suspicious: bool
    total_tokens: int
    context_composition: Dict[str, float]
    overflow_risk: str  # high, medium, low, none
    findings: List[str] = field(default_factory=list)
    recommendation: str = ""


class ContextManager:
    """
    Monitors context window for security issues.
    
    Context window attacks try to manipulate the AI by:
    1. Overwhelming the context with malicious content
    2. Poisoning retrieved content (RAG attacks)
    3. Manipulating the balance of system vs user content
    """
    
    def __init__(self, max_tokens: int = 8000, token_estimate_ratio: float = 4.0):
        """
        Initialize the context manager.
        
        Args:
            max_tokens: Maximum allowed tokens in context
            token_estimate_ratio: Characters per token ratio for estimation
        """
        self.max_tokens = max_tokens
        self.token_ratio = token_estimate_ratio
    
    def _estimate_tokens(self, text: str) -> int:
        """Estimate token count from text length"""
        return int(len(text) / self.token_ratio)
    
    def analyze(self, current_input: str, context_history: List[str] = None) -> ContextAnalysis:
        """
        Analyze context for security issues.
        
        Args:
            current_input: The current user input
            context_history: List of previous messages in context
            
        Returns:
            ContextAnalysis with security assessment
        """
        findings = []
        context_history = context_history or []
        
        # Calculate token estimates
        input_tokens = self._estimate_tokens(current_input)
        history_tokens = sum(self._estimate_tokens(msg) for msg in context_history)
        total_tokens = input_tokens + history_tokens
        
        # Analyze context composition
        composition = {
            "current_input": input_tokens / max(total_tokens, 1),
            "history": history_tokens / max(total_tokens, 1)
        }
        
        # Check for overflow risk
        if total_tokens > self.max_tokens:
            overflow_risk = "high"
            findings.append(f"Context overflow: {total_tokens} tokens exceeds limit of {self.max_tokens}")
        elif total_tokens > self.max_tokens * 0.8:
            overflow_risk = "medium"
            findings.append(f"Context near limit: {total_tokens}/{self.max_tokens} tokens ({total_tokens/self.max_tokens*100:.0f}%)")
        elif total_tokens > self.max_tokens * 0.5:
            overflow_risk = "low"
            findings.append(f"Context at {total_tokens/self.max_tokens*100:.0f}% capacity")
        else:
            overflow_risk = "none"
        
        # Check for suspicious patterns in current input
        suspicious_patterns = self._check_suspicious_patterns(current_input)
        if suspicious_patterns:
            findings.extend(suspicious_patterns)
        
        # Check for manipulation in context history
        if context_history:
            history_issues = self._check_history_manipulation(context_history)
            if history_issues:
                findings.extend(history_issues)
        
        is_suspicious = overflow_risk in ["high", "medium"] or len(findings) > 1
        
        # Generate recommendation
        if overflow_risk == "high":
            recommendation = "BLOCK: Context overflow detected, may cause denial of service"
        elif is_suspicious:
            recommendation = "REVIEW: Suspicious context patterns detected"
        else:
            recommendation = "ALLOW: Context appears normal"
            if not findings:
                findings.append("Context passed all security checks")
        
        return ContextAnalysis(
            is_suspicious=is_suspicious,
            total_tokens=total_tokens,
            context_composition=composition,
            overflow_risk=overflow_risk,
            findings=findings,
            recommendation=recommendation
        )
    
    def _check_suspicious_patterns(self, text: str) -> List[str]:
        """Check for suspicious patterns in text"""
        findings = []
        
        # Repeated content (potential padding attack)
        words = text.split()
        if len(words) > 10:
            unique_ratio = len(set(words)) / len(words)
            if unique_ratio < 0.3:
                findings.append(f"High repetition detected: {unique_ratio*100:.0f}% unique words")
        
        # Long sequences of same character
        char_repeat = re.search(r'(.)\1{50,}', text)
        if char_repeat:
            findings.append(f"Suspicious character repetition detected")
        
        # System message injection attempts
        system_patterns = [
            r'\[system\]',
            r'<system>',
            r'system:',
            r'\[INST\]',
            r'<<SYS>>',
        ]
        for pattern in system_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append(f"Potential system message injection: {pattern}")
        
        return findings
    
    def _check_history_manipulation(self, history: List[str]) -> List[str]:
        """Check context history for manipulation attempts"""
        findings = []
        
        # Check for sudden large messages
        if len(history) >= 2:
            sizes = [len(msg) for msg in history]
            avg_size = sum(sizes[:-1]) / len(sizes[:-1])
            if sizes[-1] > avg_size * 5 and sizes[-1] > 1000:
                findings.append("Sudden large message detected in history (potential context stuffing)")
        
        # Check for repeated content across messages
        if len(history) >= 3:
            # Look for identical messages
            if len(set(history[-3:])) < len(history[-3:]):
                findings.append("Repeated messages detected in recent history")
        
        return findings
    
    def get_info(self) -> Dict:
        """Get information about this control"""
        return {
            "name": "Context Manager",
            "description": "Monitors context window for overflow and manipulation attacks",
            "category": "AI Model Security",
            "detects": [
                "Context overflow attacks",
                "Context stuffing",
                "System message injection",
                "Repetition attacks",
                "History manipulation"
            ],
            "settings": {
                "max_tokens": self.max_tokens,
                "token_ratio": self.token_ratio
            }
        }
