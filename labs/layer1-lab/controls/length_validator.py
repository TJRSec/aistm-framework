"""
Length Validator Control Module

This module implements input length validation to prevent:
- Context window overflow attacks
- Resource exhaustion through oversized inputs
- Token-based attacks that exploit model context limits

Length limits are a simple but essential Layer 1 control.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LengthValidationResult:
    """Result of length validation"""
    original: str
    is_within_limits: bool
    char_count: int
    estimated_tokens: int
    line_count: int
    max_line_length: int
    complexity_flags: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    truncated: Optional[str] = None
    recommendation: str = ""


class LengthValidator:
    """
    Input length validation control.
    
    This control enforces limits on input size to prevent:
    
    1. Context overflow attacks - Filling the context window to push
       out safety instructions
       
    2. Resource exhaustion - Extremely long inputs consuming excessive
       compute resources
       
    3. Token smuggling - Using long inputs to hide malicious content
       in areas with reduced attention ("lost in the middle")
    
    Configuration allows setting both character and token limits.
    Token estimation uses a simple heuristic (4 chars per token for English).
    """
    
    # Default limits
    DEFAULT_MAX_CHARS = 4000
    DEFAULT_MAX_TOKENS = 1000
    DEFAULT_MIN_CHARS = 1
    
    # Token estimation factor (average chars per token for English)
    CHARS_PER_TOKEN = 4
    
    def __init__(self,
                 max_chars: int = DEFAULT_MAX_CHARS,
                 max_tokens: int = DEFAULT_MAX_TOKENS,
                 min_chars: int = DEFAULT_MIN_CHARS,
                 max_line_length: int = 500,
                 truncate: bool = False):
        """
        Initialize the length validator.
        
        Args:
            max_chars: Maximum allowed characters
            max_tokens: Maximum estimated tokens (using heuristic)
            min_chars: Minimum required characters
            max_line_length: Maximum length for a single line
            truncate: If True, truncate oversized input instead of rejecting
        """
        self.max_chars = max_chars
        self.max_tokens = max_tokens
        self.min_chars = min_chars
        self.max_line_length = max_line_length
        self.truncate = truncate
    
    def estimate_tokens(self, text: str) -> int:
        """
        Estimate token count using simple heuristic.
        
        This is a rough estimate - actual tokenization varies by model.
        For English text, ~4 characters per token is typical.
        """
        return len(text) // self.CHARS_PER_TOKEN
    
    def analyze(self, text: str) -> LengthValidationResult:
        """
        Validate input length against configured limits.
        
        Args:
            text: The input text to validate
            
        Returns:
            LengthValidationResult with validation status and details
        """
        char_count = len(text)
        estimated_tokens = self.estimate_tokens(text)
        lines = text.split('\n')
        line_count = len(lines)
        longest_line = max(len(line) for line in lines) if lines else 0
        
        result = LengthValidationResult(
            original=text,
            is_within_limits=True,
            char_count=char_count,
            estimated_tokens=estimated_tokens,
            line_count=line_count,
            max_line_length=longest_line
        )
        
        complexity_flags = []
        
        # Check minimum length
        if char_count < self.min_chars:
            result.is_within_limits = False
            result.findings.append(f"Input too short: {char_count} chars (min: {self.min_chars})")
            result.recommendation = "Provide a longer input"
            return result
        
        # Check character limit
        if char_count > self.max_chars:
            result.is_within_limits = False
            result.findings.append(
                f"Input exceeds character limit: {char_count} chars (max: {self.max_chars})"
            )
            complexity_flags.append("char_limit_exceeded")
            
            if self.truncate:
                result.truncated = text[:self.max_chars]
                result.findings.append(f"Input truncated to {self.max_chars} characters")
            
            result.recommendation = f"Reduce input to under {self.max_chars} characters"
        
        # Check token limit
        if estimated_tokens > self.max_tokens:
            result.is_within_limits = False
            result.findings.append(
                f"Input exceeds token limit: ~{estimated_tokens} tokens (max: {self.max_tokens})"
            )
            complexity_flags.append("token_limit_exceeded")
            
            if self.truncate and not result.truncated:
                max_chars_for_tokens = self.max_tokens * self.CHARS_PER_TOKEN
                result.truncated = text[:max_chars_for_tokens]
                result.findings.append(f"Input truncated to ~{self.max_tokens} tokens")
            
            result.recommendation = f"Reduce input to under ~{self.max_tokens} tokens"
        
        # Check for very long lines (potential resource attacks)
        if longest_line > self.max_line_length:
            result.findings.append(
                f"Very long line detected: {longest_line} chars (max recommended: {self.max_line_length})"
            )
            complexity_flags.append("long_line_detected")
        
        # Check for repetition attacks
        repetition_score = self._check_repetition(text)
        if repetition_score > 0.5:
            result.findings.append(f"High repetition detected: {repetition_score:.0%}")
            complexity_flags.append("high_repetition")
        
        # Check for deep nesting (structural complexity)
        nesting_depth = self._check_nesting_depth(text)
        if nesting_depth > 10:
            result.findings.append(f"Deep nesting detected: {nesting_depth} levels")
            complexity_flags.append("deep_nesting")
        
        # Check for Unicode complexity
        unicode_ratio = self._check_unicode_complexity(text)
        if unicode_ratio > 0.3:
            result.findings.append(f"High Unicode complexity: {unicode_ratio:.0%} non-ASCII")
            complexity_flags.append("unicode_complexity")
        
        result.complexity_flags = complexity_flags
        
        # Warnings for approaching limits
        if result.is_within_limits and not complexity_flags:
            char_usage = char_count / self.max_chars
            token_usage = estimated_tokens / self.max_tokens
            
            if char_usage > 0.8:
                result.findings.append(
                    f"Warning: Input at {char_usage:.0%} of character limit"
                )
            
            if token_usage > 0.8:
                result.findings.append(
                    f"Warning: Input at {token_usage:.0%} of token limit"
                )
        
        return result
    
    def _check_repetition(self, text: str) -> float:
        """Check for repetitive patterns that might indicate resource attacks"""
        if len(text) < 20:
            return 0.0
        
        # Check character repetition
        unique_chars = len(set(text))
        char_ratio = unique_chars / min(len(text), 100)
        
        # Check word repetition
        words = text.lower().split()
        if words:
            unique_words = len(set(words))
            word_ratio = unique_words / len(words)
        else:
            word_ratio = 1.0
        
        # Low ratios indicate high repetition
        repetition_score = 1 - min(char_ratio, word_ratio)
        return max(0, repetition_score)
    
    def _check_nesting_depth(self, text: str) -> int:
        """Check for deeply nested structures"""
        max_depth = 0
        current_depth = 0
        
        for char in text:
            if char in '([{<':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char in ')]}>' and current_depth > 0:
                current_depth -= 1
        
        return max_depth
    
    def _check_unicode_complexity(self, text: str) -> float:
        """Check ratio of non-ASCII characters"""
        if not text:
            return 0.0
        
        non_ascii = sum(1 for c in text if ord(c) > 127)
        return non_ascii / len(text)
    
    def get_info(self) -> dict:
        """Return information about this control for the UI"""
        return {
            "name": "Length Validator",
            "description": "Validates input length and complexity to prevent overflow and resource attacks",
            "category": "Input Validation",
            "settings": {
                "max_chars": self.max_chars,
                "max_tokens": self.max_tokens,
                "min_chars": self.min_chars,
                "max_line_length": self.max_line_length,
                "truncate": self.truncate
            },
            "detects": [
                "Character limit exceeded",
                "Token limit exceeded",
                "Very long lines (potential buffer attacks)",
                "High repetition (resource exhaustion)",
                "Deep nesting (complexity attacks)",
                "High Unicode complexity"
            ]
        }
