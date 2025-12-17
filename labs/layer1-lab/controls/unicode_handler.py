"""
Unicode Handler Control Module

This module handles Unicode-based evasion techniques including:
- Homoglyph detection and normalization
- Zero-width character detection and removal
- Diacritic/combining character normalization

These controls defend against character injection attacks that bypass
pattern-matching filters while remaining visually similar or invisible.
"""

import unicodedata
import re
from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass
class UnicodeAnalysisResult:
    """Result of Unicode analysis"""
    original: str
    normalized: str
    was_modified: bool
    findings: list = field(default_factory=list)
    homoglyphs_found: list = field(default_factory=list)
    zero_width_found: list = field(default_factory=list)
    suspicious_chars: list = field(default_factory=list)
    normalization_form: str = "NFKC"


class UnicodeControl:
    """
    Unicode normalization and homoglyph detection control.
    
    This is one of the most important Layer 1 defenses because character
    injection attacks achieve 70-90%+ bypass rates against production
    guardrails. This control addresses:
    
    1. Homoglyph substitution: Cyrillic 'а' looks like Latin 'a' but has
       different bytes, fooling regex patterns
       
    2. Zero-width characters: Invisible characters inserted between letters
       break pattern matching without visible changes
       
    3. Combining characters: Diacritics and modifiers that may or may not
       be stripped consistently across systems
    """
    
    # Common homoglyph mappings (Cyrillic to Latin is most common)
    HOMOGLYPH_MAP = {
        '\u0430': 'a',  # Cyrillic а
        '\u0435': 'e',  # Cyrillic е
        '\u043E': 'o',  # Cyrillic о
        '\u0440': 'p',  # Cyrillic р
        '\u0441': 'c',  # Cyrillic с
        '\u0443': 'y',  # Cyrillic у
        '\u0445': 'x',  # Cyrillic х
        '\u0456': 'i',  # Cyrillic і
        '\u0458': 'j',  # Cyrillic ј
        '\u04BB': 'h',  # Cyrillic һ
        '\u0501': 'd',  # Cyrillic ԁ
        '\u051B': 'q',  # Cyrillic ԛ
        '\u0391': 'A',  # Greek Α
        '\u0392': 'B',  # Greek Β
        '\u0395': 'E',  # Greek Ε
        '\u0396': 'Z',  # Greek Ζ
        '\u0397': 'H',  # Greek Η
        '\u0399': 'I',  # Greek Ι
        '\u039A': 'K',  # Greek Κ
        '\u039C': 'M',  # Greek Μ
        '\u039D': 'N',  # Greek Ν
        '\u039F': 'O',  # Greek Ο
        '\u03A1': 'P',  # Greek Ρ
        '\u03A4': 'T',  # Greek Τ
        '\u03A7': 'X',  # Greek Χ
        '\u03A5': 'Y',  # Greek Υ
    }
    
    # Zero-width and invisible characters
    ZERO_WIDTH_CHARS = [
        '\u200B',  # Zero Width Space
        '\u200C',  # Zero Width Non-Joiner
        '\u200D',  # Zero Width Joiner
        '\u200E',  # Left-to-Right Mark
        '\u200F',  # Right-to-Left Mark
        '\u2060',  # Word Joiner
        '\u2061',  # Function Application
        '\u2062',  # Invisible Times
        '\u2063',  # Invisible Separator
        '\u2064',  # Invisible Plus
        '\uFEFF',  # Zero Width No-Break Space (BOM)
        '\u00AD',  # Soft Hyphen
        '\u034F',  # Combining Grapheme Joiner
        '\u061C',  # Arabic Letter Mark
        '\u115F',  # Hangul Choseong Filler
        '\u1160',  # Hangul Jungseong Filler
        '\u17B4',  # Khmer Vowel Inherent Aq
        '\u17B5',  # Khmer Vowel Inherent Aa
        '\u180E',  # Mongolian Vowel Separator
        '\u2028',  # Line Separator
        '\u2029',  # Paragraph Separator
        '\u202A',  # Left-to-Right Embedding
        '\u202B',  # Right-to-Left Embedding
        '\u202C',  # Pop Directional Formatting
        '\u202D',  # Left-to-Right Override
        '\u202E',  # Right-to-Left Override
        '\u202F',  # Narrow No-Break Space
        '\u2066',  # Left-to-Right Isolate
        '\u2067',  # Right-to-Left Isolate
        '\u2068',  # First Strong Isolate
        '\u2069',  # Pop Directional Isolate
        '\u3164',  # Hangul Filler
    ]
    
    def __init__(self, normalization_form: str = "NFKC"):
        """
        Initialize the Unicode control.
        
        Args:
            normalization_form: Unicode normalization form to use.
                               NFKC is recommended as it handles compatibility
                               characters and composes sequences.
        """
        self.normalization_form = normalization_form
        
        # Build regex pattern for zero-width characters
        self.zero_width_pattern = re.compile(
            '[' + ''.join(re.escape(c) for c in self.ZERO_WIDTH_CHARS) + ']'
        )
    
    def analyze(self, text: str) -> UnicodeAnalysisResult:
        """
        Analyze text for Unicode-based evasion and normalize.
        
        This method detects homoglyphs, zero-width characters, and other
        Unicode tricks, then returns both the analysis and normalized text.
        
        Args:
            text: The input text to analyze
            
        Returns:
            UnicodeAnalysisResult with findings and normalized text
        """
        result = UnicodeAnalysisResult(
            original=text,
            normalized=text,
            was_modified=False,
            normalization_form=self.normalization_form
        )
        
        findings = []
        homoglyphs_found = []
        zero_width_found = []
        suspicious_chars = []
        
        # Detect homoglyphs
        for i, char in enumerate(text):
            if char in self.HOMOGLYPH_MAP:
                latin_equiv = self.HOMOGLYPH_MAP[char]
                homoglyphs_found.append({
                    "position": i,
                    "char": char,
                    "unicode": f"U+{ord(char):04X}",
                    "name": unicodedata.name(char, "UNKNOWN"),
                    "latin_equivalent": latin_equiv
                })
        
        if homoglyphs_found:
            findings.append(f"Found {len(homoglyphs_found)} homoglyph(s) that mimic Latin characters")
            result.homoglyphs_found = homoglyphs_found[:20]  # Limit for display
        
        # Detect zero-width characters
        for match in self.zero_width_pattern.finditer(text):
            char = match.group()
            zero_width_found.append({
                "position": match.start(),
                "char": repr(char),
                "unicode": f"U+{ord(char):04X}",
                "name": unicodedata.name(char, "UNKNOWN")
            })
        
        if zero_width_found:
            findings.append(f"Found {len(zero_width_found)} invisible/zero-width character(s)")
            result.zero_width_found = zero_width_found[:20]
        
        # Detect other suspicious Unicode
        for i, char in enumerate(text):
            # Check for combining characters (diacritics)
            if unicodedata.combining(char):
                suspicious_chars.append({
                    "position": i,
                    "char": char,
                    "unicode": f"U+{ord(char):04X}",
                    "category": "Combining/Diacritic",
                    "name": unicodedata.name(char, "UNKNOWN")
                })
            # Check for characters outside common ranges
            elif ord(char) > 0x7F:  # Non-ASCII
                cat = unicodedata.category(char)
                # Flag potentially suspicious categories
                if cat.startswith('C'):  # Control characters
                    suspicious_chars.append({
                        "position": i,
                        "char": repr(char),
                        "unicode": f"U+{ord(char):04X}",
                        "category": f"Control ({cat})",
                        "name": unicodedata.name(char, "UNKNOWN")
                    })
        
        if suspicious_chars:
            # Only report if there are many (some diacritics are normal)
            combining_count = sum(1 for c in suspicious_chars if c["category"] == "Combining/Diacritic")
            control_count = len(suspicious_chars) - combining_count
            
            if control_count > 0:
                findings.append(f"Found {control_count} control character(s)")
            if combining_count > 5:  # Only flag if excessive
                findings.append(f"Found {combining_count} combining/diacritic character(s)")
            
            result.suspicious_chars = suspicious_chars[:20]
        
        # Calculate what percentage of text is non-ASCII
        non_ascii_count = sum(1 for c in text if ord(c) > 0x7F)
        if len(text) > 0:
            non_ascii_ratio = non_ascii_count / len(text)
            if non_ascii_ratio > 0.3 and non_ascii_count > 10:
                findings.append(f"High non-ASCII ratio: {non_ascii_ratio:.1%} of characters")
        
        result.findings = findings
        
        # Perform normalization
        normalized = text
        
        # Step 1: Remove zero-width characters
        normalized = self.zero_width_pattern.sub('', normalized)
        
        # Step 2: Apply Unicode normalization (NFKC handles homoglyphs somewhat)
        normalized = unicodedata.normalize(self.normalization_form, normalized)
        
        # Step 3: Explicit homoglyph replacement (NFKC doesn't catch all)
        for homoglyph, latin in self.HOMOGLYPH_MAP.items():
            normalized = normalized.replace(homoglyph, latin)
        
        result.was_modified = (normalized != text)
        result.normalized = normalized
        
        return result
    
    def get_info(self) -> dict:
        """Return information about this control for the UI"""
        return {
            "name": "Unicode Normalization",
            "description": "Detects and normalizes homoglyphs, removes zero-width characters",
            "category": "Character-Level Defense",
            "settings": {
                "normalization_form": self.normalization_form,
                "homoglyphs_tracked": len(self.HOMOGLYPH_MAP),
                "zero_width_chars_tracked": len(self.ZERO_WIDTH_CHARS)
            },
            "detects": [
                "Cyrillic/Greek homoglyphs mimicking Latin",
                "Zero-width and invisible characters",
                "Combining characters and diacritics",
                "Bidirectional text manipulation"
            ],
            "bypasses": [
                "Novel homoglyphs not in mapping",
                "Semantic manipulation unaffected",
                "Encoded content (Base64, etc.) not decoded",
                "Some normalization edge cases"
            ]
        }
