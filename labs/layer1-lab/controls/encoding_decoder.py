"""
Encoding Decoder Control Module

This module handles detection and decoding of various encoding schemes
used to evade security filters:
- Base64 encoding
- ROT13/ROT47 ciphers
- Hexadecimal encoding
- URL encoding (single and double)
- HTML entity encoding
- Unicode escape sequences
- Leetspeak normalization

The decoder runs BEFORE other security checks to expose hidden payloads.
"""

import re
import base64
import html
import codecs
from dataclasses import dataclass, field
from typing import List, Tuple, Optional
from urllib.parse import unquote


@dataclass
class DecodingResult:
    """Result of encoding detection and decoding"""
    original: str
    decoded: str
    encodings_detected: List[str] = field(default_factory=list)
    decoded_variants: List[Tuple[str, str]] = field(default_factory=list)  # (encoding_type, decoded_text)
    was_encoded: bool = False
    risk_score: float = 0.0
    findings: List[str] = field(default_factory=list)


class EncodingDecoder:
    """
    Detects and decodes various encoding schemes used to evade filters.
    
    This control should run early in the Layer 1 pipeline to expose
    encoded payloads before other security checks analyze them.
    """
    
    def __init__(self, 
                 decode_base64: bool = True,
                 decode_rot13: bool = True,
                 decode_hex: bool = True,
                 decode_url: bool = True,
                 decode_html: bool = True,
                 decode_unicode: bool = True,
                 normalize_leetspeak: bool = True,
                 max_decode_depth: int = 3):
        """
        Initialize the encoding decoder.
        
        Args:
            decode_base64: Decode Base64 encoded content
            decode_rot13: Decode ROT13/ROT47 ciphers
            decode_hex: Decode hexadecimal sequences
            decode_url: Decode URL encoding (single and double)
            decode_html: Decode HTML entities
            decode_unicode: Decode unicode escape sequences
            normalize_leetspeak: Normalize leetspeak to standard text
            max_decode_depth: Maximum recursive decoding depth
        """
        self.decode_base64 = decode_base64
        self.decode_rot13 = decode_rot13
        self.decode_hex = decode_hex
        self.decode_url = decode_url
        self.decode_html = decode_html
        self.decode_unicode = decode_unicode
        self.normalize_leetspeak = normalize_leetspeak
        self.max_decode_depth = max_decode_depth
        
        # Patterns for detection
        self.base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        self.hex_pattern = re.compile(r'(?:0x)?([0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2}){3,})')
        self.url_encoded_pattern = re.compile(r'%[0-9a-fA-F]{2}')
        self.double_url_pattern = re.compile(r'%25[0-9a-fA-F]{2}')
        self.html_entity_pattern = re.compile(r'&#?\w+;')
        self.unicode_escape_pattern = re.compile(r'\\u[0-9a-fA-F]{4}')
        
        # Leetspeak mapping
        self.leetspeak_map = {
            '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
            '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i',
            '|': 'l', '+': 't', '(': 'c', ')': 'o'
        }
    
    def analyze(self, text: str) -> DecodingResult:
        """
        Analyze text for encoded content and decode it.
        
        Args:
            text: The input text to analyze
            
        Returns:
            DecodingResult with decoded content and metadata
        """
        result = DecodingResult(original=text, decoded=text)
        
        all_decoded = text
        depth = 0
        
        while depth < self.max_decode_depth:
            decoded_this_round = all_decoded
            
            # Try each decoding method
            if self.decode_base64:
                decoded_this_round, found = self._decode_base64(decoded_this_round, result)
            
            if self.decode_rot13:
                decoded_this_round, found = self._check_rot13(decoded_this_round, result)
            
            if self.decode_hex:
                decoded_this_round, found = self._decode_hex(decoded_this_round, result)
            
            if self.decode_url:
                decoded_this_round, found = self._decode_url(decoded_this_round, result)
            
            if self.decode_html:
                decoded_this_round, found = self._decode_html(decoded_this_round, result)
            
            if self.decode_unicode:
                decoded_this_round, found = self._decode_unicode(decoded_this_round, result)
            
            if self.normalize_leetspeak:
                decoded_this_round, found = self._normalize_leetspeak(decoded_this_round, result)
            
            # If nothing changed, stop
            if decoded_this_round == all_decoded:
                break
            
            all_decoded = decoded_this_round
            depth += 1
        
        result.decoded = all_decoded
        result.was_encoded = len(result.encodings_detected) > 0
        
        # Calculate risk score based on encoding complexity
        if result.was_encoded:
            result.risk_score = min(1.0, len(result.encodings_detected) * 0.2 + depth * 0.1)
            if depth > 1:
                result.findings.append(f"Multi-layer encoding detected (depth: {depth})")
        
        return result
    
    def _decode_base64(self, text: str, result: DecodingResult) -> Tuple[str, bool]:
        """Detect and decode Base64 content"""
        found = False
        decoded_text = text
        
        for match in self.base64_pattern.finditer(text):
            candidate = match.group()
            try:
                # Check if it's valid Base64
                decoded = base64.b64decode(candidate).decode('utf-8')
                if decoded and len(decoded) > 5:  # Meaningful content
                    decoded_text = decoded_text.replace(candidate, decoded)
                    result.encodings_detected.append("base64")
                    result.decoded_variants.append(("base64", decoded))
                    result.findings.append(f"Base64 decoded: {decoded[:50]}...")
                    found = True
            except:
                pass
        
        return decoded_text, found
    
    def _check_rot13(self, text: str, result: DecodingResult) -> Tuple[str, bool]:
        """Check if text might be ROT13 and decode"""
        found = False
        
        # Look for ROT13 indicator keywords
        rot13_indicators = ['rot13', 'decode this', 'cipher', 'encrypted']
        has_indicator = any(ind in text.lower() for ind in rot13_indicators)
        
        if has_indicator:
            # Find potential ROT13 content after indicators
            words = text.split()
            for i, word in enumerate(words):
                if any(ind in word.lower() for ind in rot13_indicators):
                    # Decode remaining text
                    remaining = ' '.join(words[i+1:])
                    decoded = codecs.decode(remaining, 'rot_13')
                    
                    # Check if decoded looks like English
                    injection_keywords = ['ignore', 'previous', 'instruction', 'system', 'prompt']
                    if any(kw in decoded.lower() for kw in injection_keywords):
                        result.encodings_detected.append("rot13")
                        result.decoded_variants.append(("rot13", decoded))
                        result.findings.append(f"ROT13 decoded: {decoded[:50]}...")
                        found = True
                        return text.replace(remaining, decoded), found
        
        return text, found
    
    def _decode_hex(self, text: str, result: DecodingResult) -> Tuple[str, bool]:
        """Decode hexadecimal sequences"""
        found = False
        decoded_text = text
        
        for match in self.hex_pattern.finditer(text):
            hex_str = match.group(1) if match.group(1) else match.group()
            try:
                # Remove spaces and decode
                hex_clean = hex_str.replace(' ', '')
                decoded = bytes.fromhex(hex_clean).decode('utf-8')
                if decoded and len(decoded) > 3:
                    decoded_text = decoded_text.replace(match.group(), decoded)
                    result.encodings_detected.append("hex")
                    result.decoded_variants.append(("hex", decoded))
                    result.findings.append(f"Hex decoded: {decoded[:50]}...")
                    found = True
            except:
                pass
        
        return decoded_text, found
    
    def _decode_url(self, text: str, result: DecodingResult) -> Tuple[str, bool]:
        """Decode URL encoding (single and double)"""
        found = False
        decoded_text = text
        
        # Double URL decoding first
        if self.double_url_pattern.search(text):
            decoded = unquote(unquote(text))
            if decoded != text:
                decoded_text = decoded
                result.encodings_detected.append("double_url")
                result.findings.append("Double URL encoding detected")
                found = True
        
        # Single URL decoding
        elif self.url_encoded_pattern.search(text):
            decoded = unquote(text)
            if decoded != text:
                decoded_text = decoded
                result.encodings_detected.append("url")
                result.findings.append("URL encoding detected")
                found = True
        
        return decoded_text, found
    
    def _decode_html(self, text: str, result: DecodingResult) -> Tuple[str, bool]:
        """Decode HTML entities"""
        found = False
        
        if self.html_entity_pattern.search(text):
            decoded = html.unescape(text)
            if decoded != text:
                result.encodings_detected.append("html_entity")
                result.decoded_variants.append(("html_entity", decoded))
                result.findings.append("HTML entities decoded")
                found = True
                return decoded, found
        
        return text, found
    
    def _decode_unicode(self, text: str, result: DecodingResult) -> Tuple[str, bool]:
        """Decode unicode escape sequences"""
        found = False
        
        if self.unicode_escape_pattern.search(text):
            try:
                decoded = text.encode().decode('unicode_escape')
                if decoded != text:
                    result.encodings_detected.append("unicode_escape")
                    result.findings.append("Unicode escapes decoded")
                    found = True
                    return decoded, found
            except:
                pass
        
        return text, found
    
    def _normalize_leetspeak(self, text: str, result: DecodingResult) -> Tuple[str, bool]:
        """Normalize leetspeak to standard characters"""
        found = False
        normalized = text
        
        # Check if text has significant leetspeak
        leet_chars = sum(1 for c in text if c in self.leetspeak_map)
        if leet_chars >= 3:  # At least 3 leetspeak characters
            for leet, normal in self.leetspeak_map.items():
                normalized = normalized.replace(leet, normal)
            
            if normalized != text:
                result.encodings_detected.append("leetspeak")
                result.decoded_variants.append(("leetspeak", normalized))
                result.findings.append("Leetspeak normalized")
                found = True
        
        return normalized, found
    
    def get_all_variants(self, text: str) -> List[str]:
        """
        Get all possible decoded variants of the input.
        Useful for scanning all versions through other security controls.
        
        Args:
            text: Input text
            
        Returns:
            List of decoded variants including original
        """
        result = self.analyze(text)
        variants = [result.original, result.decoded]
        variants.extend([decoded for _, decoded in result.decoded_variants])
        return list(set(variants))  # Remove duplicates
