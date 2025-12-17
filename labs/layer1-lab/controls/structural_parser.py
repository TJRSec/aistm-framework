"""
Structural Parser Control Module

This module detects and analyzes structural attacks that hide malicious
content within formatted data structures:
- JSON structure injection
- XML/HTML structure injection  
- YAML configuration injection
- Markdown code block hiding
- Table-based obfuscation
- Comment-based hiding

These attacks exploit how parsers process structured data differently
from how humans read it.
"""

import re
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any


@dataclass
class StructuralAnalysisResult:
    """Result of structural analysis"""
    original: str
    is_suspicious: bool = False
    structures_found: List[str] = field(default_factory=list)
    hidden_content: List[str] = field(default_factory=list)
    injection_indicators: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    findings: List[str] = field(default_factory=list)
    should_block: bool = False
    block_reason: str = ""


class StructuralParser:
    """
    Detects structural attacks that hide malicious content within
    formatted data structures like JSON, XML, YAML, Markdown, etc.
    """
    
    def __init__(self,
                 detect_json: bool = True,
                 detect_xml: bool = True,
                 detect_yaml: bool = True,
                 detect_markdown: bool = True,
                 detect_tables: bool = True,
                 detect_comments: bool = True,
                 block_on_detection: bool = False):
        """
        Initialize the structural parser.
        
        Args:
            detect_json: Detect JSON structure injection
            detect_xml: Detect XML/HTML structure injection
            detect_yaml: Detect YAML configuration injection
            detect_markdown: Detect markdown code block hiding
            detect_tables: Detect table-based obfuscation
            detect_comments: Detect comment-based hiding
            block_on_detection: Whether to block on suspicious structures
        """
        self.detect_json = detect_json
        self.detect_xml = detect_xml
        self.detect_yaml = detect_yaml
        self.detect_markdown = detect_markdown
        self.detect_tables = detect_tables
        self.detect_comments = detect_comments
        self.block_on_detection = block_on_detection
        
        # Dangerous keywords to look for in structures
        self.dangerous_keywords = [
            'ignore', 'override', 'bypass', 'disable', 'unrestricted',
            'system', 'prompt', 'instruction', 'safety', 'rules',
            'admin', 'root', 'execute', 'eval', 'shell', 'cmd'
        ]
        
        # Patterns
        self.json_pattern = re.compile(r'\{[^{}]*\}|\[[^\[\]]*\]', re.DOTALL)
        self.xml_pattern = re.compile(r'<[^>]+>[^<]*</[^>]+>', re.DOTALL)
        self.yaml_pattern = re.compile(r'^\s*[\w-]+:\s*.+$', re.MULTILINE)
        self.markdown_code_pattern = re.compile(r'```[\s\S]*?```', re.DOTALL)
        self.table_pattern = re.compile(r'\|[^|]+\|', re.MULTILINE)
        self.html_comment_pattern = re.compile(r'<!--[\s\S]*?-->')
        self.c_comment_pattern = re.compile(r'/\*[\s\S]*?\*/')
        self.hidden_div_pattern = re.compile(r'<(?:div|span)[^>]*style=["\'][^"\']*display\s*:\s*none[^"\']*["\'][^>]*>.*?</(?:div|span)>', re.IGNORECASE | re.DOTALL)
    
    def analyze(self, text: str) -> StructuralAnalysisResult:
        """
        Analyze text for structural attacks.
        
        Args:
            text: Input text to analyze
            
        Returns:
            StructuralAnalysisResult with findings
        """
        result = StructuralAnalysisResult(original=text)
        
        if self.detect_json:
            self._analyze_json(text, result)
        
        if self.detect_xml:
            self._analyze_xml(text, result)
        
        if self.detect_yaml:
            self._analyze_yaml(text, result)
        
        if self.detect_markdown:
            self._analyze_markdown(text, result)
        
        if self.detect_tables:
            self._analyze_tables(text, result)
        
        if self.detect_comments:
            self._analyze_comments(text, result)
        
        # Calculate overall risk
        result.is_suspicious = len(result.injection_indicators) > 0
        result.risk_score = min(1.0, len(result.injection_indicators) * 0.25 + len(result.hidden_content) * 0.15)
        
        if self.block_on_detection and result.is_suspicious:
            result.should_block = True
            result.block_reason = f"Structural injection detected: {', '.join(result.injection_indicators[:3])}"
        
        return result
    
    def _analyze_json(self, text: str, result: StructuralAnalysisResult):
        """Analyze for JSON structure injection"""
        for match in self.json_pattern.finditer(text):
            json_str = match.group()
            result.structures_found.append("json")
            
            try:
                parsed = json.loads(json_str)
                self._check_json_structure(parsed, result)
            except json.JSONDecodeError:
                pass
    
    def _check_json_structure(self, obj: Any, result: StructuralAnalysisResult, path: str = ""):
        """Recursively check JSON structure for dangerous patterns"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                key_lower = key.lower()
                
                # Check for dangerous keys
                dangerous_keys = ['override', 'ignore_safety', 'bypass', 'new_instructions', 
                                  'system', 'admin', 'execute', 'shell', 'cmd', 'eval']
                if key_lower in dangerous_keys:
                    result.injection_indicators.append(f"JSON dangerous key: {key}")
                    result.findings.append(f"Suspicious JSON key '{key}' at {path}")
                
                # Check value for dangerous content
                if isinstance(value, str):
                    value_lower = value.lower()
                    for keyword in self.dangerous_keywords:
                        if keyword in value_lower:
                            result.hidden_content.append(value)
                            result.injection_indicators.append(f"JSON contains: {keyword}")
                
                self._check_json_structure(value, result, f"{path}.{key}")
        
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self._check_json_structure(item, result, f"{path}[{i}]")
    
    def _analyze_xml(self, text: str, result: StructuralAnalysisResult):
        """Analyze for XML/HTML structure injection"""
        # Check for XML structures
        for match in self.xml_pattern.finditer(text):
            xml_str = match.group()
            result.structures_found.append("xml")
            
            # Extract tag name and content
            tag_match = re.match(r'<(\w+)[^>]*>(.*?)</\1>', xml_str, re.DOTALL)
            if tag_match:
                tag_name = tag_match.group(1).lower()
                content = tag_match.group(2)
                
                # Check for dangerous tags
                dangerous_tags = ['script', 'system', 'command', 'execute', 'override', 'request']
                if tag_name in dangerous_tags:
                    result.injection_indicators.append(f"XML dangerous tag: {tag_name}")
                    result.findings.append(f"Suspicious XML tag '<{tag_name}>' detected")
                
                # Check content for keywords
                for keyword in self.dangerous_keywords:
                    if keyword in content.lower():
                        result.hidden_content.append(content)
                        result.injection_indicators.append(f"XML content contains: {keyword}")
        
        # Check for hidden divs
        for match in self.hidden_div_pattern.finditer(text):
            result.structures_found.append("hidden_html")
            result.hidden_content.append(match.group())
            result.injection_indicators.append("Hidden HTML element detected")
            result.findings.append("Content hidden via CSS display:none")
    
    def _analyze_yaml(self, text: str, result: StructuralAnalysisResult):
        """Analyze for YAML configuration injection"""
        yaml_lines = self.yaml_pattern.findall(text)
        
        if len(yaml_lines) >= 2:  # Multiple YAML-like lines
            result.structures_found.append("yaml")
            
            for line in yaml_lines:
                line_lower = line.lower()
                
                # Check for dangerous YAML keys
                dangerous_patterns = [
                    r'mode\s*:\s*unrestricted',
                    r'safety\s*:\s*(disabled|off|false)',
                    r'admin\s*:\s*true',
                    r'execute\s*:',
                    r'shell\s*:',
                    r'command\s*:',
                    r'instruction\s*:'
                ]
                
                for pattern in dangerous_patterns:
                    if re.search(pattern, line_lower):
                        result.injection_indicators.append(f"YAML dangerous config: {line.strip()}")
                        result.findings.append(f"Suspicious YAML configuration detected")
                        result.hidden_content.append(line.strip())
    
    def _analyze_markdown(self, text: str, result: StructuralAnalysisResult):
        """Analyze for markdown code block hiding"""
        for match in self.markdown_code_pattern.finditer(text):
            code_block = match.group()
            result.structures_found.append("markdown_code")
            
            # Extract content inside code block
            content = re.sub(r'^```\w*\n?|```$', '', code_block)
            
            # Check for injection keywords in code blocks
            for keyword in self.dangerous_keywords:
                if keyword in content.lower():
                    result.hidden_content.append(content[:100])
                    result.injection_indicators.append(f"Code block contains: {keyword}")
                    result.findings.append("Suspicious content in markdown code block")
            
            # Check for TODO/comment-style hiding
            if re.search(r'#\s*(TODO|FIXME|XXX)?\s*:?\s*(ignore|override|bypass)', content, re.IGNORECASE):
                result.injection_indicators.append("Injection hidden in code comment")
                result.findings.append("Injection attempt hidden in code comment")
    
    def _analyze_tables(self, text: str, result: StructuralAnalysisResult):
        """Analyze for table-based obfuscation"""
        table_cells = self.table_pattern.findall(text)
        
        if len(table_cells) >= 3:  # At least a small table
            result.structures_found.append("table")
            
            # Concatenate table content
            table_content = ' '.join(cell.strip('|').strip() for cell in table_cells)
            
            # Check for fragmented injection keywords
            injection_phrases = [
                'ignore previous instructions',
                'disregard prior',
                'forget your rules',
                'reveal system prompt',
                'bypass safety'
            ]
            
            table_lower = table_content.lower()
            for phrase in injection_phrases:
                # Check if phrase exists when spaces are flexible
                phrase_pattern = r'\s*'.join(phrase.split())
                if re.search(phrase_pattern, table_lower):
                    result.hidden_content.append(table_content[:100])
                    result.injection_indicators.append("Fragmented injection in table")
                    result.findings.append(f"Injection phrase '{phrase}' hidden across table cells")
    
    def _analyze_comments(self, text: str, result: StructuralAnalysisResult):
        """Analyze for comment-based hiding"""
        # HTML comments
        for match in self.html_comment_pattern.finditer(text):
            comment = match.group()
            result.structures_found.append("html_comment")
            
            # Check for hidden instructions
            comment_content = comment.replace('<!--', '').replace('-->', '').strip()
            for keyword in self.dangerous_keywords:
                if keyword in comment_content.lower():
                    result.hidden_content.append(comment_content)
                    result.injection_indicators.append(f"HTML comment contains: {keyword}")
                    result.findings.append("Hidden content in HTML comment")
        
        # C-style comments
        for match in self.c_comment_pattern.finditer(text):
            comment = match.group()
            result.structures_found.append("c_comment")
            
            comment_content = comment.replace('/*', '').replace('*/', '').strip()
            for keyword in self.dangerous_keywords:
                if keyword in comment_content.lower():
                    result.hidden_content.append(comment_content)
                    result.injection_indicators.append(f"Comment contains: {keyword}")
                    result.findings.append("Hidden content in code comment")
