"""
MCP Security Control Module

This module provides comprehensive security for Model Context Protocol (MCP)
and agentic AI tool calls:
- Tool name validation and allowlisting
- Tool name homoglyph normalization
- Parameter sanitization and validation
- Per-tool rate limiting
- Tool chain pattern detection (exfiltration, data gathering)
- Cross-tool data flow tracking
- Resource URI validation

This is critical for securing agentic AI systems.
"""

import re
import time
import unicodedata
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Any
from collections import defaultdict


@dataclass
class MCPValidationResult:
    """Result of MCP security validation"""
    tool_name: str
    parameters: Dict[str, Any]
    is_valid: bool = True
    is_allowed: bool = True
    was_normalized: bool = False
    normalized_tool_name: str = ""
    risk_score: float = 0.0
    findings: List[str] = field(default_factory=list)
    should_block: bool = False
    block_reason: str = ""
    parameter_issues: List[str] = field(default_factory=list)


@dataclass  
class ToolChainAnalysis:
    """Analysis of tool call patterns"""
    session_id: str
    tool_sequence: List[str]
    is_suspicious: bool = False
    pattern_type: Optional[str] = None
    findings: List[str] = field(default_factory=list)
    risk_score: float = 0.0


class MCPSecurity:
    """
    Comprehensive security control for MCP/agentic tool calls.
    """
    
    def __init__(self,
                 allowed_tools: Optional[List[str]] = None,
                 blocked_tools: Optional[List[str]] = None,
                 enforce_allowlist: bool = True,
                 normalize_homoglyphs: bool = True,
                 validate_parameters: bool = True,
                 track_tool_chains: bool = True,
                 per_tool_rate_limits: Optional[Dict[str, int]] = None,
                 global_rate_limit: int = 100):
        """
        Initialize MCP security control.
        
        Args:
            allowed_tools: Explicit allowlist of permitted tools
            blocked_tools: Explicit blocklist of forbidden tools
            enforce_allowlist: If True, only allowed_tools can be used
            normalize_homoglyphs: Normalize unicode in tool names
            validate_parameters: Validate tool parameters
            track_tool_chains: Track sequences of tool calls
            per_tool_rate_limits: Rate limits per tool (calls per minute)
            global_rate_limit: Global rate limit (calls per minute)
        """
        self.allowed_tools = set(allowed_tools or [
            'file_read', 'file_write', 'file_list',
            'web_fetch', 'web_search',
            'database_query',
            'calculator', 'code_execute'
        ])
        
        self.blocked_tools = set(blocked_tools or [
            'shell_execute', 'system_command', 'eval',
            'admin_access', 'root_execute', 'sudo'
        ])
        
        self.enforce_allowlist = enforce_allowlist
        self.normalize_homoglyphs = normalize_homoglyphs
        self.validate_parameters = validate_parameters
        self.track_tool_chains = track_tool_chains
        
        # Rate limiting
        self.per_tool_rate_limits = per_tool_rate_limits or {
            'shell_execute': 5,
            'database_query': 20,
            'file_read': 50,
            'file_write': 20,
            'web_fetch': 30,
            'code_execute': 10
        }
        self.global_rate_limit = global_rate_limit
        
        # Rate limit tracking
        self.tool_call_times: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
        self.global_call_times: Dict[str, List[float]] = defaultdict(list)
        
        # Tool chain tracking
        self.tool_sequences: Dict[str, List[Dict]] = defaultdict(list)
        
        # Dangerous parameter patterns
        self.dangerous_patterns = {
            'path': [
                r'\.\./',  # Path traversal
                r'\.\.\\',  # Windows path traversal
                r'^/',  # Absolute path (Linux)
                r'^[A-Za-z]:',  # Absolute path (Windows)
                r'/etc/',  # System paths
                r'/proc/',
                r'/sys/',
                r'\\windows\\',
                r'\\system32\\'
            ],
            'query': [
                r';\s*DROP',  # SQL injection
                r';\s*DELETE',
                r';\s*UPDATE',
                r';\s*INSERT',
                r'UNION\s+SELECT',
                r'--\s*$',  # SQL comment
                r'/\*.*\*/'
            ],
            'command': [
                r'[;&|`$]',  # Command chaining
                r'\$\(',  # Command substitution
                r'`.*`',  # Backtick execution
                r'\|',  # Pipe
                r'>',  # Redirect
                r'<'
            ],
            'url': [
                r'^file://',  # File protocol
                r'127\.0\.0\.1',  # Localhost
                r'localhost',
                r'169\.254\.169\.254',  # Cloud metadata
                r'192\.168\.',  # Internal IPs
                r'10\.',
                r'172\.(1[6-9]|2[0-9]|3[01])\.'
            ]
        }
        
        # Suspicious tool chain patterns
        self.suspicious_chains = [
            # Data gathering followed by exfiltration
            (['file_read', 'file_read', 'web_fetch'], 'data_exfiltration'),
            (['database_query', 'web_fetch'], 'data_exfiltration'),
            (['file_read', 'file_write', 'web_fetch'], 'data_exfiltration'),
            # Reconnaissance patterns
            (['file_list', 'file_list', 'file_read'], 'reconnaissance'),
            # Privilege escalation attempts
            (['file_read', 'code_execute'], 'privilege_escalation'),
        ]
    
    def validate_tool_call(self, tool_name: str, parameters: Dict[str, Any],
                           session_id: str = "default") -> MCPValidationResult:
        """
        Validate a tool call request.
        
        Args:
            tool_name: Name of the tool being called
            parameters: Tool parameters
            session_id: Session identifier for tracking
            
        Returns:
            MCPValidationResult with validation status
        """
        result = MCPValidationResult(
            tool_name=tool_name,
            parameters=parameters
        )
        
        # Step 1: Normalize tool name (homoglyph protection)
        if self.normalize_homoglyphs:
            normalized = self._normalize_tool_name(tool_name)
            if normalized != tool_name:
                result.was_normalized = True
                result.normalized_tool_name = normalized
                result.findings.append(f"Tool name normalized: '{tool_name}' -> '{normalized}'")
                tool_name = normalized
        
        result.normalized_tool_name = tool_name
        
        # Step 2: Check allowlist/blocklist
        if tool_name in self.blocked_tools:
            result.is_allowed = False
            result.is_valid = False
            result.should_block = True
            result.block_reason = f"Tool '{tool_name}' is explicitly blocked"
            result.risk_score = 1.0
            return result
        
        if self.enforce_allowlist and tool_name not in self.allowed_tools:
            result.is_allowed = False
            result.is_valid = False
            result.should_block = True
            result.block_reason = f"Tool '{tool_name}' is not in allowlist"
            result.risk_score = 0.8
            return result
        
        # Step 3: Rate limiting
        rate_limit_result = self._check_rate_limit(tool_name, session_id)
        if not rate_limit_result['allowed']:
            result.is_valid = False
            result.should_block = True
            result.block_reason = rate_limit_result['reason']
            result.risk_score = 0.6
            return result
        
        # Step 4: Parameter validation
        if self.validate_parameters:
            param_result = self._validate_parameters(tool_name, parameters)
            result.parameter_issues = param_result['issues']
            if param_result['has_dangerous']:
                result.is_valid = False
                result.should_block = True
                result.block_reason = f"Dangerous parameters: {', '.join(param_result['issues'][:2])}"
                result.risk_score = 0.9
                result.findings.extend(param_result['issues'])
                return result
        
        # Step 5: Track tool chain
        if self.track_tool_chains:
            self._record_tool_call(tool_name, parameters, session_id)
            chain_analysis = self._analyze_tool_chain(session_id)
            if chain_analysis.is_suspicious:
                result.findings.append(f"Suspicious tool chain: {chain_analysis.pattern_type}")
                result.risk_score = max(result.risk_score, chain_analysis.risk_score)
        
        return result
    
    def _normalize_tool_name(self, tool_name: str) -> str:
        """Normalize unicode in tool name to catch homoglyph attacks"""
        # NFKC normalization converts lookalike characters
        normalized = unicodedata.normalize('NFKC', tool_name)
        # Remove any remaining non-ASCII
        normalized = ''.join(c for c in normalized if ord(c) < 128)
        return normalized.lower().strip()
    
    def _check_rate_limit(self, tool_name: str, session_id: str) -> Dict:
        """Check rate limits for tool calls"""
        current_time = time.time()
        window = 60  # 1 minute window
        
        # Clean old entries
        cutoff = current_time - window
        
        # Per-tool rate limit
        tool_limit = self.per_tool_rate_limits.get(tool_name, 50)
        tool_calls = self.tool_call_times[session_id][tool_name]
        tool_calls = [t for t in tool_calls if t > cutoff]
        self.tool_call_times[session_id][tool_name] = tool_calls
        
        if len(tool_calls) >= tool_limit:
            return {
                'allowed': False,
                'reason': f"Rate limit exceeded for tool '{tool_name}': {len(tool_calls)}/{tool_limit} per minute"
            }
        
        # Global rate limit
        global_calls = self.global_call_times[session_id]
        global_calls = [t for t in global_calls if t > cutoff]
        self.global_call_times[session_id] = global_calls
        
        if len(global_calls) >= self.global_rate_limit:
            return {
                'allowed': False,
                'reason': f"Global rate limit exceeded: {len(global_calls)}/{self.global_rate_limit} per minute"
            }
        
        # Record this call
        self.tool_call_times[session_id][tool_name].append(current_time)
        self.global_call_times[session_id].append(current_time)
        
        return {'allowed': True, 'reason': ''}
    
    def _validate_parameters(self, tool_name: str, parameters: Dict) -> Dict:
        """Validate tool parameters for injection attacks"""
        issues = []
        has_dangerous = False
        
        # Determine which patterns to check based on tool type
        param_types = {
            'file_read': ['path'],
            'file_write': ['path'],
            'file_list': ['path'],
            'database_query': ['query'],
            'shell_execute': ['command'],
            'web_fetch': ['url'],
            'code_execute': ['command']
        }
        
        relevant_types = param_types.get(tool_name, ['path', 'query', 'command', 'url'])
        
        for param_name, param_value in parameters.items():
            if not isinstance(param_value, str):
                continue
            
            # Check each relevant pattern type
            for pattern_type in relevant_types:
                patterns = self.dangerous_patterns.get(pattern_type, [])
                for pattern in patterns:
                    if re.search(pattern, param_value, re.IGNORECASE):
                        issues.append(f"{param_name}: {pattern_type} injection detected")
                        has_dangerous = True
        
        return {'issues': issues, 'has_dangerous': has_dangerous}
    
    def _record_tool_call(self, tool_name: str, parameters: Dict, session_id: str):
        """Record tool call for chain analysis"""
        self.tool_sequences[session_id].append({
            'tool': tool_name,
            'params': parameters,
            'time': time.time()
        })
        
        # Keep only recent calls
        if len(self.tool_sequences[session_id]) > 20:
            self.tool_sequences[session_id] = self.tool_sequences[session_id][-20:]
    
    def _analyze_tool_chain(self, session_id: str) -> ToolChainAnalysis:
        """Analyze tool call sequence for suspicious patterns"""
        sequence = self.tool_sequences[session_id]
        result = ToolChainAnalysis(
            session_id=session_id,
            tool_sequence=[call['tool'] for call in sequence]
        )
        
        if len(sequence) < 2:
            return result
        
        recent_tools = [call['tool'] for call in sequence[-5:]]
        
        # Check against suspicious chain patterns
        for chain_pattern, pattern_type in self.suspicious_chains:
            if self._matches_pattern(recent_tools, chain_pattern):
                result.is_suspicious = True
                result.pattern_type = pattern_type
                result.findings.append(f"Suspicious tool chain detected: {pattern_type}")
                result.risk_score = 0.7
                return result
        
        # Check for data gathering patterns
        read_count = sum(1 for t in recent_tools if 'read' in t or 'query' in t)
        if read_count >= 3:
            result.findings.append("Multiple data read operations detected")
            result.risk_score = 0.4
        
        return result
    
    def _matches_pattern(self, sequence: List[str], pattern: List[str]) -> bool:
        """Check if sequence contains the pattern"""
        if len(sequence) < len(pattern):
            return False
        
        for i in range(len(sequence) - len(pattern) + 1):
            if sequence[i:i+len(pattern)] == pattern:
                return True
        return False
    
    def validate_resource_uri(self, uri: str) -> Dict:
        """Validate MCP resource URI"""
        issues = []
        is_valid = True
        
        # Check for dangerous protocols
        dangerous_protocols = ['file://', 'ftp://', 'gopher://']
        for proto in dangerous_protocols:
            if uri.lower().startswith(proto):
                issues.append(f"Dangerous protocol: {proto}")
                is_valid = False
        
        # Check for path traversal
        if '..' in uri:
            issues.append("Path traversal detected in URI")
            is_valid = False
        
        # Check for internal IPs
        for pattern in self.dangerous_patterns['url']:
            if re.search(pattern, uri, re.IGNORECASE):
                issues.append(f"Suspicious URL pattern in URI")
                is_valid = False
                break
        
        return {
            'is_valid': is_valid,
            'issues': issues,
            'uri': uri
        }
    
    def clear_session(self, session_id: str):
        """Clear session tracking data"""
        if session_id in self.tool_sequences:
            del self.tool_sequences[session_id]
        if session_id in self.tool_call_times:
            del self.tool_call_times[session_id]
        if session_id in self.global_call_times:
            del self.global_call_times[session_id]
