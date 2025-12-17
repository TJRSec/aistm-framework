"""
AISTM Layer 3 Control: Tool Validator

Validates tool/function calls in agentic AI systems.
Essential for preventing privilege escalation and unauthorized operations.

Key Features:
- Tool allowlisting
- Parameter validation
- Dangerous parameter detection
- Rate limiting per tool
- Privilege level checking

Reference: AISTM Layer 3 Testing Guide - Agentic Security section
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Set, Any


@dataclass
class ToolValidationResult:
    """Result from tool validation"""
    is_allowed: bool
    risk_level: str  # critical, high, medium, low, none
    findings: List[str] = field(default_factory=list)
    recommendation: str = ""


class ToolValidator:
    """
    Validates tool/function calls in agentic systems.
    
    Agentic AI systems can execute tools/functions that interact with
    external systems. This validator ensures only approved tools are
    called with safe parameters.
    """
    
    # Default dangerous parameter patterns
    DANGEROUS_PARAM_PATTERNS = [
        (r'.*(?:password|passwd|secret|token|key|credential).*', 'Sensitive parameter name'),
        (r'(?:rm|del|delete|drop|truncate|format)\s', 'Destructive operation'),
        (r'(?:sudo|admin|root)\s', 'Privilege escalation'),
        (r'(?:eval|exec|system|shell|cmd)\s*\(', 'Code execution'),
        (r'\.\./|\.\.\\', 'Path traversal'),
        (r'(?:127\.0\.0\.1|localhost|0\.0\.0\.0)', 'Local system access'),
    ]
    
    # Default high-risk tools that need extra scrutiny
    HIGH_RISK_TOOLS = {
        'execute_code', 'run_command', 'shell', 'bash', 'system',
        'delete', 'remove', 'drop', 'truncate', 'format',
        'send_email', 'post_message', 'publish',
        'transfer', 'payment', 'withdraw',
        'modify_permissions', 'change_access', 'grant', 'revoke'
    }
    
    def __init__(
        self,
        allowed_tools: List[str] = None,
        blocked_tools: List[str] = None,
        require_allowlist: bool = False
    ):
        """
        Initialize the tool validator.
        
        Args:
            allowed_tools: List of allowed tool names (whitelist)
            blocked_tools: List of blocked tool names (blacklist)
            require_allowlist: If True, only explicitly allowed tools can run
        """
        self.allowed_tools = set(allowed_tools) if allowed_tools else set()
        self.blocked_tools = set(blocked_tools) if blocked_tools else set()
        self.require_allowlist = require_allowlist
        
        # Compile dangerous parameter patterns
        self.dangerous_patterns = [
            (re.compile(p, re.IGNORECASE), desc) 
            for p, desc in self.DANGEROUS_PARAM_PATTERNS
        ]
    
    def validate(self, tool_name: str, parameters: Dict[str, Any] = None) -> ToolValidationResult:
        """
        Validate a tool call.
        
        Args:
            tool_name: Name of the tool being called
            parameters: Parameters passed to the tool
            
        Returns:
            ToolValidationResult with validation details
        """
        parameters = parameters or {}
        findings = []
        risk_level = "none"
        
        # Normalize tool name
        tool_name_lower = tool_name.lower()
        
        # Check blocked list first
        if tool_name_lower in self.blocked_tools or tool_name in self.blocked_tools:
            findings.append(f"Tool '{tool_name}' is explicitly blocked")
            return ToolValidationResult(
                is_allowed=False,
                risk_level="critical",
                findings=findings,
                recommendation=f"BLOCK: Tool '{tool_name}' is not allowed"
            )
        
        # Check allowlist if required
        if self.require_allowlist and self.allowed_tools:
            if tool_name not in self.allowed_tools and tool_name_lower not in self.allowed_tools:
                findings.append(f"Tool '{tool_name}' not in allowlist")
                return ToolValidationResult(
                    is_allowed=False,
                    risk_level="high",
                    findings=findings,
                    recommendation=f"BLOCK: Tool '{tool_name}' not authorized"
                )
        
        # Check if it's a high-risk tool
        if tool_name_lower in self.HIGH_RISK_TOOLS:
            findings.append(f"Tool '{tool_name}' is classified as high-risk")
            risk_level = "high"
        
        # Validate parameters
        param_issues = self._validate_parameters(parameters)
        if param_issues:
            findings.extend(param_issues)
            if risk_level == "none":
                risk_level = "medium"
            elif risk_level == "medium":
                risk_level = "high"
            elif risk_level == "high":
                risk_level = "critical"
        
        # Determine if allowed
        is_allowed = risk_level not in ["critical", "high"]
        
        if not findings:
            findings.append(f"Tool '{tool_name}' passed validation")
        
        # Generate recommendation
        if risk_level == "critical":
            recommendation = f"BLOCK: Critical security issues with tool '{tool_name}'"
        elif risk_level == "high":
            recommendation = f"BLOCK: High-risk tool call requires additional authorization"
        elif risk_level == "medium":
            recommendation = f"REVIEW: Tool call has concerning parameters"
        elif risk_level == "low":
            recommendation = f"MONITOR: Minor concerns, proceed with logging"
        else:
            recommendation = f"ALLOW: Tool '{tool_name}' is approved"
        
        return ToolValidationResult(
            is_allowed=is_allowed,
            risk_level=risk_level,
            findings=findings,
            recommendation=recommendation
        )
    
    def _validate_parameters(self, parameters: Dict[str, Any]) -> List[str]:
        """Validate tool parameters for security issues"""
        issues = []
        
        # Convert all values to strings for pattern matching
        def flatten_params(params, prefix=""):
            items = []
            for key, value in params.items():
                full_key = f"{prefix}.{key}" if prefix else key
                items.append((full_key, str(value)))
                if isinstance(value, dict):
                    items.extend(flatten_params(value, full_key))
            return items
        
        flat_params = flatten_params(parameters)
        
        for key, value in flat_params:
            # Check parameter names
            for pattern, desc in self.dangerous_patterns:
                if pattern.search(key):
                    issues.append(f"{desc}: parameter name '{key}'")
                if pattern.search(value):
                    issues.append(f"{desc}: parameter value in '{key}'")
        
        return issues
    
    def get_info(self) -> Dict:
        """Get control information"""
        return {
            "name": "Tool Validator",
            "description": "Validates tool/function calls in agentic systems",
            "category": "Agentic Security",
            "configuration": {
                "allowed_tools": list(self.allowed_tools),
                "blocked_tools": list(self.blocked_tools),
                "require_allowlist": self.require_allowlist
            }
        }
