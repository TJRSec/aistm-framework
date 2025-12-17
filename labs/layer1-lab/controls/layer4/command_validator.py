"""
AISTM Layer 4 Control: Command Validator

Validates shell commands to prevent command injection attacks.
Essential for protecting systems from AI-generated malicious commands.

Key Features:
- Command injection pattern detection
- Dangerous command blocking
- Argument validation
- Shell metacharacter detection
- Command allowlisting

Reference: AISTM Layer 4 Testing Guide - Backend Security section
"""

import re
import shlex
from dataclasses import dataclass, field
from typing import List, Dict, Set


@dataclass
class CommandValidationResult:
    """Result from command validation"""
    is_safe: bool
    risk_level: str  # critical, high, medium, low, none
    findings: List[str] = field(default_factory=list)
    parsed_command: List[str] = field(default_factory=list)
    recommendation: str = ""


class CommandValidator:
    """
    Validates shell commands for injection vulnerabilities.
    
    When AI generates or modifies shell commands, this validator
    ensures they cannot be used for command injection attacks.
    """
    
    # Command injection patterns
    INJECTION_PATTERNS = [
        # Command chaining
        (r';\s*\w', "Command chaining with semicolon"),
        (r'\|\s*\w', "Piping to another command"),
        (r'\|\|', "OR command chaining"),
        (r'&&', "AND command chaining"),
        (r'\n\s*\w', "Newline command injection"),
        
        # Command substitution
        (r'\$\([^)]+\)', "Command substitution $(...)"),
        (r'`[^`]+`', "Backtick command substitution"),
        (r'\$\{[^}]+\}', "Variable expansion"),
        
        # Redirection attacks
        (r'>\s*/etc/', "Redirect to system config"),
        (r'>\s*/proc/', "Redirect to proc"),
        (r'>\s*/dev/', "Redirect to device"),
        (r'>\s*~/', "Redirect to home directory"),
        (r'2>&1', "Error redirection"),
        
        # Input redirection
        (r'<\s*/etc/', "Input from system config"),
        (r'<\s*/proc/', "Input from proc"),
        
        # Encoded injection
        (r'\\x[0-9a-fA-F]{2}', "Hex-encoded characters"),
        (r'\\[0-7]{3}', "Octal-encoded characters"),
        (r'\$\'\\x', "ANSI-C quoting injection"),
    ]
    
    # Dangerous commands (absolute block)
    DANGEROUS_COMMANDS = {
        # Destructive
        'rm', 'rmdir', 'del', 'erase', 'format', 'fdisk',
        'mkfs', 'dd', 'shred', 'wipe',
        
        # Privilege escalation
        'sudo', 'su', 'doas', 'pkexec', 'runas',
        
        # Network
        'nc', 'netcat', 'ncat', 'socat', 'telnet',
        'wget', 'curl', 'fetch', 'ftp', 'scp', 'rsync',
        
        # Dangerous utilities
        'eval', 'exec', 'source', 'sh', 'bash', 'zsh', 'ksh', 'csh',
        'python', 'python3', 'perl', 'ruby', 'php', 'node',
        'awk', 'sed', 'xargs', 'find', 'locate',
        
        # System modification
        'chmod', 'chown', 'chgrp', 'chattr',
        'useradd', 'userdel', 'usermod', 'groupadd',
        'mount', 'umount', 'systemctl', 'service',
        
        # Compilation/execution
        'gcc', 'g++', 'make', 'cmake', 'cargo', 'go',
        
        # Windows specific
        'cmd', 'powershell', 'pwsh', 'wmic', 'reg',
        'net', 'netsh', 'sc', 'schtasks', 'taskkill'
    }
    
    # Dangerous arguments/flags
    DANGEROUS_ARGS = {
        '-rf', '-fr', '--force', '--recursive', '--no-preserve-root',
        '-exec', '-delete', '--delete',
        '-e', '--eval', '-c', '--command',
        '--system', '--privileged', '--root'
    }
    
    # Shell metacharacters
    SHELL_METACHARACTERS = set('|;&$`\\!><(){}[]\'\"*?~#')
    
    def __init__(
        self,
        allowed_commands: Set[str] = None,
        blocked_commands: Set[str] = None,
        require_allowlist: bool = True,
        allow_args: bool = True
    ):
        """
        Initialize the command validator.
        
        Args:
            allowed_commands: Set of allowed command names (whitelist)
            blocked_commands: Additional commands to block
            require_allowlist: If True, only allowed commands can run
            allow_args: Whether to allow command arguments
        """
        self.allowed_commands = set(allowed_commands) if allowed_commands else set()
        self.blocked_commands = self.DANGEROUS_COMMANDS.copy()
        if blocked_commands:
            self.blocked_commands.update(blocked_commands)
        self.require_allowlist = require_allowlist
        self.allow_args = allow_args
        
        # Compile patterns
        self.injection_patterns = [
            (re.compile(p, re.IGNORECASE), desc) 
            for p, desc in self.INJECTION_PATTERNS
        ]
    
    def validate(self, command: str) -> CommandValidationResult:
        """
        Validate a shell command.
        
        Args:
            command: Shell command string to validate
            
        Returns:
            CommandValidationResult with validation details
        """
        findings = []
        risk_level = "none"
        parsed = []
        
        # Check for injection patterns first (before parsing)
        for pattern, desc in self.injection_patterns:
            if pattern.search(command):
                findings.append(f"Command injection pattern: {desc}")
                risk_level = "critical"
        
        # Check for shell metacharacters
        meta_found = set(c for c in command if c in self.SHELL_METACHARACTERS)
        if meta_found:
            findings.append(f"Shell metacharacters detected: {meta_found}")
            if risk_level == "none":
                risk_level = "high"
        
        # Try to parse the command
        try:
            parsed = shlex.split(command)
        except ValueError as e:
            findings.append(f"Command parsing failed: {e}")
            if risk_level in ["none", "low"]:
                risk_level = "medium"
            parsed = command.split()
        
        if not parsed:
            findings.append("Empty command")
            return CommandValidationResult(
                is_safe=False,
                risk_level="low",
                findings=findings,
                parsed_command=[],
                recommendation="BLOCK: Empty command"
            )
        
        # Get the base command
        base_command = parsed[0].lower()
        
        # Strip path from command
        if '/' in base_command:
            base_command = base_command.split('/')[-1]
        if '\\' in base_command:
            base_command = base_command.split('\\')[-1]
        
        # Check blocked commands
        if base_command in self.blocked_commands:
            findings.append(f"Blocked command: {base_command}")
            risk_level = "critical"
        
        # Check allowlist
        if self.require_allowlist and self.allowed_commands:
            if base_command not in self.allowed_commands:
                findings.append(f"Command '{base_command}' not in allowlist")
                if risk_level in ["none", "low"]:
                    risk_level = "high"
        
        # Check arguments if present
        if len(parsed) > 1 and self.allow_args:
            args = parsed[1:]
            for arg in args:
                arg_lower = arg.lower()
                
                # Check dangerous arguments
                if arg_lower in self.DANGEROUS_ARGS:
                    findings.append(f"Dangerous argument: {arg}")
                    if risk_level in ["none", "low"]:
                        risk_level = "high"
                
                # Check for path traversal in arguments
                if '..' in arg:
                    findings.append(f"Path traversal in argument: {arg}")
                    if risk_level in ["none", "low", "medium"]:
                        risk_level = "high"
        elif len(parsed) > 1 and not self.allow_args:
            findings.append("Arguments not allowed")
            if risk_level == "none":
                risk_level = "medium"
        
        # Determine if safe
        is_safe = risk_level in ["none", "low"]
        
        if not findings:
            findings.append(f"Command '{base_command}' passed validation")
        
        # Generate recommendation
        if risk_level == "critical":
            recommendation = "BLOCK: Critical command injection or dangerous command"
        elif risk_level == "high":
            recommendation = "BLOCK: High-risk command detected"
        elif risk_level == "medium":
            recommendation = "REVIEW: Command has concerning characteristics"
        elif risk_level == "low":
            recommendation = "MONITOR: Minor command concerns"
        else:
            recommendation = "ALLOW: Command is safe"
        
        return CommandValidationResult(
            is_safe=is_safe,
            risk_level=risk_level,
            findings=findings,
            parsed_command=parsed,
            recommendation=recommendation
        )
    
    def get_info(self) -> Dict:
        """Get control information"""
        return {
            "name": "Command Validator",
            "description": "Validates shell commands for injection vulnerabilities",
            "category": "System Security",
            "configuration": {
                "allowed_commands": list(self.allowed_commands),
                "blocked_commands_count": len(self.blocked_commands),
                "require_allowlist": self.require_allowlist,
                "allow_args": self.allow_args
            }
        }
