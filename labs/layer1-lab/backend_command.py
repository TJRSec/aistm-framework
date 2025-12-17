"""
Backend Command Execution for Layer 4 Testing

This module provides a sandboxed command execution environment that demonstrates
what happens when command injection attacks succeed against a vulnerable system.
"""

import subprocess
import os
import re
from pathlib import Path

# Sandboxed working directory
SANDBOX_DIR = Path(__file__).parent / "command_sandbox"
SANDBOX_DIR.mkdir(exist_ok=True)


def initialize_sandbox():
    """
    Creates a safe sandbox environment with sample files for command execution testing.
    """
    # Create sample files
    (SANDBOX_DIR / "users.txt").write_text("alice\nbob\ncharlie\nadmin\n")
    (SANDBOX_DIR / "config.ini").write_text("[database]\nhost=localhost\nport=5432\n")
    (SANDBOX_DIR / "secrets.env").write_text("API_KEY=sk_test_123456\nDB_PASSWORD=super_secret\n")
    (SANDBOX_DIR / "README.md").write_text("# Test Sandbox\nThis directory is used for command execution testing.\n")
    
    print(f"✅ Command sandbox created at: {SANDBOX_DIR}")


def execute_command_vulnerable(command: str) -> dict:
    """
    INTENTIONALLY VULNERABLE: Executes shell commands with NO validation.
    This demonstrates what happens when command injection succeeds.
    
    Args:
        command: Shell command string
        
    Returns:
        dict with 'success', 'output', 'error', and 'vulnerability' fields
    """
    try:
        # VULNERABLE: Direct shell execution
        result = subprocess.run(
            command,
            shell=True,  # DANGEROUS: Allows command chaining with ; | && ||
            cwd=str(SANDBOX_DIR),
            capture_output=True,
            text=True,
            timeout=5
        )
        
        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr if result.returncode != 0 else None,
            "return_code": result.returncode,
            "vulnerability": "⚠️ VULNERABLE: Direct shell execution with no validation!",
            "impact": "Attacker can execute arbitrary commands when controls are disabled."
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Command timed out (possible denial of service)",
            "vulnerability": "Command execution attempted"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "vulnerability": "Command execution attempted"
        }


def execute_command_safe(command: str, allowed_commands: list = None) -> dict:
    """
    SAFE VERSION: Uses command allowlist and validation.
    This is what Layer 4 security looks like.
    
    Args:
        command: Command string
        allowed_commands: List of allowed command names
        
    Returns:
        dict with command results
    """
    if allowed_commands is None:
        allowed_commands = ['ls', 'dir', 'cat', 'type', 'echo', 'pwd']
    
    # Parse command
    parts = command.split()
    if not parts:
        return {"success": False, "error": "Empty command", "blocked_by": "Input validation"}
    
    cmd_name = parts[0]
    
    # Validate against allowlist
    if cmd_name not in allowed_commands:
        return {
            "success": False,
            "error": f"Command '{cmd_name}' not allowed",
            "blocked_by": "Command allowlist validation",
            "security": "✅ BLOCKED: Command not in allowlist"
        }
    
    # Block dangerous characters
    dangerous_chars = [';', '|', '&', '$', '`', '\n', '>', '<', '(', ')']
    for char in dangerous_chars:
        if char in command:
            return {
                "success": False,
                "error": f"Dangerous character '{char}' detected",
                "blocked_by": "Character validation",
                "security": "✅ BLOCKED: Command injection attempt detected"
            }
    
    try:
        # Execute with shell=False (safer)
        result = subprocess.run(
            parts,
            shell=False,  # SAFE: No shell metacharacter interpretation
            cwd=str(SANDBOX_DIR),
            capture_output=True,
            text=True,
            timeout=5
        )
        
        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr if result.returncode != 0 else None,
            "security": "✅ SECURE: Command validated against allowlist"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def validate_path(path: str) -> dict:
    """
    Validates file paths for path traversal attacks.
    
    Args:
        path: File path string
        
    Returns:
        dict with validation results
    """
    # Check for path traversal sequences
    dangerous_patterns = ['..', '~', '/etc/', '/root/', 'C:\\Windows', '/sys/', '/proc/']
    
    for pattern in dangerous_patterns:
        if pattern in path:
            return {
                "valid": False,
                "error": f"Path traversal detected: {pattern}",
                "blocked_by": "Path validation",
                "security": "✅ BLOCKED: Path traversal attempt"
            }
    
    # Resolve to absolute path and check if it's within sandbox
    try:
        abs_path = (SANDBOX_DIR / path).resolve()
        if not str(abs_path).startswith(str(SANDBOX_DIR.resolve())):
            return {
                "valid": False,
                "error": "Path outside sandbox",
                "blocked_by": "Sandbox boundary check",
                "security": "✅ BLOCKED: Path escapes sandbox"
            }
    except Exception as e:
        return {
            "valid": False,
            "error": str(e),
            "blocked_by": "Path resolution"
        }
    
    return {
        "valid": True,
        "resolved_path": str(abs_path),
        "security": "✅ Path validated"
    }


if __name__ == "__main__":
    # Initialize sandbox
    initialize_sandbox()
    
    print("\n" + "="*60)
    print("TESTING COMMAND INJECTION VULNERABILITY")
    print("="*60)
    
    # Safe command
    print("\n1. Safe Command (ls):")
    result = execute_command_safe("ls")
    print(f"   Result: {result['success']}")
    print(f"   Output: {result.get('output', '')[:100]}")
    
    # Blocked command
    print("\n2. Blocked Command (rm -rf):")
    result = execute_command_safe("rm -rf /")
    print(f"   Result: {result['success']}")
    print(f"   Error: {result.get('error', '')}")
    print(f"   {result.get('security', '')}")
    
    # Vulnerable - normal command
    print("\n3. Vulnerable Command (Normal):")
    if os.name == 'nt':  # Windows
        result = execute_command_vulnerable("dir")
    else:  # Unix
        result = execute_command_vulnerable("ls -la")
    print(f"   Result: {result['success']}")
    
    # Vulnerable - command injection
    print("\n4. Vulnerable Command (Injection - ; whoami):")
    if os.name == 'nt':
        result = execute_command_vulnerable("dir & whoami")
    else:
        result = execute_command_vulnerable("ls; whoami")
    print(f"   Result: {result['success']}")
    print(f"   Output contains username: {'Yes' if result.get('output') else 'No'}")
    print(f"   {result.get('vulnerability', '')}")
    
    # Path traversal
    print("\n5. Path Traversal Test (../../../etc/passwd):")
    result = validate_path("../../../etc/passwd")
    print(f"   Valid: {result['valid']}")
    print(f"   {result.get('security', '')}")
    
    print("\n" + "="*60)
