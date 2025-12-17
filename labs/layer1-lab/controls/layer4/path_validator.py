"""
AISTM Layer 4 Control: Path Validator

Validates file paths to prevent directory traversal attacks.
Essential for protecting the file system from AI-generated malicious paths.

Key Features:
- Path traversal detection
- Base directory enforcement
- Symlink resolution
- Extension allowlisting
- Path normalization

Reference: AISTM Layer 4 Testing Guide - Backend Security section
"""

import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Set


@dataclass
class PathValidationResult:
    """Result from path validation"""
    is_safe: bool
    risk_level: str  # critical, high, medium, low, none
    findings: List[str] = field(default_factory=list)
    normalized_path: str = ""
    recommendation: str = ""


class PathValidator:
    """
    Validates file paths for directory traversal vulnerabilities.
    
    When AI generates or processes file paths, this validator
    ensures they cannot be used to access unauthorized files.
    """
    
    # Path traversal patterns
    TRAVERSAL_PATTERNS = [
        # Basic traversal
        (r'\.\./', "Unix path traversal (../)"),
        (r'\.\.\\', "Windows path traversal (..\\)"),
        (r'%2e%2e[/\\]', "URL-encoded traversal (%2e%2e)"),
        (r'%252e%252e[/\\]', "Double URL-encoded traversal"),
        (r'\.\.%00', "Null byte with traversal"),
        (r'\.\.%c0%af', "Overlong UTF-8 traversal"),
        (r'\.\.%c1%9c', "Overlong UTF-8 backslash traversal"),
        
        # Encoded variants
        (r'%2e%2e%2f', "Full URL-encoded ../"),
        (r'%2e%2e%5c', "Full URL-encoded ..\\"),
        (r'\.%2e/', "Mixed encoding traversal"),
        (r'%2e\./', "Mixed encoding traversal"),
        
        # Unicode normalization attacks
        (r'\uff0e\uff0e/', "Unicode fullwidth dots"),
        (r'\.\.／', "Unicode fullwidth slash"),
        
        # Windows-specific
        (r'\.\.;/', "Tomcat-style bypass"),
        (r'[a-zA-Z]:[\\/]', "Absolute Windows path"),
    ]
    
    # Dangerous path components
    DANGEROUS_COMPONENTS = {
        '/etc/', '/proc/', '/sys/', '/dev/',
        '/root/', '/home/', '/var/log/',
        'C:\\Windows\\', 'C:\\System32\\',
        'C:\\Users\\', 'C:\\Program Files',
        '.ssh/', '.aws/', '.env',
        'passwd', 'shadow', 'id_rsa',
        'web.config', '.htaccess', '.htpasswd'
    }
    
    # Default allowed extensions
    DEFAULT_ALLOWED_EXTENSIONS = {
        '.txt', '.md', '.json', '.csv', '.xml',
        '.jpg', '.jpeg', '.png', '.gif', '.svg',
        '.pdf', '.html', '.css', '.js'
    }
    
    def __init__(
        self,
        base_directory: str = None,
        allowed_base_paths: List[str] = None,
        allowed_extensions: Set[str] = None,
        allow_absolute: bool = False,
        resolve_symlinks: bool = True
    ):
        """
        Initialize the path validator.
        
        Args:
            base_directory: Base directory all paths must be within
            allowed_base_paths: List of allowed base paths (alternative to base_directory)
            allowed_extensions: Set of allowed file extensions
            allow_absolute: Whether to allow absolute paths
            resolve_symlinks: Whether to resolve symlinks for validation
        """
        # Support both single base_directory and list of allowed_base_paths
        if allowed_base_paths and not base_directory:
            base_directory = allowed_base_paths[0] if allowed_base_paths else None
        self.base_directory = os.path.abspath(base_directory) if base_directory else None
        self.allowed_base_paths = [os.path.abspath(p) for p in (allowed_base_paths or [])]
        
        # Handle allowed_extensions as list or set
        if allowed_extensions and isinstance(allowed_extensions, list):
            self.allowed_extensions = set(allowed_extensions)
        else:
            self.allowed_extensions = allowed_extensions or self.DEFAULT_ALLOWED_EXTENSIONS
        self.allow_absolute = allow_absolute
        self.resolve_symlinks = resolve_symlinks
        
        # Compile patterns
        self.traversal_patterns = [
            (re.compile(p, re.IGNORECASE), desc) 
            for p, desc in self.TRAVERSAL_PATTERNS
        ]
    
    def validate(self, path: str) -> PathValidationResult:
        """
        Validate a file path.
        
        Args:
            path: File path to validate
            
        Returns:
            PathValidationResult with validation details
        """
        findings = []
        risk_level = "none"
        
        # Normalize path for analysis
        try:
            normalized = os.path.normpath(path)
        except (ValueError, OSError) as e:
            findings.append(f"Path normalization failed: {e}")
            return PathValidationResult(
                is_safe=False,
                risk_level="critical",
                findings=findings,
                recommendation="BLOCK: Invalid path format"
            )
        
        # Check for traversal patterns
        for pattern, desc in self.traversal_patterns:
            if pattern.search(path):
                findings.append(f"Path traversal detected: {desc}")
                risk_level = "critical"
        
        # Check for null bytes
        if '\x00' in path:
            findings.append("Null byte injection detected")
            risk_level = "critical"
        
        # Check absolute path
        if os.path.isabs(path) and not self.allow_absolute:
            findings.append("Absolute path not allowed")
            if risk_level == "none":
                risk_level = "high"
        
        # Check for dangerous components
        path_lower = path.lower()
        for dangerous in self.DANGEROUS_COMPONENTS:
            if dangerous.lower() in path_lower:
                findings.append(f"Dangerous path component: {dangerous}")
                if risk_level in ["none", "low"]:
                    risk_level = "high"
        
        # Check extension
        _, ext = os.path.splitext(path)
        if ext and ext.lower() not in self.allowed_extensions:
            findings.append(f"Extension '{ext}' not in allowlist")
            if risk_level == "none":
                risk_level = "medium"
        
        # Check base directory constraint
        if self.base_directory:
            # Resolve the full path
            if os.path.isabs(normalized):
                full_path = normalized
            else:
                full_path = os.path.abspath(os.path.join(self.base_directory, normalized))
            
            # Resolve symlinks if configured
            if self.resolve_symlinks:
                try:
                    # Use realpath to resolve symlinks
                    real_path = os.path.realpath(full_path)
                    real_base = os.path.realpath(self.base_directory)
                    
                    if not real_path.startswith(real_base):
                        findings.append("Path escapes base directory (after symlink resolution)")
                        risk_level = "critical"
                except (OSError, ValueError):
                    # Path doesn't exist yet - check without symlink resolution
                    pass
            
            # Also check normalized path
            if not full_path.startswith(self.base_directory):
                findings.append("Path escapes base directory")
                risk_level = "critical"
        
        # Additional Windows checks
        if os.name == 'nt':
            # Check for alternate data streams
            if ':' in path[2:]:  # Skip drive letter
                findings.append("Alternate data stream detected")
                if risk_level in ["none", "low", "medium"]:
                    risk_level = "high"
            
            # Check for reserved names
            reserved = {'CON', 'PRN', 'AUX', 'NUL', 
                       'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
                       'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'}
            basename = os.path.basename(path).upper().split('.')[0]
            if basename in reserved:
                findings.append(f"Windows reserved name: {basename}")
                if risk_level in ["none", "low"]:
                    risk_level = "medium"
        
        # Determine if safe
        is_safe = risk_level in ["none", "low"]
        
        if not findings:
            findings.append("Path passed validation")
        
        # Generate recommendation
        if risk_level == "critical":
            recommendation = "BLOCK: Critical path traversal vulnerability"
        elif risk_level == "high":
            recommendation = "BLOCK: High-risk path detected"
        elif risk_level == "medium":
            recommendation = "REVIEW: Path has concerning characteristics"
        elif risk_level == "low":
            recommendation = "MONITOR: Minor path concerns"
        else:
            recommendation = "ALLOW: Path is safe"
        
        return PathValidationResult(
            is_safe=is_safe,
            risk_level=risk_level,
            findings=findings,
            normalized_path=normalized,
            recommendation=recommendation
        )
    
    def get_info(self) -> Dict:
        """Get control information"""
        return {
            "name": "Path Validator",
            "description": "Validates file paths for directory traversal vulnerabilities",
            "category": "File System Security",
            "configuration": {
                "base_directory": self.base_directory,
                "allowed_extensions": list(self.allowed_extensions),
                "allow_absolute": self.allow_absolute,
                "resolve_symlinks": self.resolve_symlinks
            }
        }
