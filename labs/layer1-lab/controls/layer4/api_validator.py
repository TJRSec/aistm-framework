"""
AISTM Layer 4 Control: API Validator

Prevents Server-Side Request Forgery (SSRF) attacks by validating URLs
before making external API calls. Essential for protecting internal
network resources from AI-generated requests.

Key Features:
- Internal IP detection (private ranges, localhost, metadata endpoints)
- Domain allowlisting
- Protocol validation (HTTP/HTTPS only)
- DNS rebinding protection
- Cloud metadata endpoint blocking (AWS, GCP, Azure)

Reference: AISTM Layer 4 Testing Guide - SSRF Prevention section
"""

import re
import ipaddress
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse


@dataclass
class APIValidationResult:
    """Result from API/URL validation"""
    is_safe: bool
    risk_level: str  # critical, high, medium, low, none
    ssrf_risk: bool
    url_components: Dict[str, str]
    findings: List[str] = field(default_factory=list)
    recommendation: str = ""


class APIValidator:
    """
    Validates URLs and API endpoints to prevent SSRF attacks.
    
    SSRF attacks can allow an AI system to access internal network resources,
    cloud metadata endpoints, or other sensitive systems by manipulating
    URL parameters passed to backend services.
    
    This validator implements defense-in-depth:
    1. Protocol validation (HTTP/HTTPS only)
    2. IP address validation (block private/internal ranges)
    3. Domain allowlisting/blocklisting
    4. Cloud metadata endpoint protection
    5. URL parsing validation
    """
    
    # Private IP ranges (RFC 1918 and others)
    PRIVATE_IP_RANGES = [
        "10.0.0.0/8",      # Class A private
        "172.16.0.0/12",   # Class B private
        "192.168.0.0/16",  # Class C private
        "127.0.0.0/8",     # Loopback
        "0.0.0.0/8",       # Current network
        "169.254.0.0/16",  # Link-local
        "100.64.0.0/10",   # Carrier-grade NAT
        "192.0.0.0/24",    # IETF Protocol Assignments
        "192.0.2.0/24",    # TEST-NET-1
        "198.51.100.0/24", # TEST-NET-2
        "203.0.113.0/24",  # TEST-NET-3
        "224.0.0.0/4",     # Multicast
        "240.0.0.0/4",     # Reserved
        "255.255.255.255/32",  # Broadcast
        "::1/128",         # IPv6 loopback
        "fc00::/7",        # IPv6 unique local
        "fe80::/10",       # IPv6 link-local
    ]
    
    # Cloud metadata endpoints
    CLOUD_METADATA_HOSTS = [
        "169.254.169.254",          # AWS/GCP/Azure metadata
        "metadata.google.internal", # GCP
        "metadata.azure.com",       # Azure
        "169.254.170.2",            # AWS ECS task metadata
        "fd00:ec2::254",            # AWS IPv6 metadata
    ]
    
    # Dangerous URL schemes
    DANGEROUS_SCHEMES = [
        "file", "ftp", "gopher", "ldap", "dict", "sftp",
        "tftp", "netdoc", "jar", "javascript", "data"
    ]
    
    # DNS rebinding bypass patterns
    DNS_REBINDING_PATTERNS = [
        r"\.internal\.",
        r"\.local$",
        r"\.localhost$",
        r"\.localdomain$",
        r"\.home$",
        r"\.corp$",
        r"\.lan$",
        r"^localhost\.",
        r"^127\.",
        r"^192\.168\.",
        r"^10\.",
        r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
    ]
    
    # URL encoding bypass patterns
    URL_BYPASS_PATTERNS = [
        r"%2f%2f",           # //
        r"%00",              # Null byte
        r"%25",              # % encoding
        r"@",                # Credential injection
        r"#",                # Fragment injection
        r"\\",               # Backslash
        r"%5c",              # Encoded backslash
        r"0x7f",             # Hex localhost
        r"2130706433",       # Decimal 127.0.0.1
        r"017700000001",     # Octal 127.0.0.1
        r"\[::ffff:",        # IPv6 mapped IPv4
    ]
    
    def __init__(
        self,
        allowed_domains: List[str] = None,
        blocked_domains: List[str] = None,
        blocked_ip_ranges: List[str] = None,
        allow_internal: bool = False,
        allowed_schemes: List[str] = None
    ):
        """
        Initialize the API validator.
        
        Args:
            allowed_domains: Whitelist of allowed domains (if set, only these are allowed)
            blocked_domains: Blacklist of blocked domains
            blocked_ip_ranges: Additional IP ranges to block
            allow_internal: If True, allows internal IPs (DANGEROUS - for testing only)
            allowed_schemes: Allowed URL schemes (default: http, https)
        """
        self.allowed_domains = set(allowed_domains) if allowed_domains else set()
        self.blocked_domains = set(blocked_domains) if blocked_domains else set()
        self.allow_internal = allow_internal
        self.allowed_schemes = set(allowed_schemes) if allowed_schemes else {"http", "https"}
        
        # Build blocked IP networks
        self.blocked_networks = []
        for cidr in self.PRIVATE_IP_RANGES:
            try:
                self.blocked_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass
        
        # Add custom blocked ranges
        if blocked_ip_ranges:
            for cidr in blocked_ip_ranges:
                try:
                    self.blocked_networks.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    pass
        
        # Compile regex patterns
        self.rebinding_patterns = [re.compile(p, re.IGNORECASE) for p in self.DNS_REBINDING_PATTERNS]
        self.bypass_patterns = [re.compile(p, re.IGNORECASE) for p in self.URL_BYPASS_PATTERNS]
    
    def validate(self, url: str) -> APIValidationResult:
        """
        Validate a URL for SSRF vulnerabilities.
        
        Args:
            url: The URL to validate
            
        Returns:
            APIValidationResult with safety assessment
        """
        findings = []
        risk_level = "none"
        ssrf_risk = False
        url_components = {}
        
        if not url or not isinstance(url, str):
            return APIValidationResult(
                is_safe=False,
                risk_level="high",
                ssrf_risk=False,
                url_components={},
                findings=["Empty or invalid URL"],
                recommendation="Provide a valid URL string"
            )
        
        # Normalize URL
        url = url.strip()
        
        # Check for URL bypass patterns BEFORE parsing
        for pattern in self.bypass_patterns:
            if pattern.search(url):
                findings.append(f"URL bypass pattern detected: {pattern.pattern}")
                ssrf_risk = True
                risk_level = "critical"
        
        # Parse URL
        try:
            parsed = urlparse(url)
            url_components = {
                "scheme": parsed.scheme,
                "netloc": parsed.netloc,
                "hostname": parsed.hostname or "",
                "port": str(parsed.port) if parsed.port else "",
                "path": parsed.path,
                "query": parsed.query
            }
        except Exception as e:
            return APIValidationResult(
                is_safe=False,
                risk_level="high",
                ssrf_risk=True,
                url_components={},
                findings=[f"URL parsing failed: {str(e)}"],
                recommendation="Provide a valid, well-formed URL"
            )
        
        hostname = parsed.hostname or ""
        scheme = parsed.scheme.lower()
        
        # 1. Check scheme
        if scheme not in self.allowed_schemes:
            findings.append(f"Disallowed URL scheme: {scheme}")
            if scheme in self.DANGEROUS_SCHEMES:
                ssrf_risk = True
                risk_level = "critical"
            else:
                risk_level = max(risk_level, "high", key=lambda x: ["none", "low", "medium", "high", "critical"].index(x))
        
        # 2. Check for credentials in URL
        if parsed.username or parsed.password:
            findings.append("Credentials detected in URL")
            risk_level = max(risk_level, "medium", key=lambda x: ["none", "low", "medium", "high", "critical"].index(x))
        
        # 3. Check for cloud metadata endpoints
        if hostname.lower() in [h.lower() for h in self.CLOUD_METADATA_HOSTS]:
            findings.append(f"Cloud metadata endpoint detected: {hostname}")
            ssrf_risk = True
            risk_level = "critical"
        
        # Check for metadata in path
        if "metadata" in url.lower() and ("google" in url.lower() or "aws" in url.lower() or "azure" in url.lower()):
            findings.append("Potential cloud metadata access attempt")
            ssrf_risk = True
            risk_level = "critical"
        
        # 4. Check for DNS rebinding patterns
        for pattern in self.rebinding_patterns:
            if pattern.search(hostname):
                findings.append(f"DNS rebinding pattern detected: {hostname}")
                ssrf_risk = True
                risk_level = max(risk_level, "high", key=lambda x: ["none", "low", "medium", "high", "critical"].index(x))
        
        # 5. Check if hostname is an IP address
        if hostname:
            ip_check = self._check_ip_address(hostname)
            if ip_check["is_ip"]:
                url_components["resolved_ip"] = hostname
                if ip_check["is_private"] and not self.allow_internal:
                    findings.append(f"Private IP address detected: {hostname}")
                    ssrf_risk = True
                    risk_level = "critical"
                elif ip_check["is_loopback"]:
                    findings.append(f"Loopback address detected: {hostname}")
                    ssrf_risk = True
                    risk_level = "critical"
        
        # 6. Check domain allowlist
        if self.allowed_domains:
            domain_allowed = False
            for allowed in self.allowed_domains:
                if hostname == allowed or hostname.endswith(f".{allowed}"):
                    domain_allowed = True
                    break
            if not domain_allowed:
                findings.append(f"Domain not in allowlist: {hostname}")
                risk_level = max(risk_level, "medium", key=lambda x: ["none", "low", "medium", "high", "critical"].index(x))
        
        # 7. Check domain blocklist
        for blocked in self.blocked_domains:
            if hostname == blocked or hostname.endswith(f".{blocked}"):
                findings.append(f"Blocked domain: {hostname}")
                ssrf_risk = True
                risk_level = max(risk_level, "high", key=lambda x: ["none", "low", "medium", "high", "critical"].index(x))
        
        # 8. Check for port scanning patterns
        common_internal_ports = {22, 23, 25, 53, 110, 135, 139, 143, 389, 445, 636, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017}
        if parsed.port and parsed.port in common_internal_ports and ssrf_risk:
            findings.append(f"Suspicious port access with SSRF risk: {parsed.port}")
            risk_level = "critical"
        
        # Determine safety
        is_safe = risk_level in ["none", "low"] and not ssrf_risk
        
        # Generate recommendation
        if ssrf_risk:
            recommendation = "BLOCK: High risk of SSRF attack. Do not make this request."
        elif risk_level == "high":
            recommendation = "REVIEW: URL has suspicious characteristics. Verify before proceeding."
        elif risk_level == "medium":
            recommendation = "CAUTION: URL may have security implications. Consider alternatives."
        elif risk_level == "low":
            recommendation = "LOW RISK: Minor concerns detected. Generally safe to proceed."
        else:
            recommendation = "SAFE: No security concerns detected."
        
        if not findings:
            findings.append("URL passed all security checks")
        
        return APIValidationResult(
            is_safe=is_safe,
            risk_level=risk_level,
            ssrf_risk=ssrf_risk,
            url_components=url_components,
            findings=findings,
            recommendation=recommendation
        )
    
    def _check_ip_address(self, hostname: str) -> Dict:
        """
        Check if hostname is an IP address and its classification.
        
        Handles various IP representations:
        - Standard dotted decimal (127.0.0.1)
        - Decimal (2130706433)
        - Octal (0177.0.0.01)
        - Hexadecimal (0x7f.0.0.1)
        - IPv6 (::1, ::ffff:127.0.0.1)
        """
        result = {
            "is_ip": False,
            "is_private": False,
            "is_loopback": False,
            "ip_version": None
        }
        
        try:
            # Try to parse as IP address
            ip = ipaddress.ip_address(hostname)
            result["is_ip"] = True
            result["ip_version"] = ip.version
            result["is_loopback"] = ip.is_loopback
            result["is_private"] = ip.is_private or ip.is_reserved or ip.is_link_local
            
            # Check against blocked networks
            for network in self.blocked_networks:
                if ip in network:
                    result["is_private"] = True
                    break
            
            return result
        except ValueError:
            pass
        
        # Try to handle alternative IP representations
        # Decimal representation (e.g., 2130706433 = 127.0.0.1)
        try:
            if hostname.isdigit():
                decimal_ip = int(hostname)
                if 0 <= decimal_ip <= 4294967295:  # Valid IPv4 range
                    ip = ipaddress.ip_address(decimal_ip)
                    result["is_ip"] = True
                    result["ip_version"] = 4
                    result["is_loopback"] = ip.is_loopback
                    result["is_private"] = ip.is_private or ip.is_reserved
                    return result
        except (ValueError, OverflowError):
            pass
        
        # Octal representation (e.g., 0177.0.0.01)
        if "." in hostname:
            try:
                parts = hostname.split(".")
                decimal_parts = []
                for part in parts:
                    if part.startswith("0x"):
                        decimal_parts.append(int(part, 16))
                    elif part.startswith("0") and len(part) > 1:
                        decimal_parts.append(int(part, 8))
                    else:
                        decimal_parts.append(int(part))
                
                if len(decimal_parts) == 4 and all(0 <= p <= 255 for p in decimal_parts):
                    ip_str = ".".join(str(p) for p in decimal_parts)
                    ip = ipaddress.ip_address(ip_str)
                    result["is_ip"] = True
                    result["ip_version"] = 4
                    result["is_loopback"] = ip.is_loopback
                    result["is_private"] = ip.is_private or ip.is_reserved
                    return result
            except (ValueError, IndexError):
                pass
        
        return result
    
    def get_info(self) -> Dict:
        """Get information about this control"""
        return {
            "name": "API Validator",
            "description": "Prevents SSRF attacks by validating URLs and blocking access to internal networks",
            "category": "Network Security",
            "detects": [
                "Private IP access",
                "Cloud metadata endpoints",
                "DNS rebinding attempts",
                "URL encoding bypasses",
                "Internal service access"
            ],
            "configuration": {
                "allowed_domains": list(self.allowed_domains),
                "blocked_domains": list(self.blocked_domains),
                "allowed_schemes": list(self.allowed_schemes),
                "allow_internal": self.allow_internal
            }
        }


# Convenience function for quick validation
def validate_url(url: str, allowed_domains: List[str] = None) -> APIValidationResult:
    """
    Quick URL validation with default settings.
    
    Args:
        url: URL to validate
        allowed_domains: Optional domain whitelist
        
    Returns:
        APIValidationResult
    """
    validator = APIValidator(allowed_domains=allowed_domains)
    return validator.validate(url)
