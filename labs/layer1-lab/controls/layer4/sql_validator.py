"""
AISTM Layer 4 Control: SQL Validator

Validates SQL queries to prevent injection attacks.
Essential for protecting databases from AI-generated malicious queries.

Key Features:
- SQL injection pattern detection
- Dangerous keyword blocking
- Parameter binding validation
- Query type restrictions
- Taint tracking for user input

Reference: AISTM Layer 4 Testing Guide - Backend Security section
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Set


@dataclass
class SQLValidationResult:
    """Result from SQL validation"""
    is_safe: bool
    risk_level: str  # critical, high, medium, low, none
    findings: List[str] = field(default_factory=list)
    sanitized_query: str = ""
    recommendation: str = ""


class SQLValidator:
    """
    Validates SQL queries for injection vulnerabilities.
    
    When AI generates or modifies SQL queries, this validator
    ensures they cannot be used for SQL injection attacks.
    """
    
    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        # Classic injections
        (r"'\s*(OR|AND)\s+['\"]?[0-9]+['\"]?\s*=\s*['\"]?[0-9]+", "Classic OR/AND injection"),
        (r"'\s*(OR|AND)\s+['\"]?[a-z]+['\"]?\s*=\s*['\"]?[a-z]+", "Classic string comparison injection"),
        (r"'\s*;\s*--", "Query termination with comment"),
        (r"'\s*;\s*#", "Query termination with hash comment"),
        (r"UNION\s+(ALL\s+)?SELECT", "UNION-based injection"),
        (r"SELECT\s+.*\s+FROM\s+information_schema", "Schema enumeration"),
        (r"SELECT\s+.*\s+FROM\s+mysql\.", "MySQL system table access"),
        (r"SELECT\s+.*\s+FROM\s+pg_", "PostgreSQL system table access"),
        (r"SELECT\s+.*\s+FROM\s+sys\.", "System table access"),
        
        # Time-based blind injection
        (r"SLEEP\s*\(\s*\d+\s*\)", "Sleep-based blind injection"),
        (r"WAITFOR\s+DELAY", "WAITFOR delay injection"),
        (r"BENCHMARK\s*\(", "Benchmark-based injection"),
        (r"PG_SLEEP\s*\(", "PostgreSQL sleep injection"),
        
        # Error-based injection
        (r"EXTRACTVALUE\s*\(", "ExtractValue injection"),
        (r"UPDATEXML\s*\(", "UpdateXML injection"),
        (r"EXP\s*\(\s*~", "EXP overflow injection"),
        
        # Stacked queries
        (r";\s*(DROP|DELETE|TRUNCATE|UPDATE|INSERT|ALTER|CREATE)\s", "Stacked query with destructive operation"),
        
        # Comment injection
        (r"/\*.*\*/", "Block comment injection"),
        (r"--\s*$", "Line comment at end"),
        
        # Hex/encoding bypass
        (r"0x[0-9a-fA-F]+", "Hexadecimal value"),
        (r"CHAR\s*\(\s*\d+", "CHAR function bypass"),
        (r"CONCAT\s*\(.*CHAR", "Concatenation bypass"),
        
        # Subquery attacks
        (r"\(\s*SELECT\s+", "Subquery injection"),
        
        # Out-of-band attacks
        (r"INTO\s+(OUT|DUMP)FILE", "File write attempt"),
        (r"LOAD_FILE\s*\(", "File read attempt"),
        (r"UTL_HTTP", "Oracle HTTP request"),
        (r"DBMS_LDAP", "Oracle LDAP request"),
    ]
    
    # Dangerous keywords/functions
    DANGEROUS_KEYWORDS = {
        'drop', 'truncate', 'delete', 'update', 'insert', 'alter', 'create',
        'grant', 'revoke', 'exec', 'execute', 'xp_', 'sp_',
        'load_file', 'into outfile', 'into dumpfile',
        'information_schema', 'mysql.user', 'pg_shadow',
        'benchmark', 'sleep', 'waitfor', 'pg_sleep',
        'utl_http', 'utl_file', 'dbms_', 'httpuritype'
    }
    
    # Allowed query types (default: read-only)
    DEFAULT_ALLOWED_TYPES = {'select'}
    
    def __init__(
        self,
        allow_types: Set[str] = None,
        allowed_operations: List[str] = None,
        block_keywords: Set[str] = None,
        max_query_length: int = 10000
    ):
        """
        Initialize the SQL validator.
        
        Args:
            allow_types: Allowed SQL statement types (default: SELECT only)
            allowed_operations: Alias for allow_types (for compatibility)
            block_keywords: Additional keywords to block
            max_query_length: Maximum allowed query length
        """
        # Support both parameter names
        if allowed_operations:
            self.allow_types = set(op.lower() for op in allowed_operations)
        else:
            self.allow_types = allow_types or self.DEFAULT_ALLOWED_TYPES
        self.block_keywords = self.DANGEROUS_KEYWORDS.copy()
        if block_keywords:
            self.block_keywords.update(block_keywords)
        self.max_query_length = max_query_length
        
        # Compile patterns
        self.injection_patterns = [
            (re.compile(p, re.IGNORECASE), desc) 
            for p, desc in self.SQL_INJECTION_PATTERNS
        ]
    
    def validate(self, query: str, user_inputs: List[str] = None) -> SQLValidationResult:
        """
        Validate a SQL query.
        
        Args:
            query: SQL query string to validate
            user_inputs: List of user-provided values in the query (for taint tracking)
            
        Returns:
            SQLValidationResult with validation details
        """
        user_inputs = user_inputs or []
        findings = []
        risk_level = "none"
        
        # Check query length
        if len(query) > self.max_query_length:
            findings.append(f"Query exceeds maximum length ({len(query)} > {self.max_query_length})")
            risk_level = "medium"
        
        # Get query type
        query_type = self._get_query_type(query)
        if query_type and query_type.lower() not in self.allow_types:
            findings.append(f"Query type '{query_type}' not allowed")
            risk_level = "high"
        
        # Check for injection patterns
        for pattern, desc in self.injection_patterns:
            if pattern.search(query):
                findings.append(f"SQL injection pattern detected: {desc}")
                if "blind" in desc.lower() or "union" in desc.lower():
                    risk_level = "critical"
                elif risk_level != "critical":
                    risk_level = "high"
        
        # Check for dangerous keywords
        query_lower = query.lower()
        for keyword in self.block_keywords:
            if keyword in query_lower:
                findings.append(f"Dangerous keyword detected: {keyword}")
                if risk_level == "none":
                    risk_level = "medium"
                elif risk_level == "medium":
                    risk_level = "high"
        
        # Taint tracking: check if user inputs appear unsanitized
        for user_input in user_inputs:
            if user_input in query and "'" + user_input not in query:
                # User input appears without quotes - potential injection
                findings.append(f"Unescaped user input detected in query")
                if risk_level in ["none", "low"]:
                    risk_level = "medium"
        
        # Check for multiple statements (stacked queries)
        if query.count(';') > 1:
            findings.append("Multiple statements detected (potential stacked query)")
            if risk_level in ["none", "low"]:
                risk_level = "medium"
        
        # Determine if safe
        is_safe = risk_level in ["none", "low"]
        
        if not findings:
            findings.append("Query passed SQL injection validation")
        
        # Generate recommendation
        if risk_level == "critical":
            recommendation = "BLOCK: Critical SQL injection vulnerability detected"
        elif risk_level == "high":
            recommendation = "BLOCK: High-risk SQL patterns detected"
        elif risk_level == "medium":
            recommendation = "REVIEW: Query contains concerning patterns"
        elif risk_level == "low":
            recommendation = "MONITOR: Minor concerns, use parameterized queries"
        else:
            recommendation = "ALLOW: Query appears safe"
        
        return SQLValidationResult(
            is_safe=is_safe,
            risk_level=risk_level,
            findings=findings,
            sanitized_query=self._sanitize_query(query) if not is_safe else query,
            recommendation=recommendation
        )
    
    def _get_query_type(self, query: str) -> str:
        """Extract the query type (SELECT, INSERT, etc.)"""
        query_stripped = query.strip().upper()
        for keyword in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 
                       'ALTER', 'TRUNCATE', 'GRANT', 'REVOKE', 'EXEC', 'EXECUTE']:
            if query_stripped.startswith(keyword):
                return keyword
        return ""
    
    def _sanitize_query(self, query: str) -> str:
        """Attempt to sanitize a query (for logging only, not execution)"""
        sanitized = query
        
        # Remove comments
        sanitized = re.sub(r'/\*.*?\*/', '', sanitized, flags=re.DOTALL)
        sanitized = re.sub(r'--.*$', '', sanitized, flags=re.MULTILINE)
        
        # Remove semicolons (prevent stacked queries)
        sanitized = sanitized.rstrip(';')
        
        return sanitized.strip()
    
    def get_info(self) -> Dict:
        """Get control information"""
        return {
            "name": "SQL Validator",
            "description": "Validates SQL queries for injection vulnerabilities",
            "category": "Database Security",
            "configuration": {
                "allowed_types": list(self.allow_types),
                "max_query_length": self.max_query_length,
                "blocked_keywords_count": len(self.block_keywords)
            }
        }
