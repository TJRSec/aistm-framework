"""
Rate Limiter Control Module

This module implements request rate limiting to prevent:
- Denial of service attacks
- Automated attack tools
- Credential stuffing and brute force
- Resource exhaustion

Uses an in-memory token bucket algorithm for simplicity.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, Optional
from collections import defaultdict
import threading


@dataclass
class RateLimitResult:
    """Result of rate limit check"""
    allowed: bool
    current_count: int
    limit: int
    window_seconds: int
    remaining: int
    reset_time: float
    findings: list = field(default_factory=list)


class RateLimiter:
    """
    Token Bucket Rate Limiter
    
    This control limits the number of requests that can be made within
    a time window. While not directly related to prompt injection,
    rate limiting is essential Layer 1 protection that:
    
    1. Prevents automated attack tools from rapid-fire testing
    2. Limits resource consumption per user
    3. Slows down brute-force bypass attempts
    4. Protects AI API costs from abuse
    
    Implementation uses a sliding window token bucket algorithm.
    Each user/IP starts with a full bucket of tokens, and tokens
    regenerate over time.
    """
    
    def __init__(self, 
                 requests_per_minute: int = 20,
                 burst_allowance: int = 5):
        """
        Initialize the rate limiter.
        
        Args:
            requests_per_minute: Sustained request rate limit
            burst_allowance: Additional tokens for burst traffic
        """
        self.rpm = requests_per_minute
        self.burst = burst_allowance
        self.window = 60  # 1 minute window
        
        # Token bucket state per identifier
        # {identifier: {"tokens": float, "last_update": timestamp}}
        self.buckets: Dict[str, Dict] = defaultdict(
            lambda: {"tokens": self.rpm + self.burst, "last_update": time.time()}
        )
        
        # Lock for thread safety
        self.lock = threading.Lock()
        
        # Request history for analytics
        self.request_history: Dict[str, list] = defaultdict(list)
    
    def check(self, identifier: str = "default") -> RateLimitResult:
        """
        Check if a request should be allowed and consume a token.
        
        Args:
            identifier: Unique identifier (user ID, IP, session, etc.)
            
        Returns:
            RateLimitResult indicating if request is allowed
        """
        with self.lock:
            now = time.time()
            bucket = self.buckets[identifier]
            
            # Calculate token regeneration since last request
            time_passed = now - bucket["last_update"]
            tokens_to_add = time_passed * (self.rpm / self.window)
            
            # Update tokens (cap at max)
            max_tokens = self.rpm + self.burst
            bucket["tokens"] = min(max_tokens, bucket["tokens"] + tokens_to_add)
            bucket["last_update"] = now
            
            # Track request for analytics
            self._record_request(identifier, now)
            
            # Check if we have tokens available
            if bucket["tokens"] >= 1:
                bucket["tokens"] -= 1
                allowed = True
                findings = [f"Request allowed ({bucket['tokens']:.1f} tokens remaining)"]
            else:
                allowed = False
                # Calculate time until next token
                time_until_token = (1 - bucket["tokens"]) / (self.rpm / self.window)
                findings = [
                    f"Rate limit exceeded for {identifier}",
                    f"Retry after {time_until_token:.1f} seconds"
                ]
            
            # Calculate reset time (when bucket would be full)
            tokens_needed = max_tokens - bucket["tokens"]
            reset_time = now + (tokens_needed / (self.rpm / self.window))
            
            return RateLimitResult(
                allowed=allowed,
                current_count=self._get_recent_count(identifier),
                limit=self.rpm,
                window_seconds=self.window,
                remaining=int(bucket["tokens"]),
                reset_time=reset_time,
                findings=findings
            )
    
    def _record_request(self, identifier: str, timestamp: float):
        """Record request for analytics"""
        history = self.request_history[identifier]
        history.append(timestamp)
        
        # Clean old entries (keep last 5 minutes)
        cutoff = timestamp - 300
        self.request_history[identifier] = [t for t in history if t > cutoff]
    
    def _get_recent_count(self, identifier: str) -> int:
        """Get request count in current window"""
        now = time.time()
        cutoff = now - self.window
        return sum(1 for t in self.request_history[identifier] if t > cutoff)
    
    def get_stats(self, identifier: str = "default") -> Dict:
        """Get rate limit statistics for an identifier"""
        with self.lock:
            bucket = self.buckets[identifier]
            history = self.request_history[identifier]
            now = time.time()
            
            # Calculate requests in different windows
            last_minute = sum(1 for t in history if t > now - 60)
            last_5_minutes = sum(1 for t in history if t > now - 300)
            
            return {
                "identifier": identifier,
                "current_tokens": bucket["tokens"],
                "max_tokens": self.rpm + self.burst,
                "requests_last_minute": last_minute,
                "requests_last_5_minutes": last_5_minutes,
                "limit_rpm": self.rpm
            }
    
    def reset(self, identifier: str = "default"):
        """Reset rate limit for an identifier (for testing)"""
        with self.lock:
            self.buckets[identifier] = {
                "tokens": self.rpm + self.burst,
                "last_update": time.time()
            }
            self.request_history[identifier] = []
    
    def get_info(self) -> dict:
        """Return information about this control for the UI"""
        return {
            "name": "Rate Limiting",
            "description": "Limits request frequency to prevent abuse and automated attacks",
            "category": "Abuse Prevention",
            "settings": {
                "requests_per_minute": self.rpm,
                "burst_allowance": self.burst,
                "window_seconds": self.window,
                "algorithm": "Token Bucket"
            },
            "detects": [
                "Rapid automated requests",
                "Brute force attempts",
                "Resource exhaustion attacks",
                "API abuse"
            ],
            "bypasses": [
                "Distributed attacks (multiple IPs)",
                "Slow-rate attacks below threshold",
                "IP/session rotation",
                "Legitimate-looking spacing"
            ]
        }
