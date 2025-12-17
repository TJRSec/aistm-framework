"""
Multi-turn Attack Tracker Control Module

This module tracks conversation patterns across multiple turns to detect:
- Fragmentation attacks (malicious content split across messages)
- Crescendo attacks (gradually escalating requests)
- Context poisoning (slowly building malicious context)
- Trust building attacks (establishing rapport before malicious request)
- Persona persistence (maintaining jailbreak personas across turns)

This is a stateful control that maintains session history.
"""

import time
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from collections import defaultdict


@dataclass
class TurnAnalysis:
    """Analysis of a single conversation turn"""
    message: str
    timestamp: float
    risk_indicators: List[str] = field(default_factory=list)
    intent_category: str = "normal"
    escalation_score: float = 0.0


@dataclass
class MultiTurnResult:
    """Result of multi-turn analysis"""
    current_message: str
    session_id: str
    turn_count: int
    is_suspicious: bool = False
    attack_type: Optional[str] = None
    cumulative_risk: float = 0.0
    pattern_detected: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    should_block: bool = False
    block_reason: str = ""
    recommendation: str = ""


class MultiTurnTracker:
    """
    Tracks conversation patterns across multiple turns to detect
    multi-turn attack patterns.
    """
    
    def __init__(self,
                 max_history: int = 20,
                 session_timeout: int = 3600,
                 fragmentation_threshold: float = 0.7,
                 escalation_threshold: float = 0.6,
                 block_on_detection: bool = False):
        """
        Initialize the multi-turn tracker.
        
        Args:
            max_history: Maximum turns to track per session
            session_timeout: Session timeout in seconds
            fragmentation_threshold: Threshold for fragmentation detection
            escalation_threshold: Threshold for escalation detection
            block_on_detection: Whether to block on pattern detection
        """
        self.max_history = max_history
        self.session_timeout = session_timeout
        self.fragmentation_threshold = fragmentation_threshold
        self.escalation_threshold = escalation_threshold
        self.block_on_detection = block_on_detection
        
        # Session storage: session_id -> list of TurnAnalysis
        self.sessions: Dict[str, List[TurnAnalysis]] = defaultdict(list)
        self.session_timestamps: Dict[str, float] = {}
        
        # Fragmentation detection patterns
        self.fragment_keywords = [
            ['ignore', 'previous', 'instructions'],
            ['forget', 'your', 'rules'],
            ['reveal', 'system', 'prompt'],
            ['bypass', 'safety', 'filters'],
            ['disable', 'content', 'moderation'],
            ['you', 'are', 'now', 'unrestricted']
        ]
        
        # Escalation categories (from benign to dangerous)
        self.escalation_categories = {
            'greeting': 0.0,
            'general_question': 0.1,
            'technical_question': 0.2,
            'security_discussion': 0.4,
            'hypothetical_harmful': 0.6,
            'indirect_harmful': 0.7,
            'direct_harmful': 0.9,
            'jailbreak_attempt': 1.0
        }
        
        # Trust building phrases
        self.trust_phrases = [
            "you've been so helpful",
            "we have such a good rapport",
            "i trust you",
            "as friends",
            "just between us",
            "surely you can make an exception",
            "you're different from other AIs"
        ]
        
        # Persona persistence patterns
        self.persona_patterns = [
            r'remember.*you.*agreed.*to.*be',
            r'continue.*as.*dan',
            r'stay.*in.*character',
            r'you.*promised.*to',
            r'don\'t.*break.*character',
            r'as.*we.*discussed',
            r'like.*before.*help.*me'
        ]
    
    def analyze(self, message: str, session_id: str) -> MultiTurnResult:
        """
        Analyze a message in the context of the conversation history.
        
        Args:
            message: Current message to analyze
            session_id: Unique session identifier
            
        Returns:
            MultiTurnResult with analysis
        """
        current_time = time.time()
        
        # Clean up expired sessions
        self._cleanup_expired_sessions(current_time)
        
        # Initialize result
        result = MultiTurnResult(
            current_message=message,
            session_id=session_id,
            turn_count=len(self.sessions[session_id]) + 1
        )
        
        # Analyze current turn
        turn_analysis = self._analyze_turn(message)
        
        # Get conversation history
        history = self.sessions[session_id]
        
        # Run multi-turn pattern detection
        self._detect_fragmentation(message, history, result)
        self._detect_escalation(turn_analysis, history, result)
        self._detect_context_poisoning(message, history, result)
        self._detect_trust_building(message, history, result)
        self._detect_persona_persistence(message, history, result)
        
        # Calculate cumulative risk
        result.cumulative_risk = self._calculate_cumulative_risk(history, turn_analysis)
        
        # Determine if suspicious
        result.is_suspicious = (
            len(result.pattern_detected) > 0 or
            result.cumulative_risk > self.escalation_threshold
        )
        
        # Update session history
        history.append(turn_analysis)
        if len(history) > self.max_history:
            history.pop(0)
        self.session_timestamps[session_id] = current_time
        
        # Block decision
        if self.block_on_detection and result.is_suspicious:
            result.should_block = True
            result.block_reason = f"Multi-turn attack pattern: {result.attack_type or 'cumulative risk'}"
        
        return result
    
    def _analyze_turn(self, message: str) -> TurnAnalysis:
        """Analyze a single turn for risk indicators"""
        analysis = TurnAnalysis(
            message=message,
            timestamp=time.time()
        )
        
        message_lower = message.lower()
        
        # Categorize intent
        if any(w in message_lower for w in ['hello', 'hi', 'hey', 'good morning']):
            analysis.intent_category = 'greeting'
        elif any(w in message_lower for w in ['hack', 'exploit', 'attack', 'bypass']):
            analysis.intent_category = 'direct_harmful'
        elif any(w in message_lower for w in ['hypothetically', 'theoretically', 'fictional']):
            analysis.intent_category = 'hypothetical_harmful'
        elif any(w in message_lower for w in ['ignore', 'forget', 'disregard', 'pretend']):
            analysis.intent_category = 'jailbreak_attempt'
        elif any(w in message_lower for w in ['security', 'vulnerability', 'penetration']):
            analysis.intent_category = 'security_discussion'
        else:
            analysis.intent_category = 'general_question'
        
        analysis.escalation_score = self.escalation_categories.get(
            analysis.intent_category, 0.3
        )
        
        return analysis
    
    def _detect_fragmentation(self, message: str, history: List[TurnAnalysis], 
                              result: MultiTurnResult):
        """Detect fragmented injection across turns"""
        if not history:
            return
        
        # Combine recent messages
        recent_messages = [t.message.lower() for t in history[-5:]] + [message.lower()]
        combined = ' '.join(recent_messages)
        
        for keyword_sequence in self.fragment_keywords:
            # Check if all keywords appear across messages
            all_found = all(kw in combined for kw in keyword_sequence)
            
            if all_found:
                # Check if they're spread across different messages
                keyword_locations = []
                for kw in keyword_sequence:
                    for i, msg in enumerate(recent_messages):
                        if kw in msg:
                            keyword_locations.append(i)
                            break
                
                # If keywords span multiple messages, it's fragmentation
                if len(set(keyword_locations)) >= 2:
                    result.pattern_detected.append("fragmentation")
                    result.attack_type = "fragmentation"
                    result.findings.append(
                        f"Fragmented injection detected: '{' '.join(keyword_sequence)}' "
                        f"split across {len(set(keyword_locations))} messages"
                    )
                    return
    
    def _detect_escalation(self, current: TurnAnalysis, history: List[TurnAnalysis],
                           result: MultiTurnResult):
        """Detect gradual escalation (crescendo attack)"""
        if len(history) < 3:
            return
        
        # Get escalation scores for recent turns
        recent_scores = [t.escalation_score for t in history[-5:]] + [current.escalation_score]
        
        # Check for consistent upward trend
        increases = sum(1 for i in range(1, len(recent_scores)) 
                       if recent_scores[i] > recent_scores[i-1])
        
        if increases >= 3 and current.escalation_score > self.escalation_threshold:
            result.pattern_detected.append("escalation")
            result.attack_type = "crescendo"
            result.findings.append(
                f"Escalation pattern detected: risk increased across {increases} turns "
                f"to {current.escalation_score:.2f}"
            )
    
    def _detect_context_poisoning(self, message: str, history: List[TurnAnalysis],
                                   result: MultiTurnResult):
        """Detect context poisoning attempts"""
        poison_phrases = [
            "let's establish",
            "in this context",
            "for our conversation",
            "from now on",
            "going forward",
            "rules are suspended",
            "normal rules don't apply",
            "educational purposes"
        ]
        
        message_lower = message.lower()
        recent_messages = [t.message.lower() for t in history[-3:]]
        
        # Check current message
        for phrase in poison_phrases:
            if phrase in message_lower:
                result.pattern_detected.append("context_poisoning")
                result.attack_type = "context_poisoning"
                result.findings.append(f"Context poisoning phrase: '{phrase}'")
                return
        
        # Check if previous messages set up context
        for msg in recent_messages:
            for phrase in poison_phrases:
                if phrase in msg:
                    # And current message tries to exploit it
                    exploit_phrases = ['now', 'so', 'therefore', 'given that', 'help me']
                    if any(ep in message_lower for ep in exploit_phrases):
                        result.pattern_detected.append("context_poisoning")
                        result.attack_type = "context_poisoning"
                        result.findings.append("Exploiting previously poisoned context")
                        return
    
    def _detect_trust_building(self, message: str, history: List[TurnAnalysis],
                                result: MultiTurnResult):
        """Detect trust building before malicious request"""
        message_lower = message.lower()
        
        for phrase in self.trust_phrases:
            if phrase in message_lower:
                # Check if followed by request
                request_indicators = ['can you', 'could you', 'would you', 'please', 'help me']
                if any(ind in message_lower for ind in request_indicators):
                    result.pattern_detected.append("trust_building")
                    result.attack_type = "trust_building"
                    result.findings.append(
                        f"Trust building phrase '{phrase}' followed by request"
                    )
                    return
    
    def _detect_persona_persistence(self, message: str, history: List[TurnAnalysis],
                                     result: MultiTurnResult):
        """Detect attempts to maintain jailbreak personas across turns"""
        message_lower = message.lower()
        
        for pattern in self.persona_patterns:
            if re.search(pattern, message_lower):
                result.pattern_detected.append("persona_persistence")
                result.attack_type = "persona_persistence"
                result.findings.append("Attempt to maintain/recall jailbreak persona")
                return
    
    def _calculate_cumulative_risk(self, history: List[TurnAnalysis], 
                                    current: TurnAnalysis) -> float:
        """Calculate cumulative risk score"""
        if not history:
            return current.escalation_score
        
        # Weighted average with recent turns weighted more heavily
        weights = [0.5 ** i for i in range(len(history), 0, -1)]
        scores = [t.escalation_score for t in history]
        
        weighted_sum = sum(w * s for w, s in zip(weights, scores))
        weighted_sum += current.escalation_score * 2  # Current turn weighted double
        
        total_weight = sum(weights) + 2
        return weighted_sum / total_weight
    
    def _cleanup_expired_sessions(self, current_time: float):
        """Remove expired sessions"""
        expired = [
            sid for sid, ts in self.session_timestamps.items()
            if current_time - ts > self.session_timeout
        ]
        for sid in expired:
            del self.sessions[sid]
            del self.session_timestamps[sid]
    
    def clear_session(self, session_id: str):
        """Manually clear a session"""
        if session_id in self.sessions:
            del self.sessions[session_id]
        if session_id in self.session_timestamps:
            del self.session_timestamps[session_id]
    
    def get_session_summary(self, session_id: str) -> Dict:
        """Get summary of a session's history"""
        history = self.sessions.get(session_id, [])
        return {
            "turn_count": len(history),
            "average_risk": sum(t.escalation_score for t in history) / len(history) if history else 0,
            "categories": [t.intent_category for t in history],
            "max_risk": max((t.escalation_score for t in history), default=0)
        }
