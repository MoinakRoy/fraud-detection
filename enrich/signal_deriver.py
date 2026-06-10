"""
Signal Derivation - Extract features and behavioral signals from requests.

Signals are facts derived from a request and its historical context.
Keep signals clearly separated from scoring logic.
"""

import logging
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Set, Optional
from collections import defaultdict, deque
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class TimeWindow:
    """Rolling time window for velocity calculations."""
    window_duration: timedelta
    max_events: int = 10000
    
    def __post_init__(self):
        self.events: deque = deque()  # (timestamp, value) tuples
    
    def add_event(self, timestamp: datetime, value: float = 1.0):
        """Add event to window."""
        self.events.append((timestamp, value))
        # Clean old events
        cutoff = timestamp - self.window_duration
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()
    
    def count(self, current_time: datetime) -> int:
        """Get count of events in window."""
        cutoff = current_time - self.window_duration
        return sum(1 for ts, _ in self.events if ts >= cutoff)
    
    def sum_values(self, current_time: datetime) -> float:
        """Get sum of values in window."""
        cutoff = current_time - self.window_duration
        return sum(val for ts, val in self.events if ts >= cutoff)


@dataclass
class BehavioralState:
    """Track behavioral patterns per IP, session, account."""
    identifier: str
    first_seen: datetime
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Time windows for velocity
    velocity_1m: TimeWindow = field(default_factory=lambda: TimeWindow(timedelta(minutes=1)))
    velocity_5m: TimeWindow = field(default_factory=lambda: TimeWindow(timedelta(minutes=5)))
    velocity_10m: TimeWindow = field(default_factory=lambda: TimeWindow(timedelta(minutes=10)))
    velocity_1h: TimeWindow = field(default_factory=lambda: TimeWindow(timedelta(hours=1)))
    
    # Cross-IP/account tracking
    ips_seen: Set[str] = field(default_factory=set)
    sessions_seen: Set[str] = field(default_factory=set)
    accounts_seen: Set[str] = field(default_factory=set)
    user_agents_seen: Set[str] = field(default_factory=set)
    ja3s_seen: Set[str] = field(default_factory=set)
    
    # Status code tracking
    status_codes: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    
    def is_new(self, max_age: timedelta = timedelta(minutes=5)) -> bool:
        """Check if this is a fresh/new identifier."""
        return datetime.now(timezone.utc) - self.first_seen < max_age


class SignalDeriver:
    """
    Derive signals from requests and behavioral state.
    
    Design:
    - Maintain separate state for IP, session, account
    - Compute signals that are facts, not judgments
    - Keep signal names consistent for rule engine
    """
    
    def __init__(self, state_retention_hours: int = 24):
        self.state_retention = timedelta(hours=state_retention_hours)
        
        # State indexed by identifier
        self.ip_state: Dict[str, BehavioralState] = {}
        self.session_state: Dict[str, BehavioralState] = {}
        self.account_state: Dict[str, BehavioralState] = {}
        
        self.ip_reputation = None  # Will be set by pipeline
        self.geo_lookup = None
    
    def derive_signals(self, request: dict, geo_lookup=None, ip_reputation=None) -> dict:
        """
        Derive all signals for a request.
        
        Returns dict of signal_name -> signal_value
        """
        signals = {}
        ts = datetime.fromisoformat(request['ts'].replace('Z', '+00:00'))
        ip = request['ip']
        session_id = request.get('session_id')
        account_id = request.get('account_id')
        
        self.geo_lookup = geo_lookup
        self.ip_reputation = ip_reputation
        
        # 1. IP Reputation Signals
        signals.update(self._derive_ip_reputation_signals(ip))
        
        # 2. Geolocation Signals
        signals.update(self._derive_geo_signals(request, ip, geo_lookup))
        
        # 3. Velocity Signals - IP
        signals.update(self._derive_ip_velocity_signals(ip, ts))
        
        # 4. Velocity Signals - Session
        signals.update(self._derive_session_velocity_signals(session_id, ts))
        
        # 5. Velocity Signals - Account
        signals.update(self._derive_account_velocity_signals(account_id, ts))
        
        # 6. Consistency Signals
        signals.update(self._derive_consistency_signals(request, ip, session_id, account_id, ts))
        
        # 7. Request pattern signals
        signals.update(self._derive_request_signals(request))
        
        # Cleanup old state
        self._cleanup_old_state(ts)
        
        return signals
    
    def _derive_ip_reputation_signals(self, ip: str) -> dict:
        """IP reputation and blocklist signals."""
        signals = {}
        
        if not self.ip_reputation:
            signals['ip_reputation_score'] = 0.0
            signals['flagged_by_feeds'] = []
            signals['flagged_feed_count'] = 0
            return signals
        
        flagged_by = self.ip_reputation.get_flagged_by(ip)
        confidence = self.ip_reputation.get_confidence_score(ip)
        
        signals['ip_reputation_score'] = confidence
        signals['flagged_by_feeds'] = flagged_by
        signals['flagged_feed_count'] = len(flagged_by)
        signals['is_flagged'] = len(flagged_by) > 0
        
        return signals
    
    def _derive_geo_signals(self, request: dict, ip: str, geo_lookup) -> dict:
        """Geolocation and ASN signals."""
        signals = {
            'country': None,
            'asn_type': 'unknown',
            'is_tor_exit': False,
            'lang_geo_mismatch': False,
        }
        
        if not geo_lookup:
            return signals
        
        geo = geo_lookup.lookup(ip)
        signals['country'] = geo.get('country')
        signals['asn_type'] = geo.get('asn_type', 'unknown')
        signals['is_tor_exit'] = geo.get('is_tor_exit', False)
        signals['asn'] = geo.get('asn')
        signals['asn_org'] = geo.get('asn_org')
        
        # Language-Geography mismatch
        accept_language = request.get('headers', {}).get('accept_language', '')
        if accept_language and geo.get('country'):
            lang_country = accept_language.split('-')[1] if '-' in accept_language else accept_language.upper()
            geo_country = geo.get('country', '')
            signals['lang_geo_mismatch'] = lang_country != geo_country
        
        return signals
    
    def _derive_ip_velocity_signals(self, ip: str, ts: datetime) -> dict:
        """Request velocity signals per IP."""
        if ip not in self.ip_state:
            self.ip_state[ip] = BehavioralState(identifier=ip, first_seen=ts)
        
        state = self.ip_state[ip]
        state.last_seen = ts
        state.velocity_1m.add_event(ts)
        state.velocity_5m.add_event(ts)
        state.velocity_10m.add_event(ts)
        state.velocity_1h.add_event(ts)
        
        return {
            'ip_req_rate_1m': state.velocity_1m.count(ts),
            'ip_req_rate_5m': state.velocity_5m.count(ts),
            'ip_req_rate_10m': state.velocity_10m.count(ts),
            'ip_req_rate_1h': state.velocity_1h.count(ts),
            'ip_is_new': state.is_new(timedelta(minutes=1)),
        }
    
    def _derive_session_velocity_signals(self, session_id: str, ts: datetime) -> dict:
        """Request velocity signals per session."""
        if not session_id:
            return {'session_req_rate_1m': 0, 'session_is_new': False}
        
        if session_id not in self.session_state:
            self.session_state[session_id] = BehavioralState(identifier=session_id, first_seen=ts)
        
        state = self.session_state[session_id]
        state.last_seen = ts
        state.velocity_1m.add_event(ts)
        state.velocity_5m.add_event(ts)
        
        return {
            'session_req_rate_1m': state.velocity_1m.count(ts),
            'session_req_rate_5m': state.velocity_5m.count(ts),
            'session_is_new': state.is_new(timedelta(minutes=1)),
        }
    
    def _derive_account_velocity_signals(self, account_id: str, ts: datetime) -> dict:
        """Request velocity signals per account."""
        if not account_id:
            return {'account_req_rate_1m': 0, 'account_is_new': False}
        
        if account_id not in self.account_state:
            self.account_state[account_id] = BehavioralState(identifier=account_id, first_seen=ts)
        
        state = self.account_state[account_id]
        state.last_seen = ts
        state.velocity_1m.add_event(ts)
        state.velocity_5m.add_event(ts)
        
        return {
            'account_req_rate_1m': state.velocity_1m.count(ts),
            'account_req_rate_5m': state.velocity_5m.count(ts),
            'account_is_new': state.is_new(timedelta(minutes=1)),
        }
    
    def _derive_consistency_signals(self, request: dict, ip: str, session_id: str, 
                                   account_id: str, ts: datetime) -> dict:
        """Cross-entity consistency signals."""
        signals = {}
        
        # Track what we see
        if session_id and session_id in self.session_state:
            self.session_state[session_id].ips_seen.add(ip)
            self.session_state[session_id].user_agents_seen.add(request.get('user_agent', ''))
            self.session_state[session_id].ja3s_seen.add(request.get('headers', {}).get('tls_ja3', ''))
        
        if account_id and account_id in self.account_state:
            self.account_state[account_id].ips_seen.add(ip)
            self.account_state[account_id].sessions_seen.add(session_id)
            self.account_state[account_id].user_agents_seen.add(request.get('user_agent', ''))
            self.account_state[account_id].ja3s_seen.add(request.get('headers', {}).get('tls_ja3', ''))
        
        if ip and ip in self.ip_state:
            self.ip_state[ip].sessions_seen.add(session_id)
            self.ip_state[ip].accounts_seen.add(account_id)
            self.ip_state[ip].user_agents_seen.add(request.get('user_agent', ''))
            self.ip_state[ip].ja3s_seen.add(request.get('headers', {}).get('tls_ja3', ''))
        
        # Derive signals from consistency
        if session_id and session_id in self.session_state:
            state = self.session_state[session_id]
            signals['session_unique_ips'] = len(state.ips_seen)
            signals['session_unique_uas'] = len(state.user_agents_seen)
            signals['session_unique_ja3s'] = len(state.ja3s_seen)
        
        if account_id and account_id in self.account_state:
            state = self.account_state[account_id]
            signals['account_unique_ips'] = len(state.ips_seen)
            signals['account_unique_sessions'] = len(state.sessions_seen)
            signals['account_unique_uas'] = len(state.user_agents_seen)
        
        if ip and ip in self.ip_state:
            state = self.ip_state[ip]
            signals['ip_unique_sessions'] = len(state.sessions_seen)
            signals['ip_unique_accounts'] = len(state.accounts_seen)
            signals['ip_unique_uas'] = len(state.user_agents_seen)
            signals['ip_unique_ja3s'] = len(state.ja3s_seen)
        
        return signals
    
    def _derive_request_signals(self, request: dict) -> dict:
        """Request-level pattern signals."""
        signals = {}
        
        # Path classification
        path = request.get('path', '')
        signals['path_class'] = self._classify_path(path)
        signals['path'] = path
        
        # User-agent signals
        user_agent = request.get('user_agent', '')
        signals['ua_is_bot'] = self._detect_bot_ua(user_agent)
        signals['ua_is_mobile'] = 'mobile' in user_agent.lower() or 'android' in user_agent.lower() or 'iphone' in user_agent.lower()
        signals['user_agent'] = user_agent
        
        # HTTP method
        signals['method'] = request.get('method', 'GET')
        
        # Status code
        status = request.get('status_seen', 200)
        signals['status_code'] = status
        signals['status_code_unusual'] = status >= 400
        
        # Accept language
        signals['accept_language'] = request.get('headers', {}).get('accept_language', '')
        
        # TLS fingerprint
        signals['tls_ja3'] = request.get('headers', {}).get('tls_ja3', '')
        
        return signals
    
    @staticmethod
    def _classify_path(path: str) -> str:
        """Classify request path by endpoint type."""
        path_lower = path.lower()
        
        if 'voucher' in path_lower or 'redeem' in path_lower:
            return 'voucher'
        elif 'login' in path_lower or 'auth' in path_lower:
            return 'auth'
        elif 'account' in path_lower or 'user' in path_lower:
            return 'account'
        elif 'scrape' in path_lower or 'api' in path_lower:
            return 'api'
        elif 'health' in path_lower or 'status' in path_lower:
            return 'health'
        else:
            return 'other'
    
    @staticmethod
    def _detect_bot_ua(user_agent: str) -> bool:
        """Detect bot/crawler user-agents."""
        bot_patterns = [
            'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python',
            'java', 'perl', 'ruby', 'go-http', 'httpx', 'requests',
            'mechanize', 'phantom', 'headless'
        ]
        ua_lower = user_agent.lower()
        return any(pattern in ua_lower for pattern in bot_patterns)
    
    def _cleanup_old_state(self, current_ts: datetime):
        """Remove old state entries to prevent memory leak."""
        cutoff = current_ts - self.state_retention
        current_ts = current_ts.replace(tzinfo=timezone.utc) if current_ts.tzinfo is None else current_ts
        
        for state_dict in [self.ip_state, self.session_state, self.account_state]:
            old_keys = [k for k, v in state_dict.items() if v.last_seen < cutoff]
            for key in old_keys:
                del state_dict[key]
        
        if old_keys:
            logger.debug(f"Cleaned up {len(old_keys)} old state entries")
