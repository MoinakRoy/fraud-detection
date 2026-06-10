"""
Unit tests for signal derivation and rule evaluation.
"""

import unittest
from datetime import datetime, timedelta
from unittest.mock import Mock

from enrich.signal_deriver import SignalDeriver, TimeWindow, BehavioralState
from engine.rule_engine import RuleEngine, Rule
from ingest.ip_lookup import IPReputation, GeoIPLookup


class TestTimeWindow(unittest.TestCase):
    """Test rolling time windows."""
    
    def test_event_counting(self):
        """Test that events within window are counted."""
        window = TimeWindow(window_duration=timedelta(minutes=1))
        now = datetime.now()
        
        window.add_event(now)
        window.add_event(now + timedelta(seconds=10))
        window.add_event(now + timedelta(seconds=20))
        
        self.assertEqual(window.count(now + timedelta(seconds=30)), 3)
    
    def test_event_expiration(self):
        """Test that old events expire from window."""
        window = TimeWindow(window_duration=timedelta(minutes=1))
        now = datetime.now()
        
        # Add events at different times
        window.add_event(now - timedelta(minutes=2))  # Outside window
        window.add_event(now - timedelta(seconds=30))  # Inside window
        window.add_event(now)
        
        count = window.count(now)
        self.assertEqual(count, 2)  # Only 2 should remain


class TestSignalDeriver(unittest.TestCase):
    """Test signal derivation."""
    
    def setUp(self):
        self.deriver = SignalDeriver()
    
    def test_path_classification(self):
        """Test path classification signals."""
        test_cases = [
            ('/api/v1/voucher/redeem', 'voucher'),
            ('/api/v1/login', 'auth'),
            ('/api/v1/account/profile', 'account'),
            ('/api/v1/categories', 'api'),
            ('/health', 'health'),
        ]
        
        for path, expected_class in test_cases:
            request = {
                'request_id': 'test',
                'ts': datetime.now().isoformat() + 'Z',
                'ip': '1.2.3.4',
                'path': path,
                'user_agent': 'Mozilla/5.0',
                'headers': {'accept_language': 'en-US', 'tls_ja3': ''},
                'session_id': 'sess1',
                'account_id': 'acc1',
                'status_seen': 200
            }
            
            signals = self.deriver.derive_signals(request)
            self.assertEqual(signals['path_class'], expected_class)
    
    def test_bot_ua_detection(self):
        """Test bot user-agent detection."""
        bot_uas = [
            'curl/7.0',
            'wget/1.0',
            'python-requests/2.0',
            'Java/11',
            'Go-http-client/2.0',
        ]
        
        for bot_ua in bot_uas:
            is_bot = SignalDeriver._detect_bot_ua(bot_ua)
            self.assertTrue(is_bot, f"Should detect bot UA: {bot_ua}")
    
    def test_velocity_signals(self):
        """Test velocity signal accumulation."""
        now = datetime.now()
        base_request = {
            'request_id': 'test',
            'ts': now.isoformat() + 'Z',
            'ip': '1.2.3.4',
            'path': '/api/test',
            'user_agent': 'Mozilla/5.0',
            'headers': {'accept_language': 'en-US', 'tls_ja3': ''},
            'session_id': 'sess1',
            'account_id': 'acc1',
            'status_seen': 200
        }
        
        # Process multiple requests from same IP
        signals_list = []
        for i in range(5):
            request = base_request.copy()
            request['ts'] = (now + timedelta(seconds=i)).isoformat() + 'Z'
            signals = self.deriver.derive_signals(request)
            signals_list.append(signals)
        
        # Last request should show velocity
        last_signals = signals_list[-1]
        self.assertEqual(last_signals['ip_req_rate_1m'], 5)


class TestIPReputation(unittest.TestCase):
    """Test IP reputation lookup."""
    
    def setUp(self):
        self.ip_rep = IPReputation()
    
    def test_single_ip_lookup(self):
        """Test single IP matching."""
        self.ip_rep.add_entries('feed1', {'192.0.2.1', '192.0.2.2', '203.0.113.5'})
        
        # Match
        result = self.ip_rep.lookup('192.0.2.1')
        self.assertTrue(result.get('feed1'))
        
        # No match
        result = self.ip_rep.lookup('10.0.0.1')
        self.assertFalse(result.get('feed1', False))
    
    def test_cidr_matching(self):
        """Test CIDR range matching."""
        self.ip_rep.add_entries('feed2', {'192.0.2.0/24', '203.0.113.0/25'})
        
        # Matches should be in range
        result = self.ip_rep.lookup('192.0.2.100')
        self.assertTrue(result.get('feed2'))
        
        # Should not match outside range
        result = self.ip_rep.lookup('192.0.3.100')
        self.assertFalse(result.get('feed2', False))
    
    def test_get_flagged_by(self):
        """Test getting list of feeds that flagged an IP."""
        self.ip_rep.add_entries('feed1', {'1.2.3.4'})
        self.ip_rep.add_entries('feed2', {'1.2.3.4'})
        self.ip_rep.add_entries('feed3', {'5.6.7.8'})
        
        flagged = self.ip_rep.get_flagged_by('1.2.3.4')
        self.assertEqual(set(flagged), {'feed1', 'feed2'})
    
    def test_confidence_score(self):
        """Test confidence score calculation."""
        self.ip_rep.add_entries('feed1', {'1.2.3.4'})
        self.ip_rep.add_entries('feed2', {'1.2.3.4'})
        self.ip_rep.add_entries('feed3', {'5.6.7.8'})
        
        # IP with 2 hits should have higher confidence
        score1 = self.ip_rep.get_confidence_score('1.2.3.4')
        score2 = self.ip_rep.get_confidence_score('5.6.7.8')
        
        self.assertGreater(score1, score2)


class TestGeoIPLookup(unittest.TestCase):
    """Test geolocation lookups."""
    
    def setUp(self):
        self.geo = GeoIPLookup()
    
    def test_tor_exit_flagging(self):
        """Test Tor exit node detection."""
        self.geo.add_tor_exits({'1.2.3.4', '5.6.7.8'})
        
        result = self.geo.lookup('1.2.3.4')
        self.assertTrue(result['is_tor_exit'])
        
        result = self.geo.lookup('9.9.9.9')
        self.assertFalse(result['is_tor_exit'])


class TestRuleEngine(unittest.TestCase):
    """Test rule engine and evaluation."""
    
    def setUp(self):
        self.engine = RuleEngine(rules_dir='rules')
    
    def test_simple_condition_evaluation(self):
        """Test simple rule condition evaluation."""
        signals = {
            'ip_req_rate_1m': 50,
            'asn_type': 'hosting',
            'path_class': 'voucher',
            'flagged_feed_count': 2
        }
        
        # Create a test rule
        rule = Rule(
            id='test_rule',
            description='Test',
            severity='high',
            condition="signals.ip_req_rate_1m > 30 and signals.asn_type == 'hosting'",
            action='block',
            weight=50
        )
        
        # Manually test evaluation
        result = self.engine._evaluate_condition(rule.condition, signals)
        self.assertTrue(result)
    
    def test_full_evaluation(self):
        """Test full rule evaluation pipeline."""
        signals = {
            'ip_req_rate_1m': 100,
            'asn_type': 'hosting',
            'path_class': 'voucher',
            'flagged_feed_count': 3,
            'is_flagged': True,
            'ua_is_bot': True,
            'status_code': 200,
            'accept_language': 'en-US',
        }
        
        result = self.engine.evaluate(signals)
        
        # Should have some result
        self.assertIn('decision', result)
        self.assertIn('score', result)
        self.assertIn('fired_rules', result)
    
    def test_rule_enable_disable(self):
        """Test rule enable/disable."""
        # First create a rule
        rule = Rule(
            id='test_disable',
            description='Test',
            severity='medium',
            condition='signals.ua_is_bot',
            action='challenge',
            weight=20
        )
        self.engine.add_rule(rule)
        
        # Test enabled
        self.assertTrue(self.engine.rules_by_id['test_disable'].enabled)
        
        # Disable
        self.engine.disable_rule('test_disable')
        self.assertFalse(self.engine.rules_by_id['test_disable'].enabled)
        
        # Enable
        self.engine.enable_rule('test_disable')
        self.assertTrue(self.engine.rules_by_id['test_disable'].enabled)


if __name__ == '__main__':
    unittest.main()
