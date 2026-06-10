"""
YAML-Based Detection Rule Engine

Loads rules from YAML files and evaluates them against request signals.
Allows analysts to add/modify rules without code changes.
"""

import yaml
import logging
from pathlib import Path
from typing import List, Dict, Set
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class Rule:
    """Represents a detection rule."""
    id: str
    description: str
    severity: str  # low, medium, high, critical
    condition: str  # Boolean expression over signals
    action: str  # allow, challenge, block, investigate
    weight: int  # 0-100, contribution to final score
    enabled: bool = True
    owner: str = None
    created_at: str = None
    
    def __repr__(self):
        return f"Rule({self.id}, {self.severity}, weight={self.weight})"


class RuleEngine:
    """
    Declarative rule engine for threat scoring.
    
    Design:
    - Rules loaded from /rules/*.yaml
    - Each rule is a condition + action
    - Conditions are evaluated as Python expressions over signal dict
    - Weights are combined into final score (0-100)
    - Multiple actions: allow (veto), challenge, block, investigate
    """
    
    # Whitelisted functions that can be used in conditions
    SAFE_FUNCTIONS = {
        'len': len,
        'any': any,
        'all': all,
        'in': lambda x, y: x in y,
    }
    
    def __init__(self, rules_dir: str = 'rules'):
        self.rules_dir = Path(rules_dir)
        self.rules: List[Rule] = []
        self.rules_by_id: Dict[str, Rule] = {}
        self.load_rules()
    
    def load_rules(self):
        """Load all rules from YAML files in rules_dir."""
        if not self.rules_dir.exists():
            logger.warning(f"Rules directory not found: {self.rules_dir}")
            return
        
        yaml_files = sorted(self.rules_dir.glob('*.yaml')) + sorted(self.rules_dir.glob('*.yml'))
        logger.info(f"Loading rules from {len(yaml_files)} files")
        
        for yaml_file in yaml_files:
            try:
                with open(yaml_file) as f:
                    rules_data = yaml.safe_load(f)
                
                if not rules_data:
                    logger.debug(f"Empty rules file: {yaml_file}")
                    continue
                
                # Handle single rule or list of rules per file
                if isinstance(rules_data, dict):
                    rules_data = [rules_data]
                
                for rule_data in rules_data:
                    rule = Rule(
                        id=rule_data.get('id', 'unknown'),
                        description=rule_data.get('description', ''),
                        severity=rule_data.get('severity', 'medium'),
                        condition=rule_data.get('condition', 'False'),
                        action=rule_data.get('action', 'investigate'),
                        weight=rule_data.get('weight', 10),
                        enabled=rule_data.get('enabled', True),
                        owner=rule_data.get('owner'),
                        created_at=rule_data.get('created_at')
                    )
                    
                    self.rules.append(rule)
                    self.rules_by_id[rule.id] = rule
                    logger.info(f"Loaded rule: {rule}")
            
            except Exception as e:
                logger.error(f"Failed to load rules from {yaml_file}: {e}")
        
        logger.info(f"Loaded {len(self.rules)} rules total")
    
    def evaluate(self, signals: dict) -> dict:
        """
        Evaluate all rules against signals.
        
        Returns:
            {
                'decision': 'allow' | 'challenge' | 'block',
                'score': 0-100,
                'fired_rules': [list of rule IDs that fired],
                'rule_details': {rule_id: {fired, weight, severity}},
                'top_signals': [signals that contributed most]
            }
        """
        fired_rules = []
        rule_details = {}
        total_weight = 0
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            try:
                # Evaluate condition
                fired = self._evaluate_condition(rule.condition, signals)
                
                rule_details[rule.id] = {
                    'fired': fired,
                    'weight': rule.weight if fired else 0,
                    'severity': rule.severity,
                    'action': rule.action
                }
                
                if fired:
                    fired_rules.append(rule.id)
                    total_weight += rule.weight
            
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.id}: {e}")
                rule_details[rule.id] = {'error': str(e)}
        
        # Compute final score and decision
        score = min(100, total_weight)  # Cap at 100
        decision = self._compute_decision(fired_rules, score, rule_details)
        
        # Top signals contributing to score
        top_signals = self._extract_top_signals(signals, fired_rules, rule_details)
        
        return {
            'decision': decision,
            'score': score,
            'fired_rules': fired_rules,
            'rule_details': rule_details,
            'top_signals': top_signals
        }
    
    def _evaluate_condition(self, condition: str, signals: dict) -> bool:
        """
        Safely evaluate a condition string against signals.
        
        Supports: Python boolean logic with comparison operators
        Example: signals.asn_type == "hosting" and signals.ip_req_rate_1m > 20
        """
        # Replace 'signals.' references with actual signal values
        expr = condition
        for signal_name, signal_value in signals.items():
            # Build safe reference: signals.name -> value
            placeholder = f"signals.{signal_name}"
            # Quote string values, leave numbers as-is
            if isinstance(signal_value, str):
                safe_value = f"'{signal_value}'"
            else:
                safe_value = repr(signal_value)
            expr = expr.replace(placeholder, safe_value)
        
        # Safely evaluate
        try:
            result = eval(expr, {"__builtins__": {}}, self.SAFE_FUNCTIONS)
            return bool(result)
        except Exception as e:
            logger.warning(f"Failed to evaluate condition: {condition}")
            logger.warning(f"  Expr: {expr}")
            logger.warning(f"  Error: {e}")
            return False
    
    def _compute_decision(self, fired_rules: List[str], score: int, 
                         rule_details: dict) -> str:
        """
        Compute final decision from fired rules and score.
        
        Priority: explicit block action > score threshold > allow
        """
        actions = [rule_details.get(r, {}).get('action') for r in fired_rules]
        
        # Explicit block rules take priority
        if 'block' in actions:
            return 'block'
        
        # Then challenge
        if 'challenge' in actions:
            if score >= 70:
                return 'block'
            else:
                return 'challenge'
        
        # Score-based decision
        if score >= 80:
            return 'block'
        elif score >= 50:
            return 'challenge'
        else:
            return 'allow'
    
    def _extract_top_signals(self, signals: dict, fired_rules: List[str],
                            rule_details: dict, top_k: int = 5) -> List[str]:
        """Extract the most relevant signals for this request."""
        # Signals mentioned in fired rules
        relevant_signals = set()
        for rule_id in fired_rules:
            rule = self.rules_by_id.get(rule_id)
            if rule:
                # Extract signal names from condition
                for signal_name in signals.keys():
                    if f"signals.{signal_name}" in rule.condition:
                        value = signals[signal_name]
                        # Format signal for display
                        if isinstance(value, (int, float)):
                            relevant_signals.add(f"{signal_name}={value}")
                        elif value:
                            relevant_signals.add(signal_name)
        
        # Add high-value signals even if not in explicit rules
        high_value_signals = [
            ('is_flagged', signals.get('is_flagged')),
            ('ip_req_rate_1m', signals.get('ip_req_rate_1m')),
            ('flagged_feed_count', signals.get('flagged_feed_count')),
            ('asn_type', signals.get('asn_type')),
            ('is_tor_exit', signals.get('is_tor_exit')),
            ('account_unique_ips', signals.get('account_unique_ips')),
        ]
        
        for signal_name, value in high_value_signals:
            if value and signal_name not in relevant_signals:
                if isinstance(value, (int, float)):
                    relevant_signals.add(f"{signal_name}={value}")
                else:
                    relevant_signals.add(signal_name)
        
        return sorted(list(relevant_signals))[:top_k]
    
    def add_rule(self, rule: Rule):
        """Add a rule dynamically."""
        self.rules.append(rule)
        self.rules_by_id[rule.id] = rule
        logger.info(f"Added rule: {rule}")
    
    def disable_rule(self, rule_id: str):
        """Disable a rule without removing it."""
        if rule_id in self.rules_by_id:
            self.rules_by_id[rule_id].enabled = False
            logger.info(f"Disabled rule: {rule_id}")
    
    def enable_rule(self, rule_id: str):
        """Enable a previously disabled rule."""
        if rule_id in self.rules_by_id:
            self.rules_by_id[rule_id].enabled = True
            logger.info(f"Enabled rule: {rule_id}")
    
    def get_rules_summary(self) -> dict:
        """Get summary of loaded rules."""
        return {
            'total_rules': len(self.rules),
            'enabled_rules': len([r for r in self.rules if r.enabled]),
            'rules_by_severity': {
                severity: len([r for r in self.rules if r.severity == severity and r.enabled])
                for severity in ['critical', 'high', 'medium', 'low']
            },
            'rules': [{
                'id': r.id,
                'description': r.description,
                'severity': r.severity,
                'weight': r.weight,
                'enabled': r.enabled
            } for r in sorted(self.rules, key=lambda r: -r.weight)]
        }
