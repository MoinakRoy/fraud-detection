"""
Real-Time Stream Processor

Processes requests from traffic.jsonl as a stream.
Maintains state windows, enriches requests, scores them, and outputs decisions.
"""

import json
import logging
import traceback
from pathlib import Path
from typing import Iterator, List, Dict
from datetime import datetime, timedelta
import time

from ingest.feed_fetcher import ThreatIntelligenceFetcher
from ingest.ip_lookup import IPReputation, GeoIPLookup
from enrich.signal_deriver import SignalDeriver
from engine.rule_engine import RuleEngine, Rule

logger = logging.getLogger(__name__)


class StreamProcessor:
    """
    Main detection pipeline.
    
    Flow:
    1. Initialize threat intelligence (feeds, geolocation)
    2. For each request in stream:
       a. Derive signals (IP reputation, geo, behavioral)
       b. Evaluate rules
       c. Output decision
       d. Update state
    """
    
    def __init__(self, 
                 data_dir: str = 'data',
                 rules_dir: str = 'rules',
                 feeds_cache_dir: str = 'data/feeds'):
        self.data_dir = Path(data_dir)
        self.rules_dir = Path(rules_dir)
        
        # Initialize threat intel
        self.fetcher = ThreatIntelligenceFetcher(cache_dir=feeds_cache_dir)
        self.ip_reputation = IPReputation()
        self.geo_lookup = GeoIPLookup()
        
        # Initialize processors
        self.signal_deriver = SignalDeriver()
        self.rule_engine = RuleEngine(rules_dir=rules_dir)
        
        # Statistics
        self.stats = {
            'processed': 0,
            'allow': 0,
            'challenge': 0,
            'block': 0,
            'errors': 0,
            'start_time': None,
            'end_time': None,
        }
    
    def initialize_threat_intel(self, skip_geo: bool = False):
        """Fetch and load threat intelligence feeds."""
        logger.info("Initializing threat intelligence...")
        
        # Fetch all configured feeds
        feeds = self.fetcher.fetch_all(skip_geo=skip_geo)
        
        # Load into IP reputation lookup
        for feed_id, entries in feeds.items():
            if entries:
                self.ip_reputation.add_entries(feed_id, entries)
        
        # Load Tor exits into geo lookup
        if 'tor_exit_nodes' in feeds and feeds['tor_exit_nodes']:
            self.geo_lookup.add_tor_exits(feeds['tor_exit_nodes'])
        
        # Log feed freshness metadata
        logger.info("Feed status:")
        for feed_id, metadata in self.fetcher.get_metadata().items():
            logger.info(f"  {feed_id}: {metadata}")
        
        logger.info(f"IP Reputation index stats: {self.ip_reputation.stats()}")
    
    def process_stream(self, input_file: str, output_file: str = None):
        """
        Process traffic log as a stream.
        
        Args:
            input_file: Path to traffic.jsonl
            output_file: Path to write decisions.jsonl (default: decisions.jsonl)
        """
        if output_file is None:
            output_file = str(Path(input_file).parent / 'decisions.jsonl')
        
        input_path = Path(input_file)
        output_path = Path(output_file)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        logger.info(f"Processing stream from {input_file}")
        logger.info(f"Outputting decisions to {output_file}")
        
        start_time = time.time()
        self.stats['start_time'] = datetime.now()
        
        with open(output_path, 'w') as out_f:
            for request in self._read_jsonl(input_path):
                try:
                    decision = self.process_request(request)
                    
                    # Write decision
                    out_f.write(json.dumps(decision) + '\n')
                    
                    # Update stats
                    self.stats['processed'] += 1
                    self.stats[decision['decision']] += 1
                    
                    # Log progress
                    if self.stats['processed'] % 5000 == 0:
                        elapsed = time.time() - start_time
                        throughput = self.stats['processed'] / elapsed
                        logger.info(f"Processed {self.stats['processed']} requests "
                                  f"({throughput:.1f} req/sec)")
                
                except Exception as e:
                    logger.error(f"Error processing request: {str(e)}")
                    logger.debug(traceback.format_exc())
                    self.stats['errors'] += 1
        
        self.stats['end_time'] = datetime.now()
        elapsed = time.time() - start_time
        throughput = self.stats['processed'] / elapsed if elapsed > 0 else 0
        
        logger.info("Stream processing complete!")
        logger.info(f"Processed {self.stats['processed']} requests in {elapsed:.1f}s ({throughput:.1f} req/sec)")
        logger.info(f"Decisions: allow={self.stats['allow']}, "
                   f"challenge={self.stats['challenge']}, block={self.stats['block']}")
        
        return {
            'output_file': output_file,
            'stats': self.stats,
            'throughput_req_sec': throughput
        }
    
    def process_request(self, request: dict) -> dict:
        """
        Process single request through full pipeline.
        
        Returns: decision record with request_id, score, decision, etc.
        """
        request_id = request.get('request_id')
        
        # Derive signals
        signals = self.signal_deriver.derive_signals(
            request,
            geo_lookup=self.geo_lookup,
            ip_reputation=self.ip_reputation
        )
        
        # Evaluate rules
        scoring_result = self.rule_engine.evaluate(signals)
        
        # Build decision record
        decision_record = {
            'request_id': request_id,
            'score': scoring_result['score'],
            'decision': scoring_result['decision'],
            'fired_rules': scoring_result['fired_rules'],
            'top_signals': scoring_result['top_signals'],
            'timestamp': request.get('ts'),
            'ip': request.get('ip'),
            'path': request.get('path'),
        }
        
        return decision_record
    
    @staticmethod
    def _read_jsonl(filepath: Path) -> Iterator[dict]:
        """Read JSONL file line by line."""
        with open(filepath) as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid JSON at line {line_num}: {e}")
    
    def get_decision_summary(self, output_file: str) -> dict:
        """Analyze decisions and produce summary."""
        logger.info(f"Analyzing decisions from {output_file}")
        
        summary = {
            'total_decisions': 0,
            'by_decision': {'allow': 0, 'challenge': 0, 'block': 0},
            'score_distribution': {
                '0-20': 0, '20-40': 0, '40-60': 0, '60-80': 0, '80-100': 0
            },
            'top_fired_rules': {},
            'top_signals': {},
        }
        
        with open(output_file) as f:
            for line in f:
                record = json.loads(line)
                summary['total_decisions'] += 1
                
                # Decision distribution
                decision = record.get('decision')
                summary['by_decision'][decision] = summary['by_decision'].get(decision, 0) + 1
                
                # Score distribution
                score = record.get('score', 0)
                if score < 20:
                    bucket = '0-20'
                elif score < 40:
                    bucket = '20-40'
                elif score < 60:
                    bucket = '40-60'
                elif score < 80:
                    bucket = '60-80'
                else:
                    bucket = '80-100'
                summary['score_distribution'][bucket] += 1
                
                # Rule firing frequency
                for rule_id in record.get('fired_rules', []):
                    summary['top_fired_rules'][rule_id] = summary['top_fired_rules'].get(rule_id, 0) + 1
                
                # Signal frequency
                for signal in record.get('top_signals', []):
                    summary['top_signals'][signal] = summary['top_signals'].get(signal, 0) + 1
        
        # Get top K
        summary['top_fired_rules'] = dict(
            sorted(summary['top_fired_rules'].items(), 
                   key=lambda x: -x[1])[:10]
        )
        summary['top_signals'] = dict(
            sorted(summary['top_signals'].items(), 
                   key=lambda x: -x[1])[:10]
        )
        
        return summary


def main():
    """CLI entry point for stream processing."""
    import sys
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Initialize processor
    processor = StreamProcessor()
    
    # Load threat intel
    processor.initialize_threat_intel(skip_geo=True)  # Skip geo for now
    
    # Process stream
    input_file = 'data/traffic.jsonl'
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    
    result = processor.process_stream(input_file)
    
    # Analyze results
    summary = processor.get_decision_summary(result['output_file'])
    
    logger.info("Decision Summary:")
    logger.info(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
