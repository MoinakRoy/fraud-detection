#!/usr/bin/env python3
"""
Main entry point for the fraud detection pipeline.

Usage:
    python main.py <traffic.jsonl> [output.jsonl]
    
Example:
    python main.py data/traffic.jsonl data/decisions.jsonl
"""

import sys
import logging
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from stream.processor import StreamProcessor

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python main.py <traffic.jsonl> [output.jsonl]")
        print("\nExample: python main.py data/traffic.jsonl data/decisions.jsonl")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    try:
        # Create processor
        processor = StreamProcessor(
            data_dir='data',
            rules_dir='rules'
        )
        
        logger.info("Initializing threat intelligence feeds...")
        processor.initialize_threat_intel(skip_geo=True)
        
        logger.info("Starting stream processing...")
        result = processor.process_stream(input_file, output_file)
        
        logger.info("\n" + "="*60)
        logger.info("PROCESSING COMPLETE")
        logger.info("="*60)
        logger.info(f"Output: {result['output_file']}")
        logger.info(f"Processed: {result['stats']['processed']} requests")
        logger.info(f"Throughput: {result['throughput_req_sec']:.1f} requests/sec")
        logger.info(f"Decisions: "
                   f"allow={result['stats']['allowed']}, "
                   f"challenge={result['stats']['challenged']}, "
                   f"blocked={result['stats']['blocked']}")
        
        # Print decision summary
        logger.info("\nGenerating decision summary...")
        summary = processor.get_decision_summary(result['output_file'])
        
        logger.info(f"\nDecision Distribution:")
        for decision, count in summary['by_decision'].items():
            pct = 100 * count / summary['total_decisions'] if summary['total_decisions'] > 0 else 0
            logger.info(f"  {decision:10s}: {count:6d} ({pct:5.1f}%)")
        
        logger.info(f"\nScore Distribution:")
        for bucket, count in summary['score_distribution'].items():
            pct = 100 * count / summary['total_decisions'] if summary['total_decisions'] > 0 else 0
            logger.info(f"  {bucket:8s}: {count:6d} ({pct:5.1f}%)")
        
        logger.info(f"\nTop Fired Rules:")
        for rule_id, count in list(summary['top_fired_rules'].items())[:5]:
            logger.info(f"  {rule_id}: {count}")
        
        logger.info(f"\nTop Signals:")
        for signal, count in list(summary['top_signals'].items())[:10]:
            logger.info(f"  {signal}: {count}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
