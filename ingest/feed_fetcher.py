"""
Threat Intelligence Feed Fetching and Normalisation

Handles fetching, parsing, and caching of threat intelligence feeds.
Treats all feeds as untrusted input with freshness tracking.
"""

import requests
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Set, Tuple
from dataclasses import dataclass
import json

logger = logging.getLogger(__name__)


@dataclass
class FeedMetadata:
    """Track feed health and freshness."""
    feed_id: str
    url: str
    last_fetched: datetime
    last_successful_fetch: datetime
    is_available: bool
    record_count: int
    fetch_error: str = None


class ThreatIntelligenceFetcher:
    """
    Fetch and normalize threat intelligence feeds.
    
    Design principles:
    - Treat all feeds as untrusted (handle HTML errors, invalid data)
    - Cache locally with age tracking
    - Degrade gracefully when sources unavailable
    - Track feed freshness and trigger alerts on staleness
    """
    
    FEEDS = {
        'firehol_level1': {
            'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
            'type': 'cidr',
            'description': 'FireHOL Level 1 CIDR ranges (~600M addresses)'
        },
        'ipsum': {
            'url': 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
            'type': 'scored_ips',
            'description': 'stampars/ipsum - IPs with blocklist counts'
        },
        'abuseipdb': {
            'url': 'https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-30d.ipv4',
            'type': 'ip_list',
            'description': 'AbuseIPDB aggregated high-confidence malicious IPs'
        },
        'tor_exit_nodes': {
            'url': 'https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst',
            'type': 'ip_list',
            'description': 'Tor exit node IP addresses'
        },
        'db_ip_asn': {
            'url': 'https://db-ip.com/db/download/ip-to-asn-lite',
            'type': 'geo_asn',
            'description': 'DB-IP Lite ASN database (requires manual download)'
        }
    }
    
    # Known legitimate IPs that should never be blocked (even if poisoned)
    WHITELIST_RANGES = [
        '8.8.8.8/32',           # Google DNS
        '1.1.1.1/32',           # Cloudflare DNS
        '208.67.222.222/32',    # OpenDNS
        '127.0.0.1/32',         # Localhost
        '::1/128',              # IPv6 Localhost
    ]
    
    def __init__(self, cache_dir: str = 'data/feeds', max_age_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_age_hours = max_age_hours
        self.metadata = {}
        self.session = requests.Session()
        self.session.timeout = 30  # 30 second timeout
        
    def _get_cache_path(self, feed_id: str) -> Path:
        """Get local cache file path for a feed."""
        return self.cache_dir / f"{feed_id}.cache"
    
    def _is_html_error(self, content: str) -> bool:
        """Detect if response is HTML error page instead of expected content."""
        content_lower = content[:500].lower()
        return any(x in content_lower for x in ['<!doctype', '<html', '<body', '404', '403', '500'])
    
    def _get_cache_age(self, feed_id: str) -> timedelta:
        """Get age of cached feed."""
        cache_path = self._get_cache_path(feed_id)
        if not cache_path.exists():
            return timedelta(days=999)
        age = datetime.now() - datetime.fromtimestamp(cache_path.stat().st_mtime)
        return age
    
    def fetch_feed(self, feed_id: str, force_fresh: bool = False) -> Set[str]:
        """
        Fetch a threat intelligence feed.
        
        Args:
            feed_id: Key in FEEDS dict
            force_fresh: Ignore cache and fetch fresh
            
        Returns:
            Set of IPs or CIDR ranges from the feed
            
        Raises:
            ValueError: If feed_id unknown or fetch fails
        """
        if feed_id not in self.FEEDS:
            raise ValueError(f"Unknown feed: {feed_id}")
        
        feed_info = self.FEEDS[feed_id]
        cache_path = self._get_cache_path(feed_id)
        cache_age = self._get_cache_age(feed_id)
        
        # Check if we have fresh cached data
        if not force_fresh and cache_path.exists() and cache_age < timedelta(hours=self.max_age_hours):
            logger.info(f"Using cached {feed_id} (age: {cache_age.seconds}s)")
            return self._load_cache(feed_id)
        
        # Attempt fresh fetch
        logger.info(f"Fetching {feed_id} from {feed_info['url']}")
        try:
            response = self.session.get(feed_info['url'], timeout=30)
            response.raise_for_status()
            
            content = response.text
            
            # Detect poisoned/error responses
            if self._is_html_error(content):
                logger.error(f"{feed_id} returned HTML error instead of feed")
                if cache_path.exists():
                    logger.warning(f"Degrading to stale cache for {feed_id}")
                    return self._load_cache(feed_id)
                return set()
            
            # Parse and validate
            entries = self._parse_feed(feed_id, content)
            
            # Filter out known legitimate ranges
            entries = self._filter_whitelist(entries)
            
            # Cache successful fetch
            cache_path.write_text('\n'.join(sorted(entries)))
            
            self.metadata[feed_id] = FeedMetadata(
                feed_id=feed_id,
                url=feed_info['url'],
                last_fetched=datetime.now(),
                last_successful_fetch=datetime.now(),
                is_available=True,
                record_count=len(entries),
                fetch_error=None
            )
            
            logger.info(f"Successfully fetched {feed_id}: {len(entries)} entries")
            return entries
            
        except requests.RequestException as e:
            logger.error(f"Failed to fetch {feed_id}: {e}")
            
            # Degrade to cache if available
            if cache_path.exists():
                logger.warning(f"Using stale cache for {feed_id}")
                entries = self._load_cache(feed_id)
                cache_age = self._get_cache_age(feed_id)
                self.metadata[feed_id] = FeedMetadata(
                    feed_id=feed_id,
                    url=feed_info['url'],
                    last_fetched=datetime.now(),
                    last_successful_fetch=datetime.fromtimestamp(cache_path.stat().st_mtime),
                    is_available=False,
                    record_count=len(entries),
                    fetch_error=str(e)
                )
                return entries
            else:
                self.metadata[feed_id] = FeedMetadata(
                    feed_id=feed_id,
                    url=feed_info['url'],
                    last_fetched=datetime.now(),
                    last_successful_fetch=None,
                    is_available=False,
                    record_count=0,
                    fetch_error=str(e)
                )
                return set()
    
    def _load_cache(self, feed_id: str) -> Set[str]:
        """Load cached entries for a feed."""
        cache_path = self._get_cache_path(feed_id)
        if not cache_path.exists():
            return set()
        content = cache_path.read_text()
        return set(line.strip() for line in content.split('\n') if line.strip())
    
    def _parse_feed(self, feed_id: str, content: str) -> Set[str]:
        """Parse feed content based on feed type."""
        feed_type = self.FEEDS[feed_id]['type']
        entries = set()
        
        for line in content.split('\n'):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#') or line.startswith(';'):
                continue
            
            # Parse by type
            if feed_type == 'cidr':
                # FireHOL format: CIDR ranges
                if '/' in line and self._is_valid_cidr(line):
                    entries.add(line)
            elif feed_type == 'ip_list':
                # Simple IP list
                if self._is_valid_ip(line):
                    entries.add(line)
            elif feed_type == 'scored_ips':
                # ipsum format: IP,count[,source]
                parts = line.split(',')
                if parts and self._is_valid_ip(parts[0]):
                    entries.add(parts[0])
            elif feed_type == 'geo_asn':
                # Will be handled separately
                entries.add(line)
        
        return entries
    
    def _filter_whitelist(self, entries: Set[str]) -> Set[str]:
        """Remove whitelisted ranges to prevent poisoning attacks."""
        # This is a simple filter; in production, use proper CIDR arithmetic
        filtered = set()
        for entry in entries:
            # Remove if it's in our whitelist
            if entry not in ['8.8.8.8', '8.8.8.8/32', '1.1.1.1', '1.1.1.1/32']:
                filtered.add(entry)
        return filtered
    
    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Simple IP validation."""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    
    @staticmethod
    def _is_valid_cidr(cidr: str) -> bool:
        """Simple CIDR validation."""
        if '/' not in cidr:
            return False
        ip_part, prefix = cidr.split('/')
        if not ThreatIntelligenceFetcher._is_valid_ip(ip_part):
            return False
        try:
            prefix_int = int(prefix)
            return 0 <= prefix_int <= 32
        except ValueError:
            return False
    
    def fetch_all(self, skip_geo: bool = False) -> dict:
        """Fetch all configured feeds."""
        results = {}
        for feed_id in self.FEEDS:
            if skip_geo and self.FEEDS[feed_id]['type'] == 'geo_asn':
                logger.info(f"Skipping {feed_id} (geo data requires manual setup)")
                continue
            results[feed_id] = self.fetch_feed(feed_id)
        return results
    
    def get_metadata(self) -> dict:
        """Return feed freshness and availability metadata."""
        return {
            feed_id: {
                'available': meta.is_available,
                'last_successful': meta.last_successful_fetch.isoformat() if meta.last_successful_fetch else None,
                'record_count': meta.record_count,
                'error': meta.fetch_error,
                'age_hours': round((datetime.now() - meta.last_successful_fetch).total_seconds() / 3600, 1)
                if meta.last_successful_fetch else None
            }
            for feed_id, meta in self.metadata.items()
        }
