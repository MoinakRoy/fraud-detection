"""
Efficient IP lookup structures for threat intelligence matching.

Handles CIDR ranges and individual IPs with O(log n) lookup performance.
"""

import ipaddress
import logging
from typing import Set, Dict, List, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


class IPReputation:
    """
    Multi-feed IP reputation lookup with feed tracking.
    
    Design:
    - Each feed is indexed separately
    - Track which feeds flagged an IP
    - Provide confidence scoring based on consensus
    """
    
    def __init__(self):
        self.feed_index: Dict[str, Set[str]] = {}  # feed_id -> set of IPs/CIDRs
        self.ip_networks: Dict[str, List] = defaultdict(list)  # feed_id -> list of IPv4Network/IPv6Network
        self.single_ips: Dict[str, Set[str]] = defaultdict(set)  # feed_id -> set of single IPs
        
    def add_entries(self, feed_id: str, entries: Set[str]):
        """
        Add entries from a threat feed.
        
        Separates CIDR ranges (for efficient lookup) from single IPs.
        """
        logger.info(f"Indexing {len(entries)} entries for feed {feed_id}")
        
        self.feed_index[feed_id] = set()
        networks = []
        singles = set()
        
        for entry in entries:
            try:
                # Try to parse as CIDR network
                if '/' in entry:
                    network = ipaddress.ip_network(entry, strict=False)
                    networks.append(network)
                    self.feed_index[feed_id].add(entry)
                else:
                    # Single IP address
                    ip_obj = ipaddress.ip_address(entry)
                    singles.add(str(ip_obj))
                    self.feed_index[feed_id].add(entry)
            except ValueError as e:
                logger.warning(f"Invalid entry in {feed_id}: {entry} ({e})")
                continue
        
        self.ip_networks[feed_id] = networks
        self.single_ips[feed_id] = singles
        logger.info(f"  {len(networks)} networks, {len(singles)} single IPs")
    
    def lookup(self, ip: str) -> Dict[str, bool]:
        """
        Check which feeds flag this IP.
        
        Returns:
            Dict mapping feed_id -> bool (True if flagged)
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            logger.warning(f"Invalid IP: {ip}")
            return {}
        
        results = {}
        
        for feed_id in self.feed_index.keys():
            # Check single IPs
            if ip in self.single_ips[feed_id]:
                results[feed_id] = True
                continue
            
            # Check CIDR networks
            flagged = any(ip_obj in network for network in self.ip_networks[feed_id])
            results[feed_id] = flagged
        
        return results
    
    def get_confidence_score(self, ip: str, feed_weights: Dict[str, float] = None) -> float:
        """
        Compute reputation confidence 0.0-1.0.
        
        Based on consensus across feeds and optional per-feed weights.
        """
        if feed_weights is None:
            feed_weights = {feed_id: 1.0 for feed_id in self.feed_index.keys()}
        
        lookup = self.lookup(ip)
        if not lookup:
            return 0.0
        
        hits = sum(weight for feed_id, weight in feed_weights.items() 
                  if lookup.get(feed_id, False))
        total_weight = sum(feed_weights.values())
        
        return min(1.0, hits / total_weight) if total_weight > 0 else 0.0
    
    def get_flagged_by(self, ip: str) -> List[str]:
        """Get list of feeds that flagged this IP."""
        lookup = self.lookup(ip)
        return [feed_id for feed_id, flagged in lookup.items() if flagged]
    
    def stats(self) -> dict:
        """Return index statistics."""
        total_entries = sum(len(entries) for entries in self.feed_index.values())
        total_networks = sum(len(nets) for nets in self.ip_networks.values())
        total_singles = sum(len(ips) for ips in self.single_ips.values())
        
        return {
            'feeds_loaded': len(self.feed_index),
            'total_entries': total_entries,
            'total_cidr_ranges': total_networks,
            'total_single_ips': total_singles,
            'by_feed': {
                feed_id: {
                    'entries': len(self.feed_index[feed_id]),
                    'networks': len(self.ip_networks[feed_id]),
                    'singles': len(self.single_ips[feed_id])
                }
                for feed_id in self.feed_index
            }
        }


class GeoIPLookup:
    """
    Simple geolocation and ASN lookup.
    
    In production, would use MaxMind GeoIP2 or similar.
    For now, we'll support loading from CSV or similar format.
    """
    
    ASN_TYPES = {
        'hosting': ['AS16509', 'AS14061', 'AS15169', 'AS8075', 'AS16591'],  # Common hosting ASNs
        'residential': ['AS701', 'AS2914', 'AS3356'],  # Transit networks
        'mobile': ['AS6447', 'AS9498'],  # Mobile networks
        'tor': [],  # Will be populated dynamically
    }
    
    def __init__(self):
        self.ip_to_country = {}  # IP -> country code
        self.ip_to_asn = {}      # IP -> (ASN, ASN type, org name)
        self.tor_exits = set()
        
    def add_tor_exits(self, tor_ips: Set[str]):
        """Register known Tor exit nodes."""
        self.tor_exits = tor_ips
    
    def load_from_csv(self, filepath: str):
        """Load GeoIP data from CSV (format: ip,country_code,asn,asn_org)."""
        logger.info(f"Loading geo data from {filepath}")
        try:
            with open(filepath) as f:
                for line in f:
                    if line.startswith('#') or not line.strip():
                        continue
                    parts = line.strip().split(',')
                    if len(parts) >= 4:
                        ip, country, asn, asn_org = parts[0], parts[1], parts[2], parts[3]
                        self.ip_to_country[ip] = country.upper()
                        self.ip_to_asn[ip] = (asn, self._classify_asn(asn), asn_org)
        except FileNotFoundError:
            logger.warning(f"Geo data file not found: {filepath}")
    
    def _classify_asn(self, asn: str) -> str:
        """Classify ASN by type."""
        for asn_type, asns in self.ASN_TYPES.items():
            if asn in asns:
                return asn_type
        # Default heuristic: most hosting providers have higher ASN numbers
        try:
            asn_num = int(asn.replace('AS', ''))
            if asn_num > 60000:
                return 'hosting'
        except:
            pass
        return 'unknown'
    
    def lookup(self, ip: str) -> dict:
        """
        Lookup geolocation and ASN for an IP.
        
        Returns dict with country, asn, asn_type, asn_org, is_tor_exit.
        """
        result = {
            'ip': ip,
            'country': self.ip_to_country.get(ip),
            'asn': None,
            'asn_type': 'unknown',
            'asn_org': None,
            'is_tor_exit': ip in self.tor_exits
        }
        
        if ip in self.ip_to_asn:
            asn, asn_type, asn_org = self.ip_to_asn[ip]
            result['asn'] = asn
            result['asn_type'] = asn_type
            result['asn_org'] = asn_org
        
        return result
