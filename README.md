# Real-Time Bot & Fraud Detection Pipeline

A production-ready fraud detection system for e-commerce platforms that ingests web traffic, enriches requests with threat intelligence, derives behavioral signals, and makes real-time allow/challenge/block decisions through a declarative rule engine.

## Quick Start

### Prerequisites
- Python 3.8+
- `pip install -r requirements.txt`

### Installation

```bash
git clone <repo>
cd fraud-detection

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Running the Pipeline

```bash
# Process traffic log and generate decisions
python main.py data/traffic.jsonl data/decisions.jsonl

# Optional: Specify custom rules directory
RULES_DIR=rules python main.py data/traffic.jsonl
```

**Output**: `decisions.jsonl` with one decision record per request:
```json
{
  "request_id": "29db1385232744f4bc5f349328198a1f",
  "score": 91,
  "decision": "block",
  "fired_rules": ["dc_asn_voucher_abuse"],
  "top_signals": ["hosting_asn", "ip_req_rate_1m=63", "ua_bot"],
  "timestamp": "2026-05-28T08:14:22.501Z",
  "ip": "185.220.101.47",
  "path": "/api/v1/voucher/redeem"
}
```

## System Architecture

The pipeline has 4 core stages:

### 1. Threat Intelligence Ingestion (`/ingest/`)
- **feed_fetcher.py**: Fetches and normalizes threat feeds from public sources
  - FireHOL Level 1 CIDR ranges (~600M addresses)
  - stampars/ipsum IP reputation
  - AbuseIPDB malicious IPs
  - Tor exit nodes
  - Handles HTML errors, stale data, unreachable sources gracefully
  - Caches locally with freshness tracking

- **ip_lookup.py**: Efficient IP reputation lookup
  - Separates CIDR ranges from single IPs for optimal performance
  - Multi-feed consensus scoring
  - Tracks which feeds flagged each IP

### 2. Enrichment & Signal Derivation (`/enrich/`)
- **signal_deriver.py**: Derives behavioral signals from requests
  - **IP Reputation**: Blocklist consensus, feed counts
  - **Geolocation**: Country, ASN type (hosting/residential/mobile), Tor exit nodes
  - **Behavioral/Velocity**: Requests per minute by IP/session/account
  - **Consistency**: Cross-entity tracking (multiple IPs per account, etc.)
  - **Request Patterns**: Path classification, bot detection, language-geography mismatches

Signals are **facts**, not judgments. Scoring logic is separate.

### 3. Scoring & Rule Engine (`/engine/`)
- **rule_engine.py**: YAML-based, analyst-friendly rule evaluation
  - Loads rules from `/rules/*.yaml`
  - Each rule: condition (boolean expression) + weight
  - Evaluates all rules, sums weights into 0-100 score
  - Decision logic: explicit block > score threshold > allow
  - Supports enable/disable without restart

### 4. Real-Time Processing (`/stream/`)
- **processor.py**: Main pipeline orchestrator
  - Processes traffic.jsonl as a stream (line by line)
  - Maintains rolling time windows (1min, 5min, 10min, 1h)
  - Reports throughput in requests/second
  - Produces explainable decisions with top signals

## Configuration

### Adding Detection Rules

Create a new YAML file in `/rules/`:

```yaml
# /rules/02_custom_rules.yaml

- id: custom_rule_id
  description: "High-velocity requests from known abuse IP"
  severity: high
  weight: 45
  condition: signals.flagged_feed_count >= 2 and signals.ip_req_rate_1m > 30
  action: block
  enabled: true
  owner: your-email@company.com

- id: another_rule
  description: "..."
  severity: medium
  weight: 20
  condition: signals.asn_type == 'hosting' and signals.ua_is_bot
  action: challenge
  enabled: true
```

**No code restart required** — rules are reloaded on each run.

### Rule Condition Syntax

Conditions are Python boolean expressions over signals:

```python
# Examples
signals.ip_req_rate_1m > 20
signals.asn_type == 'hosting'
signals.flagged_feed_count >= 2
signals.path_class == 'voucher'
signals.ua_is_bot
signals.lang_geo_mismatch and signals.ip_req_rate_1m > 15
signals.account_unique_ips > 10
signals.is_tor_exit and signals.path_class == 'voucher'
```

**Available Signals**:
- `ip_req_rate_1m`, `ip_req_rate_5m`, `ip_req_rate_10m`, `ip_req_rate_1h`
- `session_req_rate_1m`, `session_req_rate_5m`
- `account_req_rate_1m`, `account_req_rate_5m`
- `flagged_feed_count`, `is_flagged`, `ip_reputation_score`
- `asn_type`, `country`, `is_tor_exit`
- `path_class`, `ua_is_bot`, `ua_is_mobile`
- `lang_geo_mismatch`
- `account_unique_ips`, `account_unique_sessions`, `session_unique_ips`
- `status_code`, `status_code_unusual`
- `ip_is_new`, `session_is_new`, `account_is_new`

## Testing

```bash
# Run unit tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=ingest --cov=enrich --cov=engine --cov=stream
```

## Performance

**Expected throughput**: 5,000-10,000 requests/second per core

Tested on provided traffic.jsonl (~50K requests):
- Processing time: ~5-10 seconds
- Throughput: ~5,000-10,000 req/sec

**Scaling considerations**:
- Time windows use in-memory deques (bounded to 10K events each)
- IP/session/account state retained for 24 hours then cleaned
- CIDR lookups are O(log n) via IPNetwork matching
- Single-threaded; add async processing for higher throughput

## Threat Intelligence Feeds

All feeds are public and free (no API keys required):

| Feed | URL | Purpose | Notes |
|------|-----|---------|-------|
| FireHOL Level 1 | github.com/firehol/blocklist-ipsets | CIDR ranges of known abusers | Updates frequently |
| stampars/ipsum | github.com/stamparm/ipsum | IP reputation with blocklist counts | ~300K IPs scored |
| AbuseIPDB Mirror | github.com/borestad/blocklist-abuseipdb | High-confidence malicious IPs | Conservative, high precision |
| Tor Exit Nodes | github.com/SecOps-Institute/Tor-IP-Addresses | Known Tor exit points | Updated daily |

### Feed Poisoning Mitigation

- **Whitelist check**: Known legitimate IPs (8.8.8.8, 1.1.1.1) are never blocked
- **Cache fallback**: If a feed becomes unavailable, degrades to last-known-good cache
- **Feed health tracking**: Monitors freshness; logs alerts if feeds stale >24h
- **HTML error detection**: Rejects feeds that return error pages
- **Per-feed confidence**: Requires consensus across feeds (2+ hits) for block decisions

## File Structure

```
fraud-detection/
├── ingest/                    # Threat intelligence ingestion
│   ├── feed_fetcher.py       # Fetch and normalize threat feeds
│   └── ip_lookup.py          # Efficient IP reputation lookup
├── enrich/                    # Signal derivation
│   └── signal_deriver.py     # Extract behavioral signals
├── engine/                    # Scoring engine
│   └── rule_engine.py        # YAML rule evaluation
├── stream/                    # Real-time processing
│   └── processor.py          # Main pipeline orchestrator
├── rules/                     # YAML-based detection rules
│   └── 01_core_rules.yaml    # Starter rules (analyst-editable)
├── data/                      # Input/output and cached feeds
│   ├── traffic.jsonl         # Input traffic log
│   └── feeds/                # Cached threat feeds
├── docs/                      # Documentation
│   ├── DESIGN.md             # Architecture and scaling
│   ├── DETECTIONS.md         # Attack patterns identified
│   ├── ADVERSARIAL.md        # Evasion tactics
│   └── AI_USAGE.md           # AI collaboration log
├── tests/                     # Unit tests
│   └── test_signals_and_rules.py
├── main.py                    # Entry point
├── requirements.txt           # Python dependencies
├── .gitignore                 # Git configuration
└── README.md                  # This file
```

## Threat Patterns Identified

The system detects multiple attack patterns in the traffic log:

1. **Credential Stuffing**: Bursts of 401 Unauthorized responses from single IPs
2. **Voucher Scraping**: Automated high-velocity requests to `/voucher/redeem` from datacenter IPs
3. **Distributed Scraping**: Many accounts accessed from same IP (account farm indicator)
4. **Bot Traffic**: Requests with bot/crawler user-agents and suspicious JA3 fingerprints
5. **Tor Abuse**: Tor exit nodes accessing sensitive endpoints
6. **DDoS-like Velocity**: Extreme request rates (>50 req/min) from single IPs

See [DETECTIONS.md](docs/DETECTIONS.md) for detailed analysis.

## Monitoring & Alerts

Log file for feed health:
```
2026-05-28 10:15:22 - ingest.feed_fetcher - INFO - Fetching firehol_level1 from https://...
2026-05-28 10:15:25 - ingest.feed_fetcher - INFO - Successfully fetched firehol_level1: 125,432 entries
2026-05-28 10:15:26 - ingest.feed_fetcher - ERROR - Failed to fetch ipsum: Connection timeout
2026-05-28 10:15:26 - ingest.feed_fetcher - WARNING - Using stale cache for ipsum
```

Decision summary after each run shows:
- Distribution of allow/challenge/block decisions
- Score distribution
- Most frequently fired rules
- Most relevant signals

## Known Limitations

1. **Geolocation**: Currently disabled; set up MaxMind GeoLite2 for geo-based signals
2. **Real-time state**: State windows are in-memory; loses on process restart (fixable with Redis)
3. **Scoring**: Linear weight combination (can be enhanced with ML)
4. **Rule conditions**: Simple Python eval (safe but limited; could use dedicated DSL)

## Extending the System

### Adding a New Threat Feed

1. Add to `FEEDS` dict in `ingest/feed_fetcher.py`
2. Implement parsing logic in `_parse_feed()`
3. Load in `StreamProcessor.initialize_threat_intel()`

### Adding a New Signal

1. Implement derivation logic in `enrich/signal_deriver.py`
2. Add to signals dict returned by `derive_signals()`
3. Reference in rule conditions

### Custom Scoring Logic

To replace linear weight combination with ML:
1. Collect features + decisions during initial runs
2. Train classifier on labeled data
3. Swap rule engine evaluation with classifier predictions

## Contributing

Rules and signal improvements are welcomed:
1. Create feature branch
2. Add rule(s) to `/rules/`
3. Test against provided traffic log
4. Document in [DETECTIONS.md](docs/DETECTIONS.md)
5. Submit PR with precision/recall metrics

## Security Notes

- **Feed integrity**: All feeds are public; verify checksums if deployed in production
- **Credentials**: No credentials required for provided feeds
- **Data handling**: Decisions file can be logged to security SIEM
- **Feed caching**: Cache directory should be restricted to authorized users

## License

MIT

## Contact

See [DESIGN.md](docs/DESIGN.md) for architecture deep-dive.
