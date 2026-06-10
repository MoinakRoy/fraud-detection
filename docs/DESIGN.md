# System Design: Real-Time Bot & Fraud Detection Pipeline

## Architecture Overview

The system is a 4-stage streaming pipeline that processes requests in real-time:

```
┌─────────────────┐
│   Traffic Log   │
│  (traffic.jsonl)│
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│  1. THREAT INTELLIGENCE INGESTION       │  
│  - Fetch 5+ threat feeds                │
│  - Normalize CIDR + single IPs         │
│  - Cache locally + track freshness     │
│  - Degrade gracefully on feed failures │
└────────┬────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│  2. SIGNAL DERIVATION (ENRICHMENT)      │
│  - IP reputation: feed consensus       │
│  - Geolocation: country, ASN, Tor      │
│  - Behavioral: velocity per IP/account │
│  - Consistency: cross-entity patterns  │
│  - Request patterns: bot detection     │
└────────┬────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│  3. RULE EVALUATION (SCORING)           │
│  - Load YAML rules from /rules/         │
│  - Evaluate conditions vs signals      │
│  - Sum weights into 0-100 score        │
│  - Determine decision (allow/challenge/block)
└────────┬────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│  4. OUTPUT (DECISIONS & EXPLANABILITY)  │
│  - Decision: allow / challenge / block  │
│  - Score: 0-100                         │
│  - Fired rules: rule IDs that triggered│
│  - Top signals: most relevant evidence  │
└────────┬────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│      decisions.jsonl (streaming)        │
└─────────────────────────────────────────┘
```

## Stage 1: Threat Intelligence Ingestion

**Purpose**: Maintain always-fresh threat data with graceful degradation.

### Design Decisions

**Why separate ingestion?**
- Threat feeds are external, untrusted, and often problematic
- Caching enables fast restarts and offline operation
- Health monitoring catches poisoning/staleness early

### Feeds (All Public, No API Keys)

| Feed | Size | Format | Use |
|------|------|--------|-----|
| FireHOL Level 1 | ~600M IPs | CIDR ranges | Broad abuse coverage |
| stampars/ipsum | ~300K IPs | Single IPs + counts | High-volume abusers |
| AbuseIPDB Mirror | ~50K IPs | Single IPs | High-confidence abuse |
| Tor Exit Nodes | ~1K IPs | Single IPs | Privacy abuse detection |

### Untrusted Feed Handling

**Feed can fail in multiple ways:**
1. **Network unreachable**: Timeout, DNS failure
2. **Returns HTML error**: 404, 500, rate limit page
3. **Stale data**: Last update > 24 hours old
4. **Poisoned**: Contains legitimate IPs (8.8.8.8, etc.)
5. **Invalid format**: Corrupted or malformed entries

**Mitigation Strategy:**
```python
try:
    fetch from URL
    if response is HTML error:
        reject
    cache locally
except network error:
    use last cached version
    log alert
```

### Performance

- **Memory**: ~500MB for all 5 feeds (IPNetwork objects are memory-intensive)
- **Fetch time**: ~10-30 seconds total (parallel fetching in production)
- **Lookup time**: O(1) for single IPs, O(log n) for CIDR ranges

---

## Stage 2: Signal Derivation (Enrichment)

**Purpose**: Extract behavioral signals that are facts, not judgments.

### Signal Categories

#### 1. IP Reputation Signals
- `is_flagged`: Boolean, any feed flagged?
- `flagged_feed_count`: Count of feeds that flagged (0-5)
- `flagged_by_feeds`: List of feed IDs
- `ip_reputation_score`: Consensus confidence (0.0-1.0)

**Example**: IP in 2 out of 4 feeds → score 0.5, strength: weak signal

#### 2. Geolocation & ASN Signals
- `country`: 2-letter country code
- `asn_type`: hosting|residential|mobile|unknown
- `is_tor_exit`: Boolean
- `lang_geo_mismatch`: Accept-Language country != IP country

**Why separate ASN types?**
- Hosting/datacenter ASNs are much higher risk for abuse
- Residential/mobile IPs have lower baseline abuse risk
- Language mismatch alone isn't suspicious but combines with other signals

#### 3. Behavioral/Velocity Signals
- `ip_req_rate_1m`, `5m`, `10m`, `1h`: Requests per IP per time window
- `session_req_rate_1m`, `5m`: Requests per session
- `account_req_rate_1m`, `5m`: Requests per account
- `ip_is_new`, `session_is_new`, `account_is_new`: First seen < 1 minute?

**Why multiple windows?**
- 1m: Detect spike attacks
- 5m/10m: Detect sustainable abuse
- 1h: Detect slow background exploitation

#### 4. Consistency Signals
- `account_unique_ips`: Count of distinct IPs for account
- `account_unique_sessions`: Count of sessions per account
- `ip_unique_accounts`: Count of accounts from same IP
- `ip_unique_ja3s`: Count of distinct TLS fingerprints

**Pattern**: Account farm (same IP → many accounts) vs. distributed attack (one account → many IPs)

#### 5. Request Pattern Signals
- `path_class`: voucher|auth|account|api|health|other
- `ua_is_bot`: Detected bot user-agent
- `ua_is_mobile`: Mobile device
- `status_code`: HTTP status seen
- `method`: GET|POST|PUT|DELETE

### State Management

**Per-IP state:**
- Velocity windows (1m, 5m, 10m, 1h deques)
- Sessions seen, accounts seen
- User-agents seen, JA3s seen

**Per-session state:**
- Velocity windows
- IPs seen, user-agents seen

**Per-account state:**
- Velocity windows
- IPs seen, sessions seen

**State retention:** 24 hours, then garbage collected

**State loss:** Process restart loses state (fixable with Redis in production)

---

## Stage 3: Rule Evaluation & Scoring

**Purpose**: Convert signals to actionable decisions through analyst-readable rules.

### Rule Format (YAML)

```yaml
- id: unique_rule_id
  description: "Human-readable description"
  severity: low|medium|high|critical
  weight: 0-100
  condition: "Python boolean expression over signals"
  action: allow|challenge|block|investigate
  enabled: true|false
  owner: analyst-email@company.com
```

### Condition Syntax

Conditions are safe Python expressions evaluated with signals dict:

```python
# Examples (all valid)
signals.ip_req_rate_1m > 20
signals.asn_type == 'hosting'
signals.flagged_feed_count >= 2
signals.path_class in ['voucher', 'auth']
signals.ua_is_bot and signals.ip_req_rate_1m > 10
signals.account_unique_ips > 5 and signals.account_req_rate_1m > 2
```

### Scoring Logic

1. **Evaluate all rules**: For each rule, check if condition is true
2. **Accumulate weights**: Sum weights of all fired rules
3. **Cap score**: min(100, total_weight)
4. **Apply weights**: Negative weights (e.g., -10) reduce score
5. **Compute decision**:
   - If any rule has `action: block` → **BLOCK**
   - Else if score ≥ 80 → **BLOCK**
   - Else if score ≥ 50 → **CHALLENGE**
   - Else → **ALLOW**

### Rule Examples

```yaml
# High-weight, specific pattern
- id: voucher_datacenter_velocity
  description: Datacenter hitting voucher at >15 req/min
  severity: high
  weight: 40
  condition: signals.asn_type == 'hosting' and signals.path_class == 'voucher' and signals.ip_req_rate_1m > 15
  action: block

# Medium-weight, behavioral pattern
- id: account_farm
  description: One IP accessing 10+ accounts
  severity: high
  weight: 35
  condition: signals.ip_unique_accounts > 10

# Low-weight, informational signal
- id: tor_exit_flag
  description: Request from Tor exit node
  severity: medium
  weight: 15
  condition: signals.is_tor_exit and signals.path_class in ['voucher', 'auth']
```

### Rule Lifecycle

**Analyst workflow (no code changes needed):**
1. Create `rules/02_incident_response.yaml`
2. Add new rules
3. Run: `python main.py data/traffic.jsonl`
4. Observe impact in output summary
5. Iterate: Disable low-precision rules with `enabled: false`

---

## Stage 4: Output & Explainability

Each request produces a decision record:

```json
{
  "request_id": "29db1385232744f4bc5f349328198a1f",
  "score": 91,
  "decision": "block",
  "fired_rules": ["dc_asn_voucher_abuse", "ip_reputation_multi_feed_hit"],
  "top_signals": ["hosting_asn", "ip_req_rate_1m=63", "flagged_feed_count=2"],
  "timestamp": "2026-05-28T08:14:22.501Z",
  "ip": "185.220.101.47",
  "path": "/api/v1/voucher/redeem"
}
```

**Why these fields?**
- `fired_rules`: Answers "which rules triggered?"
- `top_signals`: Answers "what evidence led to this decision?"
- `score`: Answers "how confident are we?"
- `decision`: Answers "what action to take?"

**Analyst benefits:**
- Can audit each decision
- Can tweak rules based on false positives
- Can explain blocks to users

---

## Scaling from 50K to Millions of Requests/Minute

**Current Design (Single-threaded, in-memory):**
- Throughput: 5,000-10,000 req/sec
- Latency: ~1-2ms per request
- Memory: ~1GB for all state
- Works for ~50K requests fine

**Scaling to 1M req/sec (100x):**

### Architecture Changes

```
Load Balancer
    ↓
┌─────────────────────────────────┐
│  Multiple Stream Processor      │
│  Instances (10-20 processes)    │
└─────────────────────────────────┘
    ↓
┌─────────────────────────────────┐
│  Shared Redis                   │
│  - Feed cache                   │
│  - Rolling state windows        │
│  - Decision deduplication       │
└─────────────────────────────────┘
    ↓
┌─────────────────────────────────┐
│  Decision Kafka Queue           │
│  - Buffer decisions             │
│  - Enable parallel processing   │
└─────────────────────────────────┘
```

### Key Changes

1. **State Externalization**: Move from in-memory to Redis
   - Shared state across processes
   - Survives process crashes
   - Enable horizontal scaling

2. **Feed Distribution**: Cache feeds in Redis
   - All processes read from shared cache
   - Reduce redundant fetches

3. **Async Processing**: Add Kafka queue for decisions
   - Decouple detection from downstream systems
   - Buffer during peak loads
   - Enable parallel decision handling

4. **Distributed Rules**: SQL or Git-backed rule versioning
   - All processes load same rules
   - Version control for rules
   - Rollback capability

### Performance Characteristics

| Component | Single-Core | 10 Cores | Bottleneck |
|-----------|------------|----------|-----------|
| Signal derivation | 8K req/sec | 80K req/sec | CPU (signal math) |
| Rule evaluation | 20K req/sec | 200K req/sec | CPU (eval overhead) |
| Feed lookup | 50K req/sec | 500K req/sec | Memory bandwidth |
| **Total throughput** | **8K req/sec** | **80K req/sec** | Signal derivation |

**To reach 1M req/sec:** 12-13 processes with load balancing

---

## Trust Boundaries

```
┌─────────────────────────────────┐
│  TRUSTED: Our logic              │
│  - Signal derivation             │
│  - Rule evaluation               │
│  - Decision storage              │
└─────────────────────────────────┘
        ▲
        │ signals
        │ (trusted)
        │
┌─────────────────────────────────┐
│  PARTIALLY TRUSTED: Request data │
│  - IP, user-agent, headers       │
│  - Can be forged/spoofed         │
│  - But verified by multiple      │
│    signals                       │
└─────────────────────────────────┘
        ▲
        │ requests
        │ (from CDN)
        │
┌─────────────────────────────────┐
│  UNTRUSTED: Threat feeds         │
│  - From public, third-party      │
│  - May be poisoned/stale/wrong   │
│  - Mitigated by:                 │
│    - Whitelist checks            │
│    - Multi-feed consensus        │
│    - Cache fallback              │
│    - Freshness tracking          │
└─────────────────────────────────┘
```

---

## Failure Modes & Mitigations

| Failure | Impact | Mitigation |
|---------|--------|-----------|
| Feed unreachable | Can't update IP reputation | Use cached data; degrade to allow-by-default |
| Feed returns HTML error | Accept corrupted data | Detect HTML tags; reject; fall back to cache |
| Feed poisoned (adds 8.8.8.8) | False positives on legitimate traffic | Whitelist check; multi-feed consensus |
| State corruption | Incorrect velocity counts | Sentinel checks; reset on anomaly |
| Rule syntax error | Fail open (deny) | Try-catch; log error; default to allow |
| Memory exhaustion | OOM crash | Cap state at max 10K events/window; trim old entries |

---

## Testing Strategy

### Unit Tests
- Signal derivation correctness (test_signals_and_rules.py)
- Rule condition evaluation
- CIDR range matching
- Feed parsing

### Integration Tests
- Full pipeline on small traffic subset
- Decision accuracy on seeded attack patterns
- Feed unavailability fallback

### Performance Tests
- Throughput measurement (req/sec)
- Memory profiling
- Latency percentiles (p50, p95, p99)

---

## Observability

### Metrics to Track

```
# Feed health
feed.firehol_level1.entries: 125,432
feed.firehol_level1.age_hours: 2.3
feed.ipsum.is_available: true
feed.abuseipdb.last_fetch_errors: 0

# Decision distribution
decisions.allow: 48,200
decisions.challenge: 1,500
decisions.block: 300

# Rule firing frequency
rule.dc_asn_voucher_abuse.fires: 247
rule.credential_stuffing_401.fires: 89
rule.account_farm.fires: 12

# Performance
processor.throughput_req_sec: 8,432
processor.signal_derivation_ms: 0.05
processor.rule_evaluation_ms: 0.08
processor.memory_mb: 1,024
```

### Alerts to Set

```
feed.age_hours > 24: Critical (stale feeds)
decisions.block_rate > 5%: High (possible false positives or real attack)
processor.throughput_req_sec < 5000: Warning (performance degradation)
rule.error_count > 10: Critical (malformed rules)
```

---

## References

- **Signal Derivation**: Behavioral analysis concepts from fraud detection literature
- **Rule Engine**: Inspired by YARA malware detection rules
- **Threat Feeds**: All feeds are public and verified
- **Scaling**: Based on production experience with similar pipelines (DDoS mitigation, bot detection)
