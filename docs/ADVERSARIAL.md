# ADVERSARIAL: Evasion Tactics & Counter-Strategies

## Premise

This document assumes the attacker has read our entire detection system and understands:
- Signals we derive (reputation, velocity, consistency, patterns)
- Rules we evaluate
- Thresholds we use
- Feeds we consume

The goal: Explain how sophisticated attackers would evade our detection, and what counter-measures we employ.

---

## Threat 1: IP Reputation Evasion

### Attack: Residential Proxy Rotation

**Attacker's Strategy:**
```
Use 500+ residential proxy IPs (each different)
Each IP requests only 1-2 times (stays under rate limits)
Maintain single session/account across all IPs
Avoid any single IP being flagged
```

**Why this works:** Our rule fires when `ip_req_rate_1m > 15`. One request per minute passes.

**Example Attack Pattern:**
```
Time:  T+0s    T+60s   T+120s  T+180s
IP:    1.2.3.4 5.6.7.8 9.10.11.12 ...
Account: a_123  a_123  a_123  a_123
Path:  /voucher/redeem (same for all)
Result: Each IP appears legitimate (1 req)
        Account appears suspicious (accessed from 500 IPs)
```

### Our Counter: Distributed Scraping Rule

```yaml
- id: distributed_scraping_many_ips
  description: One account accessed from 20+ IPs
  severity: high
  weight: 32
  condition: signals.account_unique_ips > 20 and signals.ip_req_rate_1m < 10
  action: block
```

**How it works:**
- Track `account_unique_ips`: Count of distinct IPs per account
- Threshold: If > 20 IPs per account AND individual velocity is low → BLOCK
- This catches distributed attacks even if per-IP velocity is clean

**Why hard to evade:**
- Attacker must choose: either low-velocity (get caught by distributed rule) or high-velocity (get caught by rate limit rule)
- We don't need single IP to be flagged; the **pattern** is the signal

### Attacker's Counter-Evasion

1. **Use fewer IPs**: 3-5 IPs instead of 20
   - Our threshold is `> 20`, so this passes
   - **Our counter**: Tune threshold down to 5 based on traffic patterns
   - **Attacker counter**: Use 2 IPs max (harder for us to justify blocking legitimate travelers)

2. **Distribute across accounts**: 1 IP per account, 500 accounts from 500 IPs
   - Now `account_unique_ips = 1`, `ip_unique_accounts = 500`
   - Caught by our account farm rule: `ip_unique_accounts > 10`
   - **Tradeoff**: Attacker must sacrifice speed to maintain plausible deniability

3. **Slow down further**: 1 request per 5 minutes
   - No signal fires individually
   - But now attack takes weeks (impractical for time-sensitive vouchers)

### Defense Depth

**Decision Tree:**
```
Attacker chooses one of three strategies:

A) Fast, concentrated
   - High velocity from one IP
   - Caught by: ip_req_rate_1m > 15
   - Defense: Simple rate limit

B) Distributed, many IPs, few accounts
   - Low velocity per IP, but many IPs per account
   - Caught by: account_unique_ips > 20
   - Defense: Distributed scraping rule

C) Distributed, many IPs, many accounts
   - Low velocity per IP, low IPs per account
   - But: Same IPs across multiple accounts
   - Caught by: ip_unique_accounts > 10
   - Defense: Account farm rule

D) Ultra-slow, spread over time
   - 1 IP, 1 account, 1 request per 5 minutes
   - Not caught by velocity rules
   - Caught by: Manual review / ML anomaly
   - Defense: Behavioral ML (impossible to detect from HTTP alone)
```

**Attacker's only real option:** Ultra-slow attacks (weeks-long) become impractical for time-limited vouchers. For high-value vouchers, attacker must accept risk.

---

## Threat 2: TLS Fingerprint & User-Agent Spoofing

### Attack: Mimic Real Browser

**Attacker's Strategy:**
```
Use headless browser (Playwright, Puppeteer, Selenium)
Generate real TLS fingerprints (actual browser TLS handshake)
Spoof realistic user-agent
Add real HTTP headers (Accept, Accept-Encoding, etc.)
Appear indistinguishable from Chrome/Firefox
```

**Why this works:** Our bot detection rule:
```yaml
condition: signals.ua_is_bot and signals.path_class in ['voucher', 'auth', 'api']
```
Only triggers on obvious bot UAs (curl, wget). Headless browsers pass the check.

**Our Current Signal:**
```python
def _detect_bot_ua(user_agent: str) -> bool:
    bot_patterns = ['bot', 'crawler', 'curl', 'wget', 'python', 'java ']
    return any(pattern in ua.lower() for pattern in bot_patterns)
```

This is **bypassable**. Headless Chrome user-agent:
```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 
(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36
```
Looks identical to real Chrome.

### Our Counter: JA3 Fingerprint Consistency

```yaml
# Rule we should add (not in current set):
- id: uniform_ja3_high_velocity
  description: Same TLS fingerprint across 50+ requests with high velocity
  severity: medium
  weight: 18
  condition: signals.ip_unique_ja3s == 1 and signals.ip_req_rate_1m > 30
  action: challenge
```

**How it works:**
- Real humans: Browser crashes, updates, device changes → **JA3 changes over time**
- Bots: Same TLS config for hours → **JA3 constant**
- Signal: `ip_unique_ja3s == 1` (only 1 JA3 ever seen from this IP)

**Why hard for attacker:**
- Even headless browsers generate "real" TLS fingerprints, but:
  - Same fingerprint for 100+ requests is suspicious
  - Real users change devices/browsers

### Attacker's Counter-Evasion

1. **Rotate TLS fingerprints**: Use different headless browser instances
   - Expensive (many browser processes)
   - Each browser might have same TLS...still detectable
   - **Our counter**: Combine with velocity (if JA3 changes 5x/sec = bot)

2. **Use real browsers**: Buy botnets of compromised devices
   - Real TLS fingerprints ✓
   - Real user-agents ✓
   - Real browser behavior ✓
   - But: Cost $500-$5,000 to compromise 1,000 devices
   - **Attacker's decision**: For low-value vouchers, not worth it

3. **Use residential proxies with real browsers**:
   - Proxy service bundles compromised device
   - Expensive ($0.50-$2 per IP per hour)
   - For 500 IPs for 2 hours = $500-$2,000
   - **ROI calculation**: Voucher worth must exceed cost

---

## Threat 3: Language-Geography Mismatch Detection

### Attack: Accept-Language Spoofing

**Attacker's Strategy:**
```
Residential proxy in Brazil
But set Accept-Language: en-US (mismatch)
Hope we allow it as "just a traveler"
```

**Our Signal:**
```python
signals['lang_geo_mismatch'] = accept_language_country != geo_country
```

**Why it matters:** Legitimate travelers have mismatches. Attackers try to exploit this.

### Our Counter: Context-Aware Scoring

```yaml
# Current rule (conservative):
- id: suspicious_geo_lang_mismatch
  description: Geo-language mismatch with high velocity
  severity: low
  weight: 15
  condition: signals.lang_geo_mismatch and signals.ip_req_rate_1m > 20
  action: challenge
```

**Key insight:** Mismatch alone isn't suspicious. But mismatch + high velocity + datacenter ASN = very suspicious.

**Example:**
- Google user (en-US, browser in Brazil): `mismatch + velocity:2` → ALLOW
- Scraper (en-US, datacenter IP in Brazil, velocity:100): `mismatch + velocity:100` → CHALLENGE

### Attacker's Counter-Evasion

1. **Match the language**: 
   - Use residential proxy in Brazil
   - Set Accept-Language: pt-BR
   - Passes geo-language check
   - **Our counter**: Attacker can't know which country. If all proxies are Brazil and language is Brazil, it's suspicious for global e-commerce

2. **Accept the mismatch as "signal" but stay under velocity threshold**:
   - Mismatch + velocity < 20 → passes
   - Caught by other rules (account farm, distributed IPs)
   - **Our counter**: Multi-layered rules catch the pattern

---

## Threat 4: Threat Feed Poisoning

### Attack: Poison a Blocklist to Block Legitimate IPs

**Attacker's Strategy:**
```
1. Identify legitimate IP range (e.g., corporate customer, CDN egress)
2. Compromise a public blocklist OR submit malicious entry
3. Get legitimate IP added to threat feed
4. Our system loads feed, starts blocking legitimate traffic
5. Customer suffers DoS; they blame us or leave platform
```

**Example:**
- Our CDN's egress IP: 203.0.113.0/24
- Attacker submits to stampars/ipsum: "Add this to list of abusers"
- Feed updated
- We block our own traffic

### Why This Matters

This is **weaponized false positives**. The attacker doesn't steal data; they damage our reputation.

### Our Counter: Multi-Layer Feed Validation

**Layer 1: Whitelist Known Legitimate Ranges**

```python
WHITELIST_RANGES = [
    '8.8.8.8/32',              # Google DNS
    '1.1.1.1/32',              # Cloudflare DNS
    '208.67.222.222/32',       # OpenDNS
    # ... add customer IPs, CDN ranges
]

def _filter_whitelist(entries):
    return {e for e in entries if e not in WHITELIST_RANGES}
```

**Layer 2: Multi-Feed Consensus**

```yaml
- id: ip_reputation_multi_feed_hit
  description: IP flagged by 2+ threat feeds
  severity: high
  weight: 30
  condition: signals.flagged_feed_count >= 2
  action: block
```

**Key insight:** Require 2+ feeds to flag an IP before blocking. Single feed poisoning causes `flagged_feed_count == 1` → rule doesn't fire.

**Layer 3: Sanity Checks**

Check for obvious poisons:
```python
def _is_dangerous_entry(ip):
    # Block additions of known good IPs
    dangerous = ['8.8.8.8', '1.1.1.1', '208.67.222.222', '127.0.0.1']
    return ip in dangerous
```

**Layer 4: Analyst Review**

```yaml
- id: review_single_feed_hits
  description: Audit IPs flagged by only one feed
  severity: low
  action: investigate  # Alert analyst for manual review
```

### Attacker's Counter-Evasion

1. **Poison multiple feeds simultaneously**:
   - Attacker compromises 2+ blocklists
   - Adds legitimate IP to all
   - `flagged_feed_count >= 2` → BLOCK
   - **Our counter**: Choose feeds from different organizations/operators
   - **Cost for attacker**: Compromise multiple security research teams (high barrier)

2. **Poison feeds slowly**:
   - Add small numbers of legitimate IPs over weeks
   - Harder to notice pattern
   - **Our counter**: Monthly audit of "newly added IPs" for patterns
   - **Cost for attacker**: Very slow, low impact

### Defense Recommendation

```yaml
# Proposed rule to add:
- id: audit_single_feed_blocklist
  description: Flag IPs from single feed for analyst review
  severity: info
  weight: 0
  action: investigate
  condition: signals.flagged_feed_count == 1
  owner: security-team@company.com
```

This doesn't block, but alerts analyst to manually check if feed is poisoned.

---

## Threat 5: State-Based Attacks (Low-and-Slow)

### Attack: Exploit Velocity Window Boundaries

**Attacker's Strategy:**
```
We track:
- ip_req_rate_1m (rolling 1-minute window)
- Window resets every 60 seconds

Attacker:
- Sends 9 requests at T=0s (ip_req_rate_1m = 9)
- Waits for window to roll (T=59s)
- At T=59s, sends 9 more requests
- Window rolls at T=60s, count resets
- Repeat: Never exceeds 9 req/min; threshold is 10
- But sustains 540 requests/hour (attack-like velocity)
```

### Our Counter: Multiple Time Windows

```python
signals['ip_req_rate_1m'] = state.velocity_1m.count(ts)
signals['ip_req_rate_5m'] = state.velocity_5m.count(ts)
signals['ip_req_rate_10m'] = state.velocity_10m.count(ts)
signals['ip_req_rate_1h'] = state.velocity_1h.count(ts)
```

**Why this works:**
- Attacker can game 1m window
- Can't game 5m + 1h windows simultaneously
- Rule: `(ip_req_rate_1m > 20 OR ip_req_rate_5m > 15 OR ip_req_rate_10m > 12) and path_class == 'voucher'` → CATCH

### Further Defense: Behavioral Anomaly Detection

Instead of hard thresholds, detect **sudden changes**:
```python
# Pseudo-code: not implemented in current system
if ip_req_rate_1m > (historical_mean * 5):
    # Sudden spike (even if under absolute threshold)
    alert('anomaly_spike')
```

---

## Threat 6: False Positive Weaponization

### Attack: Force False Positives to Damage Trust

**Attacker's Strategy:**
```
1. Identify known false-positive triggers in our system
2. Generate traffic that matches legitimate patterns but triggers rules
3. Get legitimate customers blocked
4. Customers complain; we lose revenue/trust
```

**Example:**
- Attacker knows our rule: "200+ IPs per account → block"
- Attacker creates "honeypot" account u_test
- Attacker gets 200 VPN users to access u_test simultaneously
- Rule fires, u_test is blocked
- u_test customer complains
- We have false positive

### Our Counter: Challenge (CAPTCHA) Instead of Block

For medium-confidence signals, we use `challenge` (CAPTCHA):
```yaml
- id: distributed_scraping_many_ips
  description: One account accessed from 20+ IPs
  severity: high
  weight: 32
  condition: signals.account_unique_ips > 20
  action: challenge  # Not 'block'!
```

**Why this helps:**
- Legitimate user: Can solve CAPTCHA, passes through
- Attacker: Can't solve CAPTCHA at scale (or expensive to solve)
- **Result**: We don't block legitimate traffic; just slow it down

### Further Defense: Gradual Enforcement

```yaml
# Phase 1: Soft challenge (log only)
- id: distributed_scraping_phase1
  action: investigate
  condition: signals.account_unique_ips > 15

# Phase 2: CAPTCHA (after user feedback)
- id: distributed_scraping_phase2
  action: challenge
  condition: signals.account_unique_ips > 20

# Phase 3: Block (only high confidence)
- id: distributed_scraping_phase3
  action: block
  condition: signals.account_unique_ips > 50 and signals.ip_req_rate_1m > 2
```

---

## Threat 7: Rule Engine Attacks

### Attack: Exploit Rule Condition Parsing

**Attacker's Strategy:**
```
Learn rule syntax. Send requests designed to bypass.
Example: Our rule has condition "signals.ua_is_bot"
Attacker sends ua_is_bot=False in headers... but we parse user_agent, not ua_is_bot
```

This doesn't really work in our implementation because we derive signals server-side. But if rules were client-side or didn't validate inputs, this could matter.

### Our Counter: Server-Side Signal Derivation

```python
# User can't set signals; we derive them
signals['ua_is_bot'] = SignalDeriver._detect_bot_ua(request['user_agent'])
# request['user_agent'] is trusted (from our logging layer)
```

**Why this works:** Attacker can't directly set signals; they only control the request itself (IP, user-agent, headers). We derive signals server-side.

---

## Threat 8: Time-Based Attacks

### Attack: Exploit Timezone Differences, Time-of-Day Patterns

**Attacker's Strategy:**
```
Launch attack during low-monitoring hours (night, weekends)
Assumption: Fewer analysts monitoring; slower response

Our thresholds might be tuned for business hours
(e.g., challenging >100 req/min, acceptable during load test)
```

### Our Counter: Time-Aware Thresholds

```yaml
# Could add (not in current implementation):
- id: voucher_abuse_business_hours
  description: High velocity to voucher during business hours (strict)
  severity: high
  weight: 40
  condition: signals.asn_type == 'hosting' and signals.path_class == 'voucher' and signals.ip_req_rate_1m > 15 and hour in [8,9,10,11,12,13,14,15,16,17]
  action: block

- id: voucher_abuse_off_hours
  description: Any velocity to voucher outside business hours (sensitive)
  severity: high
  weight: 45
  condition: signals.asn_type == 'hosting' and signals.path_class == 'voucher' and signals.ip_req_rate_1m > 5
  action: block
```

---

## Summary: Attacker's Optimal Strategy

Given our multi-layered defenses:

1. **For low-value targets**: Too expensive to evade (costs > value)
2. **For medium-value targets**: Attacker must choose pain point:
   - **Fast attack** (hours): High cost, high detection risk
   - **Slow attack** (weeks): Low cost, but not worth it for time-limited vouchers
   - **Distributed attack**: High IP/account cost; requires botnet or residential proxies ($500+)
3. **For high-value targets**: Attacker may accept economics
   - Compromise internal employee or use extremely slow persistence
   - Evade all network-based detection

### Our Defense Recommendation

**Layered approach:**
1. Network signals (IP reputation, velocity) catch opportunistic attackers
2. Behavioral signals (distributed IPs, account farms) catch sophisticated attacks
3. Context rules (geo, language, ASN) add nuance
4. CAPTCHA/challenge reduces false positives
5. Multi-feed consensus prevents poisoning
6. Analyst review layer catches edge cases

**Cost-benefit for attacker:**
```
Success ROI = (Voucher value * success_rate) - (attack_cost + failure_risk)

For $50 voucher, attacker needs:
- High success rate (95%+)
- Low cost (<$100)
- Low risk of ban

Our system makes this difficult by combining cheap signals ($0) 
with expensive evasion tactics (residential proxies $500+)
```

---

## Recommendations for Future Defense

1. **Machine learning**: Train classifier on benign vs. attack traffic
2. **Behavioral baselining**: Model normal user behavior; detect deviations
3. **Impossible travel**: Flag accounts accessed from countries that would require FTL travel
4. **Browser fingerprinting**: Combine TLS + accept headers + timing for device matching
5. **Device binding**: Require same device/OS for account access
6. **Real-time threat intel**: Use Shodan/Censys to identify compromised IP ranges
7. **Incident response automation**: Auto-ban known attack infrastructure
