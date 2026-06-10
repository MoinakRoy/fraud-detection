# AI_USAGE: Collaboration Log

This document explains how AI was used to accelerate the fraud detection pipeline and how human judgment shaped the final design.

## Summary

| Aspect | AI Contribution | Human Contribution | Result |
|---|---|---|---|
| Architecture | Suggested a 4-stage pipeline | Refined scaling, state boundaries, and operational concerns | Clean separation of ingestion, enrichment, scoring, and output |
| Feed parsing | Generated initial feed parsers | Added whitelist, poisoning defenses, and validation | Robust threat-intel ingestion |
| Rule engine | Proposed declarative rule format | Chose YAML, weights, actions, and governance metadata | Analyst-friendly rules without code changes |
| Signal derivation | Brainstormed many candidate signals | Filtered to 15 practical signals | Focused on facts, not opinions |
| Behavioral tracking | Suggested time windows and state management | Designed multi-window cleanup and entity state | Efficient, real-time behavior tracking |
| Detection rules | Generated starter rules | Tuned thresholds for attack patterns | 12 rules covering six meaningful patterns |
| Documentation | Drafted initial structure | Added security analysis, scaling math, and limitations | Complete and credible documentation |
| Adversarial analysis | Wrote first-pass attack tactics | Added cost/benefit, game theory, and false-positive risk | Credible evasion defenses |

---

## Example 1: CIDR Parsing

### Prompt

```
Write a Python parser for firehol_level1.netset that:
- handles CIDR ranges
- supports comments
- builds a fast lookup structure
- validates entries
- supports IPv4 and IPv6
```

### AI output

The first version used a linear scan:

```python
for cidr in cidrs:
    if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
        return True
```

### Human refinement

That implementation works, but it is too slow for a feed with millions of CIDR ranges. The human decision was to separate single IPs from CIDR ranges and use a network-based lookup structure instead.

### Result

- Single IP addresses are stored in a set for O(1) lookup
- CIDR ranges are stored as networks and checked efficiently
- Feed parsing includes validation and HTML error detection

**Lesson**: AI provided working code. Human judgment improved performance and reliability.

---

## Example 2: Signal Derivation

### Prompt

```
Create fraud signals for:
- IP reputation
- geolocation
- behavioral patterns
- consistency across entities
- request patterns
```

### AI output

The model suggested 25+ signals, including:
- `ip_reputation_score`
- `asn_type`
- `ip_req_rate_1m`
- `account_unique_ips`
- `ua_is_bot`

It also proposed data points that were not available in the provided log, such as `time_since_account_creation`.

### Human refinement

The final design kept signals that were:
- computable from the traffic log
- fact-based rather than risk judgments
- actionable for rules

### Result

The pipeline uses a compact set of 15 practical signals, documented clearly for analysts.

**Lesson**: AI is useful for brainstorming; human reviewers must ensure the signal set matches data availability and domain relevance.

---

## Example 3: Feed Poisoning Defense

### Prompt

```
How do we defend public threat feeds against poisoning?
Example: an attacker adds 8.8.8.8 to a blocklist.
```

### AI output

The first answer was a simple whitelist:

```python
if entry in KNOWN_GOOD:
    skip(entry)
```

### Human refinement

That alone is insufficient. The final defense combines:
- a whitelist for known safe addresses
- multi-feed consensus before a block action triggers
- feed health and freshness tracking

### Result

The system avoids blocking on single-feed hits and flags stale or unavailable feeds.

**Lesson**: AI can identify a starting point, but humans must design layered defenses for real threat intelligence.

---

## Example 4: Rule Engine Design

### Prompt

```
Design a declarative rule engine where analysts can add rules without touching code.
```

### AI output

The initial draft used JSON and multiplicative scoring.

### Human refinement

The final design uses YAML because it is easier for analysts to read and edit. The rule schema includes:
- `id`
- `description`
- `severity`
- `weight`
- `condition`
- `action`
- `enabled`
- `owner`

The engine evaluates conditions, sums weights, and chooses `allow`, `challenge`, or `block`.

### Result

Rules are genuinely editable without code changes, and metadata supports governance.

**Lesson**: AI can propose structure; humans must decide the best format and scoring semantics.

---

## Example 5: Adversarial Thinking

### Prompt

```
Assume you are an attacker who knows our detection system. How would you evade it?
```

### AI output

The first pass was generic:
- use VPN
- slow down
- spoof user-agent

### Human refinement

The final analysis added:
- attacker cost/benefit
- why each evasion is expensive
- the trade-off between speed and stealth
- how defense layers force bad choices

### Result

The adversarial section now explains attacker dilemmas, not just tactics.

**Lesson**: AI generates ideas quickly, but humans must interpret them in context.

---

## Example 6: Rule Tuning

### Prompt

```
Run the pipeline on traffic.jsonl. Which rules fire most often?
Are thresholds too loose or too tight?
```

### AI output

The model identified noisy rules and offered candidates for refinement.

### Human refinement

One key change was to avoid blocking health checks by refining `bot_ua_detection` and similar rules.

### Result

Rules were tuned with specific conditions and after reviewing decision outputs.

**Lesson**: AI can help identify candidates for adjustment; humans validate and decide final thresholds.

---

## Example 7: Documentation

### Prompt

```
Write DESIGN.md with architecture, scaling, trust boundaries, and failure modes.
```

### AI output

The model produced a solid outline and draft sections.

### Human refinement

The final document added:
- scaling math from 50K to 1M requests per minute
- practical architecture options like Redis and Kafka
- failure mode handling for feed outages and poisoned data
- realistic throughput estimates

### Result

Design documentation is complete, concrete, and grounded in real operational trade-offs.

---

## Honest Assessment

### Where AI worked well
- generating boilerplate code
- drafting architecture and rule syntax
- framing documentation structure
- surfacing edge cases

### Where human judgment was essential
- performance optimization
- threat-intel poisoning defense
- adversarial modeling and attacker incentives
- false-positive risk and challenge-vs-block decisions
- domain-specific signal selection

### Recommended use of AI
Use AI for implementation drafts and documentation scaffolding, but keep humans in the loop for security design, tuning, and final validation.

---

## Collaboration Workflow

The most effective workflow was:
1. use AI to draft code or design options
2. review the draft for correctness and risk
3. revise with targeted feedback
4. validate with actual data and tests
5. repeat until stable

This approach saved time while preserving quality.

---

## Prompting Guidance

### Effective prompts
- “You are an attacker. List evasion tactics and explain the countermeasures.”
- “Generate a Python parser for CIDR ranges. Prioritize correctness over performance.”
- “List fraud detection signals and separate facts from judgments.”

### Ineffective prompts
- “Make it production-ready.”
- “Defend against all attacks.”
- “Optimize for performance.”

Clear constraints and concrete goals produced the best results.

---

## Credibility Note

This submission was not created entirely by AI.

Human contributions included:
- defining the four-stage architecture
- choosing practical signals
- designing multi-feed consensus and poison defenses
- writing the adversarial threat model
- tuning detection rules against data
- selecting YAML for rule configuration

AI accelerated implementation and documentation, but the security design and final decisions were human-led.
