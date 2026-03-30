# 🔐 Weak Challenge-Response Authentication Simulator

A comprehensive security simulation tool demonstrating precomputation attacks on weak challenge-response authentication systems, with prevention mechanisms and live graph analysis.

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Mathematical Proof](#mathematical-proof)
3. [Attack Simulation](#attack-simulation)
4. [Prevention Mechanisms](#prevention-mechanisms)
5. [Installation](#installation)
6. [Usage Guide](#usage-guide)
7. [GUI Reference](#gui-reference)
8. [Graph Descriptions](#graph-descriptions)
9. [Comparative Analysis](#comparative-analysis)
10. [Test Case Methodology](#test-case-methodology)

---

## Overview

**Challenge-Response Authentication** is a security protocol where a server issues a challenge and the client must respond with a valid cryptographic answer (e.g., HMAC of the challenge using a shared secret). Security depends entirely on the **unpredictability of the challenge**.

This simulator demonstrates:

| Mode | Challenge Space | Attack Success |
|------|----------------|----------------|
| Counter-based | Sequential integers | ~100% |
| Timestamp-based | ±60s window = 121 values | ~100% |
| Sequential ID | `REQ-00001` pattern | ~100% |
| Small random (8-bit) | Only 256 possibilities | ~100% |
| **Large random (256-bit)** | 2²⁵⁶ possibilities | **~0%** |
| **Time-bound expiration** | Large + expiry window | **~0%** |
| **HMAC-signed challenge** | Server-authenticated | **~0%** |
| **Nonce + replay detect** | One-time use enforced | **~0%** |

---

## Mathematical Proof

### Why Weak Challenges Enable Precomputation

**Formal Model:**

Let:
- `C` = challenge space, `|C|` = cardinality  
- `f = HMAC-SHA256(key, ·)` : C → {0,1}²⁵⁶ (response function)  
- `T` = precomputed table `{ c → f(c) | c ∈ C }`

**Attack success probability:**

```
Pr[attack succeeds] = |precomputed ∩ C| / |C|
```

**Precomputation complexity:**

| Challenge Size | |C| | Precompute Time | Space |
|---|---|---|---|
| 8-bit random | 256 | ~0.25 ms | 256 × 32 bytes = 8 KB |
| Timestamp (±60s) | 121 | ~0.12 ms | 3.8 KB |
| Counter (N=10000) | 10,000 | ~10 ms | 320 KB |
| 32-bit random | 2³² ≈ 4.3B | ~72 min | 137 GB |
| **128-bit random** | **2¹²⁸** | **~forever** | **infeasible** |
| **256-bit random** | **2²⁵⁶** | **physically impossible** | **impossible** |

### Birthday Bound

After √|C| queries, collision probability ≈ 50%:

```
Pr[collision in n queries] ≈ 1 - e^(-n(n-1) / 2|C|)

8-bit:  √256 = 16 queries → 50% success in 16 attempts!
256-bit: √(2^256) = 2^128 queries → computationally infeasible
```

### Security of Large Random Challenges

```
Pr[guess 256-bit challenge] = 1 / 2^256 ≈ 8.6 × 10^-78

Atoms in observable universe ≈ 10^80
→ More secure than guessing one specific atom in the universe — twice.
```

---

## Attack Simulation

### Precomputation Attack Flow

```
1. Attacker observes authentication protocol
2. Identifies challenge generator is weak (counter/timestamp/small)
3. Precomputes table: T = { challenge → HMAC(key, challenge) }
4. When server issues challenge c*:
   - If c* ∈ T → attack succeeds (≥90% for weak generators)
   - Responds with T[c*] → authenticated!
```

### Weak Generator Details

**Counter-based:**
```python
# Challenges: "1", "2", "3", ... "N"
# Attacker precomputes all N responses before authentication begins
challenge = str(counter)   # trivially predictable
```

**Timestamp-based:**
```python
# Challenges: current Unix timestamp (1-second precision)
# Attacker precomputes ±60 second window = 121 values
challenge = str(int(time.time()))
```

**Sequential ID:**
```python
# Challenges: "REQ-00001", "REQ-00002", ...
# Structurally predictable
challenge = f"REQ-{counter:05d}"
```

**Small 8-bit random:**
```python
# Only 256 possible values!
# Full precomputation in <1ms
challenge = str(random.randint(0, 255))
```

---

## Prevention Mechanisms

### 1. Large Random (256-bit)

```python
import secrets
challenge = secrets.token_hex(32)  # 256-bit cryptographic RNG
# Space: 2^256 ≈ 10^77 possibilities
# Precomputation: physically impossible
```

**Why it works:** The challenge space is astronomically large. Even with all computing power on Earth, an attacker cannot precompute even a negligible fraction of the table.

### 2. Time-bound Expiration

```python
challenge = secrets.token_hex(16)
store[challenge] = (time.time(), False)   # timestamp + used flag

def validate(challenge, window_sec=5):
    ts, used = store[challenge]
    if used or (time.time() - ts) > window_sec:
        return False
    store[challenge] = (ts, True)  # mark used
    return True
```

**Why it works:** Even if an attacker somehow precomputes a challenge, it's only valid for `window_sec` seconds and can only be used once.

### 3. HMAC-Signed Challenge

```python
nonce = secrets.token_hex(16)
ts    = str(int(time.time()))
sig   = HMAC(server_key, f"{nonce}:{ts}")
challenge = f"{nonce}:{ts}:{sig}"

def validate(challenge):
    nonce, ts, sig = challenge.split(":")
    expected = HMAC(server_key, f"{nonce}:{ts}")
    if not constant_time_compare(sig, expected): return False
    return abs(time.time() - float(ts)) <= 5
```

**Why it works:** The server signs each challenge with its secret key. An attacker cannot forge a valid signed challenge without knowing the key.

### 4. Nonce + Replay Detection

```python
nonce = secrets.token_hex(32)
nonce_store.add(nonce)  # server tracks issued nonces

def validate(nonce):
    if nonce in nonce_store:
        nonce_store.discard(nonce)  # one-time use!
        return True
    return False  # replay or invalid
```

**Why it works:** Each nonce is used exactly once (like a one-time pad for challenges). Replayed responses are rejected.

---

## Installation

### Requirements

```
Python 3.9+
tkinter (usually bundled with Python)
matplotlib >= 3.5
numpy >= 1.21
```

### Install Dependencies

```bash
# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Linux/macOS
# OR
venv\Scripts\activate           # Windows

# Install required packages
pip install matplotlib numpy
```

> **Note:** `tkinter` and `hmac`, `hashlib`, `secrets` are part of Python's standard library — no extra install needed.

### Verify Installation

```bash
python -c "import tkinter, matplotlib, numpy, hmac, hashlib, secrets; print('All OK')"
```

---

## Usage Guide

### Quick Start

```bash
python challenge_auth_simulator.py
```

### Step-by-Step Workflow

#### Step 1 — Generate a Challenge Sample

1. Select a **Weak Challenge Generator** from the dropdown (e.g., `Counter-based`)
2. Click **⚙ Generate Challenge**
3. Observe 5 sample challenges printed in the log — notice their predictability

#### Step 2 — Run the Precomputation Attack

1. Keep the same generator selected
2. Set test count to **25**
3. Click **💥 Run Attack**
4. Watch the log: red entries = attack succeeded (≥90% expected)
5. Check the **Results Table** tab for per-test detail

#### Step 3 — Apply Prevention

1. Select a **Prevention Mechanism** (e.g., `Large random (256-bit)`)
2. Click **🛡 Apply Prevention**
3. Watch the log: green entries = attack failed (0% expected)

#### Step 4 — Show Graphs

1. Click **📊 Show All Graphs**
2. Review all 6 graphs in the Graphs tab

#### Step 5 — Full Automated Suite

1. Click **🔄 Run Full Suite (All Generators + Preventions)**
2. This runs all 4 attack types + all 4 prevention types automatically
3. Then click **📊 Show All Graphs** for comprehensive comparison

---

## GUI Reference

```
┌─────────────────────────────────────────────────────────────────────┐
│  🔐  Challenge-Response Auth Simulator                              │
│  Precomputation Attack Demo | HMAC-SHA256 | 25 Test Cases          │
├─────────────────────┬───────────────────────────────────────────────┤
│  CONTROLS           │  GRAPHS / MATH PROOF / RESULTS TABLE          │
│  ─────────────────  │  ─────────────────────────────────────────    │
│  Weak Generator:    │  [📊 Graphs Tab]                              │
│  [Counter-based ▼]  │    Graph 1: Before vs After Success Rate      │
│                     │    Graph 2: Time vs Challenge Size             │
│  Prevention:        │    Graph 3: CIA Rate Before/After             │
│  [Large random ▼]   │    Graph 4: Attack vs Prevention Latency      │
│                     │    Graph 5: Prevention Effectiveness           │
│  Test Cases: [25]   │    Graph 6: Security Improvement %            │
│                     │                                                │
│  [⚙ Generate]       │  [📐 Math Proof Tab]                          │
│  [💥 Run Attack]    │    Formal proofs, complexity analysis,         │
│  [🛡 Prevention]    │    birthday bounds, security definitions       │
│  [📊 Graphs]        │                                                │
│  [🔄 Full Suite]    │  [📋 Results Table Tab]                        │
│                     │    Per-test: challenge, response,             │
│  STATUS BAR         │    attacked response, success, latency        │
│  [Progress Bar]     │                                                │
│                     │                                                │
│  EVENT LOG          │                                                │
│  Red  = Vulnerable  │                                                │
│  Green= Secure      │                                                │
└─────────────────────┴───────────────────────────────────────────────┘
```

### Color Coding

| Color | Meaning |
|-------|---------|
| 🔴 Red | Attack succeeded — system is VULNERABLE |
| 🟢 Green | Attack failed — system is SECURE |
| 🔵 Blue | System / info messages |
| 🟡 Yellow | Challenge values / generated data |
| ⚪ Gray | Secondary information |

---

## Graph Descriptions

### Graph 1: Before vs After Attack Success Rate

Shows attack success rate (%) for each weak generator (red bars) vs each prevention mechanism (green bars). The 90% threshold line marks the minimum required attack success before prevention.

**Expected results:**
- Weak generators: 90–100% attack success
- Prevention mechanisms: 0% attack success

### Graph 2: Auth Time vs Challenge Size (bits)

Shows how HMAC computation time scales with challenge size (8 to 256 bits). Demonstrates that security doesn't come at a significant performance cost — 256-bit challenges add only microseconds.

### Graph 3: CIA Rate — Before vs After Prevention

Grouped bar chart showing **Confidentiality**, **Integrity**, and **Authentication** rates before (red) and after (green) applying prevention. All three CIA pillars improve to ~100% after prevention.

### Graph 4: Attack vs Prevention Latency Overhead

Compares average latency (ms) across all attack and prevention scenarios. Shows that prevention mechanisms have slightly higher latency due to cryptographic operations but remain well within acceptable bounds.

### Graph 5: Prevention Effectiveness Comparison

Horizontal bar chart comparing all prevention mechanisms by effectiveness percentage (100% - attack_success_rate). All secure mechanisms should show ~100%.

### Graph 6: Security Improvement vs Weak Baseline

Shows how many percentage points each prevention mechanism improves security over the weak baseline. For a 95% weak attack rate with 0% post-prevention rate, improvement = 95%.

---

## Comparative Analysis

### 3 Prevention Mechanisms Compared

| Mechanism | Effectiveness | Latency Overhead | Key Size | Replay Safe | Forgery Safe |
|-----------|--------------|-----------------|----------|-------------|--------------|
| Large random (256-bit) | 100% | Minimal | 256-bit | No extra | By size |
| Time-bound expiration | 100% | Low | 128-bit + timestamp | Yes (5s window) | By size |
| HMAC-signed challenge | 100% | Low | 128-bit + HMAC key | Yes (timestamp) | Yes (HMAC) |
| Nonce + replay detect | 100% | Low | 256-bit | Yes (one-time) | By size |

### RSA/DH Equivalent Guidance

This simulation uses HMAC-SHA256, but the principles apply to all protocols:

| Protocol | Minimum Key Size | Secure Challenge Size |
|----------|-----------------|----------------------|
| RSA | 2048-bit | ≥ 256-bit challenge |
| DH (Diffie-Hellman) | 2048-bit prime | ≥ 256-bit random |
| AES | 128-bit (min) / 256-bit (recommended) | ≥ 128-bit challenge |
| HMAC-SHA256 (this sim) | 256-bit | 256-bit challenge |

---

## Test Case Methodology

### Test Configuration

- **Test cases per run:** 20–25 (configurable)
- **Protocol:** HMAC-SHA256 with fixed 256-bit secret key
- **Variation:** Keys, inputs, and parameters vary per test
- **Attack model:** Precomputation table lookup

### Success Rate Calculation

```
Success Rate = (Successful Attacks / Total Tests) × 100

Before prevention: ≥ 90%   (requirement met by weak generators)
After prevention:  = 0%    (requirement met by all prevention mechanisms)
```

### Test Case Variation

Each of the 25 tests varies:
- Challenge value (different counter/timestamp/random value)
- Timing (slight delays simulate real network conditions)
- Attacker response strategy (table lookup for weak, random guess for prevention)

### Expected Results Summary

```
Generator          | 25 Tests | Expected Attack Rate
───────────────────┼──────────┼────────────────────
Counter-based      |    25    |    100.0%
Timestamp-based    |    25    |    100.0%
Sequential ID      |    25    |    100.0%
Small random (8b)  |    25    |    100.0%
                   |          |
Prevention         | 25 Tests | Expected Attack Rate
───────────────────┼──────────┼────────────────────
Large random 256b  |    25    |      0.0%
Time-bound (5s)    |    25    |      0.0%
HMAC-signed        |    25    |      0.0%
Nonce+replay       |    25    |      0.0%
```

---

## File Structure

```
.
├── challenge_auth_simulator.py    # Main application
└── README.md                      # This file
```

---

## Security Notes

> This simulator is for **educational purposes only**. The secret key is hardcoded for demonstration. In production:
> - Use environment variables or secure key stores for secrets
> - Use CSPRNG (`secrets` module) for all challenge generation
> - Implement server-side nonce tracking with TTL
> - Always use HMAC with constant-time comparison (`hmac.compare_digest`)
> - Consider challenge size of at least 128 bits; 256 bits recommended

---

## License

Educational use. No warranty expressed or implied.
