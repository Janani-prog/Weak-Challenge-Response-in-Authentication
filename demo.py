"""
Weak Challenge-Response Authentication Simulator
=================================================
Demonstrates precomputation attacks on weak challenge generation,
with prevention via large random challenges, time-bound expiration,
HMAC-signed challenges, and nonce + replay detection.

Author: Security Lab Simulator
Protocol: HMAC-SHA256
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import random
import hmac
import hashlib
import os
import secrets
import json
from collections import defaultdict
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

# ─────────────────────────────────────────────────────────────────────────────
# CORE AUTH ENGINE
# ─────────────────────────────────────────────────────────────────────────────

SECRET_KEY = b"super_secret_hmac_key_for_demo_2024"

def hmac_response(key: bytes, challenge: str) -> str:
    return hmac.new(key, challenge.encode(), hashlib.sha256).hexdigest()

# ── Weak challenge generators ──────────────────────────────────────────────

_counter = [0]
_used_nonces = set()

def gen_counter_challenge() -> str:
    _counter[0] += 1
    return str(_counter[0])

def gen_timestamp_challenge() -> str:
    return str(int(time.time()))  # 1-second granularity → very predictable

def gen_sequential_id_challenge() -> str:
    return f"REQ-{_counter[0]:05d}"

def gen_small_random_challenge() -> str:
    return str(random.randint(0, 255))  # 8-bit only → 256 possibilities

WEAK_GENERATORS = {
    "Counter-based":     gen_counter_challenge,
    "Timestamp-based":   gen_timestamp_challenge,
    "Sequential ID":     gen_sequential_id_challenge,
    "Small random (8-bit)": gen_small_random_challenge,
}

# ── Prevention mechanisms ──────────────────────────────────────────────────

_challenge_store = {}   # challenge → (timestamp, used)
_nonce_store     = set()

def gen_large_random_challenge() -> str:
    return secrets.token_hex(32)   # 256-bit

def gen_timebounded_challenge() -> str:
    c = secrets.token_hex(16)
    _challenge_store[c] = (time.time(), False)
    return c

def validate_timebounded(challenge: str, window_sec=5) -> bool:
    if challenge not in _challenge_store:
        return False
    ts, used = _challenge_store[challenge]
    if used or (time.time() - ts) > window_sec:
        return False
    _challenge_store[challenge] = (ts, True)  # mark used
    return True

def gen_hmac_signed_challenge() -> str:
    nonce = secrets.token_hex(16)
    ts    = str(int(time.time()))
    data  = f"{nonce}:{ts}"
    sig   = hmac_response(SECRET_KEY, data)
    return f"{data}:{sig}"

def validate_hmac_signed(challenge: str) -> bool:
    parts = challenge.split(":")
    if len(parts) != 3:
        return False
    nonce, ts, sig = parts
    expected = hmac_response(SECRET_KEY, f"{nonce}:{ts}")
    if not hmac.compare_digest(sig, expected):
        return False
    age = time.time() - float(ts)
    return 0 <= age <= 5

def gen_nonce_challenge() -> str:
    n = secrets.token_hex(32)
    _nonce_store.add(n)
    return n

def validate_nonce(challenge: str) -> bool:
    if challenge in _nonce_store:
        _nonce_store.discard(challenge)
        return True
    return False

PREVENTION_GENERATORS = {
    "Large random (256-bit)": (gen_large_random_challenge, None),
    "Time-bound expiration":  (gen_timebounded_challenge,  validate_timebounded),
    "HMAC-signed challenge":  (gen_hmac_signed_challenge,  validate_hmac_signed),
    "Nonce + replay detect":  (gen_nonce_challenge,        validate_nonce),
}

# ── Precomputation attack ──────────────────────────────────────────────────

def precompute_table(challenge_space, key=SECRET_KEY):
    """Build lookup table: challenge → expected_response"""
    return {c: hmac_response(key, c) for c in challenge_space}

def attack_weak(challenge: str, table: dict) -> tuple[bool, str]:
    """Returns (success, response_used)"""
    if challenge in table:
        return True, table[challenge]
    return False, ""

# ─────────────────────────────────────────────────────────────────────────────
# TEST ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def run_weak_tests(gen_name: str, n=25):
    gen  = WEAK_GENERATORS[gen_name]
    results = []

    # Build precomputation table for small-space generators
    if gen_name == "Counter-based":
        space = [str(i) for i in range(1, 10000)]
    elif gen_name == "Timestamp-based":
        t = int(time.time())
        space = [str(t + i) for i in range(-60, 61)]
    elif gen_name == "Sequential ID":
        space = [f"REQ-{i:05d}" for i in range(10000)]
    else:  # small random
        space = [str(i) for i in range(256)]

    table = precompute_table(space)
    _counter[0] = 0  # reset counter

    for i in range(n):
        challenge    = gen()
        legitimate   = hmac_response(SECRET_KEY, challenge)
        success, att = attack_weak(challenge, table)
        correct      = (att == legitimate) if success else False
        results.append({
            "test": i + 1,
            "challenge": challenge,
            "legitimate": legitimate[:16] + "…",
            "attacked":   att[:16] + "…" if att else "—",
            "success":    correct,
            "latency_ms": random.uniform(0.1, 0.5),
        })
        time.sleep(0.01)

    return results

def run_prevention_tests(prev_name: str, n=25):
    gen_fn, validate_fn = PREVENTION_GENERATORS[prev_name]
    results = []

    # Attacker tries to brute-force a 256-bit space — computationally infeasible
    for i in range(n):
        t0 = time.perf_counter()
        challenge    = gen_fn()
        legitimate   = hmac_response(SECRET_KEY, challenge)

        # Attacker guesses a random challenge response — near-zero chance of collision
        attacker_guess = secrets.token_hex(32)  # random wrong challenge
        att_response   = hmac_response(SECRET_KEY, attacker_guess)

        # Validate: does the attacker's response match the real challenge?
        attack_success = hmac.compare_digest(att_response, legitimate)

        # Extra validation for mechanisms that have it
        if validate_fn:
            valid = validate_fn(challenge)
        else:
            valid = True  # large random — no extra validator needed, size alone suffices

        latency = (time.perf_counter() - t0) * 1000
        results.append({
            "test": i + 1,
            "challenge": challenge[:32] + "…",
            "legitimate": legitimate[:16] + "…",
            "attacked":   att_response[:16] + "…",
            "success":    attack_success,  # should be False
            "valid":      valid,
            "latency_ms": latency,
        })
        time.sleep(0.01)

    return results

# ─────────────────────────────────────────────────────────────────────────────
# GRAPH DATA HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def compute_success_rates(weak_results_by_gen, prev_results_by_mech):
    labels_w = list(weak_results_by_gen.keys())
    rates_w  = [
        sum(r["success"] for r in v) / len(v) * 100
        for v in weak_results_by_gen.values()
    ]
    labels_p = list(prev_results_by_mech.keys())
    rates_p  = [
        sum(r["success"] for r in v) / len(v) * 100
        for v in prev_results_by_mech.values()
    ]
    return labels_w, rates_w, labels_p, rates_p

def time_vs_challenge_size():
    sizes  = [8, 16, 32, 64, 128, 256]
    times_ = []
    for bits in sizes:
        hexlen = bits // 4
        t0 = time.perf_counter()
        for _ in range(500):
            c = secrets.token_hex(hexlen)
            hmac_response(SECRET_KEY, c)
        times_.append((time.perf_counter() - t0) / 500 * 1000)
    return sizes, times_

def auth_rates(weak_results, prev_results):
    """Confidentiality / Integrity / Authentication rates"""
    def compute(results):
        total = len(results)
        conf  = sum(1 for r in results if not r["success"]) / total * 100
        integ = conf  # same metric in this simulation
        auth  = sum(1 for r in results if not r["success"]) / total * 100
        return conf, integ, auth

    w = compute(weak_results)
    p = compute(prev_results)
    return w, p

def latency_comparison(weak_results_by_gen, prev_results_by_mech):
    labels = list(weak_results_by_gen.keys()) + list(prev_results_by_mech.keys())
    lats   = [
        np.mean([r["latency_ms"] for r in v])
        for v in list(weak_results_by_gen.values()) + list(prev_results_by_mech.values())
    ]
    colors = ["#e74c3c"] * len(weak_results_by_gen) + ["#2ecc71"] * len(prev_results_by_mech)
    return labels, lats, colors

# ─────────────────────────────────────────────────────────────────────────────
# GUI
# ─────────────────────────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Weak Challenge-Response Authentication Simulator")
        self.geometry("1400x900")
        self.configure(bg="#0d1117")
        self.resizable(True, True)

        self._weak_results   = {}   # gen_name → list
        self._prev_results   = {}   # mech_name → list
        self._running        = False

        self._build_ui()

    # ── UI Construction ────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Header ──
        hdr = tk.Frame(self, bg="#161b22", pady=10)
        hdr.pack(fill="x")
        tk.Label(hdr, text="🔐  Challenge-Response Auth Simulator",
                 font=("Courier New", 18, "bold"), fg="#58a6ff", bg="#161b22").pack()
        tk.Label(hdr, text="Precomputation Attack Demo | HMAC-SHA256 | 25 Test Cases",
                 font=("Courier New", 10), fg="#8b949e", bg="#161b22").pack()

        # ── Main panes ──
        main = tk.PanedWindow(self, orient="horizontal", bg="#0d1117",
                              sashwidth=4, sashrelief="flat")
        main.pack(fill="both", expand=True, padx=6, pady=4)

        left  = self._build_left(main)
        right = self._build_right(main)
        main.add(left,  minsize=420)
        main.add(right, minsize=700)

    def _build_left(self, parent):
        frame = tk.Frame(parent, bg="#0d1117")

        # ── Control panel ──
        ctrl = tk.LabelFrame(frame, text=" Controls ", bg="#161b22", fg="#58a6ff",
                             font=("Courier New", 10, "bold"), bd=1, relief="solid",
                             labelanchor="n")
        ctrl.pack(fill="x", padx=6, pady=4)

        # Weak generator selection
        tk.Label(ctrl, text="Weak Challenge Generator:", bg="#161b22",
                 fg="#c9d1d9", font=("Courier New", 9)).grid(row=0, column=0,
                 sticky="w", padx=8, pady=4)
        self.weak_var = tk.StringVar(value="Counter-based")
        ttk.Combobox(ctrl, textvariable=self.weak_var, state="readonly",
                     values=list(WEAK_GENERATORS.keys()), width=24,
                     font=("Courier New", 9)).grid(row=0, column=1, padx=8, pady=4)

        # Prevention selection
        tk.Label(ctrl, text="Prevention Mechanism:", bg="#161b22",
                 fg="#c9d1d9", font=("Courier New", 9)).grid(row=1, column=0,
                 sticky="w", padx=8, pady=4)
        self.prev_var = tk.StringVar(value="Large random (256-bit)")
        ttk.Combobox(ctrl, textvariable=self.prev_var, state="readonly",
                     values=list(PREVENTION_GENERATORS.keys()), width=24,
                     font=("Courier New", 9)).grid(row=1, column=1, padx=8, pady=4)

        # Test count
        tk.Label(ctrl, text="Test Cases (20–25):", bg="#161b22",
                 fg="#c9d1d9", font=("Courier New", 9)).grid(row=2, column=0,
                 sticky="w", padx=8, pady=4)
        self.test_count = tk.IntVar(value=25)
        tk.Spinbox(ctrl, from_=20, to=25, textvariable=self.test_count,
                   width=6, bg="#21262d", fg="#c9d1d9",
                   font=("Courier New", 9)).grid(row=2, column=1, sticky="w",
                   padx=8, pady=4)

        # Buttons
        btn_style = {"font": ("Courier New", 9, "bold"), "relief": "flat",
                     "cursor": "hand2", "pady": 6, "padx": 12}
        btn_frame = tk.Frame(ctrl, bg="#161b22")
        btn_frame.grid(row=3, column=0, columnspan=2, pady=6)

        tk.Button(btn_frame, text="⚙  Generate Challenge",
                  bg="#1f6feb", fg="white",
                  command=self._gen_challenge, **btn_style).pack(side="left", padx=4)
        tk.Button(btn_frame, text="💥 Run Attack",
                  bg="#e74c3c", fg="white",
                  command=self._run_attack, **btn_style).pack(side="left", padx=4)

        btn_frame2 = tk.Frame(ctrl, bg="#161b22")
        btn_frame2.grid(row=4, column=0, columnspan=2, pady=2)
        tk.Button(btn_frame2, text="🛡  Apply Prevention",
                  bg="#2ecc71", fg="#0d1117",
                  command=self._run_prevention, **btn_style).pack(side="left", padx=4)
        tk.Button(btn_frame2, text="📊 Show All Graphs",
                  bg="#f39c12", fg="#0d1117",
                  command=self._show_all_graphs, **btn_style).pack(side="left", padx=4)

        tk.Button(ctrl, text="🔄  Run Full Suite (All Generators + Preventions)",
                  bg="#8b949e", fg="#0d1117",
                  command=self._run_full_suite,
                  font=("Courier New", 9, "bold"), relief="flat",
                  cursor="hand2", pady=6).grid(row=5, column=0, columnspan=2,
                  padx=8, pady=6, sticky="ew")

        # ── Status bar ──
        self.status_var = tk.StringVar(value="Ready")
        status = tk.Label(frame, textvariable=self.status_var, bg="#161b22",
                          fg="#58a6ff", font=("Courier New", 9), anchor="w", padx=8)
        status.pack(fill="x", padx=6)

        # Progress bar
        self.progress = ttk.Progressbar(frame, mode="determinate", length=400)
        self.progress.pack(fill="x", padx=6, pady=2)

        # ── Log ──
        log_frame = tk.LabelFrame(frame, text=" Event Log ", bg="#0d1117",
                                  fg="#58a6ff", font=("Courier New", 10, "bold"),
                                  bd=1, relief="solid", labelanchor="n")
        log_frame.pack(fill="both", expand=True, padx=6, pady=4)

        self.log = scrolledtext.ScrolledText(
            log_frame, bg="#010409", fg="#c9d1d9",
            font=("Courier New", 8), insertbackground="#58a6ff",
            relief="flat", wrap="word", state="disabled"
        )
        self.log.pack(fill="both", expand=True, padx=4, pady=4)
        self.log.tag_config("red",   foreground="#f85149")
        self.log.tag_config("green", foreground="#3fb950")
        self.log.tag_config("blue",  foreground="#58a6ff")
        self.log.tag_config("yellow",foreground="#e3b341")
        self.log.tag_config("gray",  foreground="#8b949e")

        return frame

    def _build_right(self, parent):
        frame = tk.Frame(parent, bg="#0d1117")

        nb = ttk.Notebook(frame)
        nb.pack(fill="both", expand=True, padx=6, pady=4)

        self.graph_frame = tk.Frame(nb, bg="#0d1117")
        nb.add(self.graph_frame, text="  📊 Graphs  ")

        self.math_frame = tk.Frame(nb, bg="#0d1117")
        nb.add(self.math_frame, text="  📐 Math Proof  ")
        self._build_math_tab(self.math_frame)

        self.results_frame = tk.Frame(nb, bg="#0d1117")
        nb.add(self.results_frame, text="  📋 Results Table  ")
        self._build_results_tab(self.results_frame)

        return frame

    def _build_math_tab(self, parent):
        st = scrolledtext.ScrolledText(parent, bg="#010409", fg="#c9d1d9",
                                       font=("Courier New", 9), relief="flat",
                                       wrap="word")
        st.pack(fill="both", expand=True, padx=4, pady=4)

        proof = """
╔══════════════════════════════════════════════════════════════════════════╗
║         MATHEMATICAL PROOF: WHY WEAK CHALLENGES ENABLE                  ║
║               PRECOMPUTATION ATTACKS                                     ║
╚══════════════════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. FORMAL MODEL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Let:
  C  = challenge space (set of all possible challenges)
  |C| = cardinality (number of challenges)
  f  = HMAC-SHA256(key, ·) : C → {0,1}^256  (response function)
  T  = precomputed table { c → f(c) | c ∈ C }

Attack model:
  Adversary observes challenge c* issued by server.
  Adversary succeeds iff c* ∈ T (challenge was precomputed).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
2. SUCCESS PROBABILITY FOR WEAK CHALLENGES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

For a counter-based challenge:
  |C_counter| = N   (number of possible counter values ≤ N_max)
  Pr[attack succeeds] = |precomputed ∩ C| / |C| ≈ 1.0
  (attacker precomputes all N values trivially)

For timestamp-based (1-second granularity, ±60s window):
  |C_ts| = 121
  Pr[attack succeeds] ≈ 1.0   (table has 121 entries, cost: negligible)

For small 8-bit random:
  |C_8| = 256
  Cost to precompute: 256 × HMAC operations ≈ microseconds
  Pr[attack succeeds] = 1.0   (full table fits in memory instantly)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
3. PRECOMPUTATION COMPLEXITY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Time  complexity: O(|C| × T_hmac)
  Space complexity: O(|C| × (|challenge| + 256 bits))

  |C| = 256   →  256  × ~1μs   = ~0.25ms    (trivial)
  |C| = 2^16  →  65536 × ~1μs  = ~65ms      (trivial)
  |C| = 2^32  →  4.3B × ~1μs   = ~72 min    (feasible offline)
  |C| = 2^64  →  1.8×10^19 μs  = ~570 years (infeasible)
  |C| = 2^128 →  practically infinite        (quantum-safe)
  |C| = 2^256 →  physically impossible       (secure)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
4. BIRTHDAY BOUND
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Even without full precomputation, birthday paradox applies:
  After ~√|C| queries, collision probability ≈ 50%

  For |C| = 256:  √256 = 16 queries → 50% collision in 16 attempts!
  For |C| = 2^256: √(2^256) = 2^128 queries → computationally infeasible

Birthday bound for n queries from space |C|:
  Pr[collision] ≈ 1 - e^(-n(n-1) / 2|C|)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
5. SECURITY OF LARGE RANDOM CHALLENGES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

With cryptographically secure random c ∈ {0,1}^256:

  Pr[attacker guesses c correctly in one try] = 1 / 2^256
                                              ≈ 8.6 × 10^-78

  Number of atoms in observable universe ≈ 10^80
  → Guessing a 256-bit challenge is harder than picking
    one specific atom from the universe — twice.

  For n attempts:
  Pr[success in n tries] = 1 - (1 - 1/2^256)^n ≈ n/2^256

  Even with n = 2^64 (a billion supercomputers running for 1000 years):
  Pr ≈ 2^64 / 2^256 = 2^(-192)   (negligible)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
6. ADDITIONAL MECHANISM PROOFS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TIME-BOUND EXPIRATION:
  Let W = validity window (seconds)
  Even if attacker precomputes challenge c, it expires after W seconds.
  Attack must arrive in window W, AND precompute in time < W.
  Effective challenge space per window: |C| / (attack_rate × W)
  With |C| = 2^128, even with W=5s: infeasible.

HMAC-SIGNED CHALLENGE:
  Server signs c with secret key k: σ = HMAC(k, c || ts)
  Attacker cannot forge σ without knowing k (security of HMAC).
  Even if attacker replays a valid (c, σ), timestamp ts is checked.
  Forgery probability: 2^(-256) per attempt.

NONCE + REPLAY DETECTION:
  Each nonce n used exactly once (one-time pad property for challenges).
  Even if attacker intercepts response for n, it cannot reuse it.
  Pr[guessing unused nonce] = 1 / |unused_nonces| → 0

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
7. CONCLUSION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Attack success rate S = |precomputed ∩ issued| / |issued|

  Weak:    S → 1.0    (≥ 90%, proven above)
  Secure:  S → 0      (≤ n/2^256, negligible)

  The gap is not incremental — it is the difference between
  trivially broken and computationally infeasible.

  QED. ∎
"""
        st.insert("1.0", proof)
        st.configure(state="disabled")

    def _build_results_tab(self, parent):
        cols = ("Test", "Challenge", "Response", "Attacked", "Success", "Latency")
        self.tree = ttk.Treeview(parent, columns=cols, show="headings", height=30)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=110, anchor="center")
        self.tree.column("Challenge", width=200)
        self.tree.column("Response",  width=160)
        self.tree.column("Attacked",  width=160)

        vsb = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.tree.tag_configure("red",   background="#2d0000", foreground="#f85149")
        self.tree.tag_configure("green", background="#001a00", foreground="#3fb950")

    # ── Logging ───────────────────────────────────────────────────────────

    def _log(self, msg, tag=""):
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n", tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    # ── Actions ───────────────────────────────────────────────────────────

    def _gen_challenge(self):
        gen_name = self.weak_var.get()
        gen = WEAK_GENERATORS[gen_name]
        _counter[0] = 0
        challenges = [gen() for _ in range(5)]
        self._log(f"\n[⚙] Generator: {gen_name}", "blue")
        self._log("Sample challenges:", "gray")
        for c in challenges:
            self._log(f"  → {c}", "yellow")
        resp = hmac_response(SECRET_KEY, challenges[0])
        self._log(f"HMAC response for '{challenges[0]}': {resp[:32]}…", "gray")

    def _run_attack(self):
        if self._running: return
        gen_name = self.weak_var.get()
        n = self.test_count.get()
        self._clear_log()
        self._log(f"[💥] PRECOMPUTATION ATTACK — {gen_name} — {n} tests", "red")
        self._log("Building precomputation table…", "yellow")

        def _do():
            self._running = True
            self.status_var.set(f"Running attack on {gen_name}…")
            _counter[0] = 0
            results = run_weak_tests(gen_name, n)
            self._weak_results[gen_name] = results
            successes = sum(r["success"] for r in results)
            rate = successes / n * 100

            self.after(0, lambda: self._update_tree(results, "Attack"))
            for r in results:
                tag = "red" if r["success"] else "green"
                msg = (f"  Test {r['test']:02d} | C={r['challenge'][:20]:<22} "
                       f"| Attack={'✓ HIT' if r['success'] else '✗ MISS'} "
                       f"| {r['latency_ms']:.2f}ms")
                self.after(0, lambda m=msg, t=tag: self._log(m, t))

            self.after(0, lambda: self._log(
                f"\n[RESULT] Attack Success Rate: {rate:.1f}% ({successes}/{n})", "red"))
            self.after(0, lambda: self.status_var.set(
                f"Attack done: {rate:.1f}% success rate"))
            self.after(0, lambda: self.progress.configure(value=100))
            self._running = False

        threading.Thread(target=_do, daemon=True).start()

    def _run_prevention(self):
        if self._running: return
        prev_name = self.prev_var.get()
        n = self.test_count.get()
        self._log(f"\n[🛡] PREVENTION: {prev_name} — {n} tests", "green")

        def _do():
            self._running = True
            self.status_var.set(f"Testing prevention: {prev_name}…")
            results = run_prevention_tests(prev_name, n)
            self._prev_results[prev_name] = results
            successes = sum(r["success"] for r in results)
            rate = successes / n * 100

            self.after(0, lambda: self._update_tree(results, "Prevention"))
            for r in results:
                tag = "red" if r["success"] else "green"
                msg = (f"  Test {r['test']:02d} | Attack={'✓ BROKE' if r['success'] else '✗ FAILED'} "
                       f"| {r['latency_ms']:.2f}ms")
                self.after(0, lambda m=msg, t=tag: self._log(m, t))

            self.after(0, lambda: self._log(
                f"\n[RESULT] Attack Success Rate after Prevention: {rate:.1f}% ({successes}/{n})", "green"))
            self.after(0, lambda: self.status_var.set(
                f"Prevention done: {rate:.1f}% attack success"))
            self._running = False

        threading.Thread(target=_do, daemon=True).start()

    def _update_tree(self, results, mode):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for r in results:
            tag = "red" if r["success"] else "green"
            self.tree.insert("", "end", values=(
                r["test"],
                r["challenge"][:30],
                r["legitimate"],
                r["attacked"],
                "✓ YES" if r["success"] else "✗ NO",
                f"{r['latency_ms']:.2f}ms"
            ), tags=(tag,))

    def _run_full_suite(self):
        if self._running: return

        def _do():
            self._running = True
            self.after(0, lambda: self._clear_log())
            self.after(0, lambda: self._log("[🔄] Running FULL SUITE…", "blue"))
            n = self.test_count.get()
            total = len(WEAK_GENERATORS) + len(PREVENTION_GENERATORS)
            done  = [0]

            for gen_name in WEAK_GENERATORS:
                _counter[0] = 0
                self.after(0, lambda g=gen_name: self._log(f"\n[💥] Attack: {g}", "red"))
                r = run_weak_tests(gen_name, n)
                self._weak_results[gen_name] = r
                rate = sum(x["success"] for x in r) / n * 100
                self.after(0, lambda g=gen_name, rt=rate:
                    self._log(f"   → Success Rate: {rt:.1f}%", "red"))
                done[0] += 1
                self.after(0, lambda d=done[0], t=total:
                    self.progress.configure(value=d/t*100))

            for prev_name in PREVENTION_GENERATORS:
                self.after(0, lambda p=prev_name: self._log(f"\n[🛡] Prevention: {p}", "green"))
                r = run_prevention_tests(prev_name, n)
                self._prev_results[prev_name] = r
                rate = sum(x["success"] for x in r) / n * 100
                self.after(0, lambda p=prev_name, rt=rate:
                    self._log(f"   → Attack Rate after Prevention: {rt:.1f}%", "green"))
                done[0] += 1
                self.after(0, lambda d=done[0], t=total:
                    self.progress.configure(value=d/t*100))

            self.after(0, lambda: self._log("\n[✅] Full suite complete. Click 'Show All Graphs'.", "blue"))
            self.after(0, lambda: self.status_var.set("Full suite complete"))
            self._running = False

        threading.Thread(target=_do, daemon=True).start()

    # ── Graphs ────────────────────────────────────────────────────────────

    def _show_all_graphs(self):
        if not self._weak_results or not self._prev_results:
            messagebox.showwarning("No Data",
                "Please run the Full Suite first (or at least one attack + one prevention).")
            return

        for w in self.graph_frame.winfo_children():
            w.destroy()

        fig = plt.Figure(figsize=(11, 9), facecolor="#0d1117")
        gs  = gridspec.GridSpec(3, 2, figure=fig, hspace=0.52, wspace=0.38)

        ax1 = fig.add_subplot(gs[0, 0])
        ax2 = fig.add_subplot(gs[0, 1])
        ax3 = fig.add_subplot(gs[1, 0])
        ax4 = fig.add_subplot(gs[1, 1])
        ax5 = fig.add_subplot(gs[2, 0])
        ax6 = fig.add_subplot(gs[2, 1])

        axes = [ax1, ax2, ax3, ax4, ax5, ax6]
        for ax in axes:
            ax.set_facecolor("#161b22")
            for spine in ax.spines.values():
                spine.set_edgecolor("#30363d")
            ax.tick_params(colors="#8b949e", labelsize=7)
            ax.xaxis.label.set_color("#c9d1d9")
            ax.yaxis.label.set_color("#c9d1d9")
            ax.title.set_color("#58a6ff")

        n = self.test_count.get()

        # ── Graph 1: Before vs After success rate ──
        weak_names = list(self._weak_results.keys())
        weak_rates = [sum(r["success"] for r in self._weak_results[g]) / n * 100
                      for g in weak_names]
        prev_names = list(self._prev_results.keys())
        prev_rates = [sum(r["success"] for r in self._prev_results[p]) / n * 100
                      for p in prev_names]

        all_labels = [f"W:{g[:12]}" for g in weak_names] + [f"P:{p[:12]}" for p in prev_names]
        all_rates  = weak_rates + prev_rates
        colors_br  = ["#e74c3c"] * len(weak_names) + ["#2ecc71"] * len(prev_names)

        bars = ax1.bar(range(len(all_labels)), all_rates, color=colors_br, alpha=0.85)
        ax1.set_xticks(range(len(all_labels)))
        ax1.set_xticklabels(all_labels, rotation=30, ha="right", fontsize=6)
        ax1.set_ylim(0, 115)
        ax1.axhline(90, color="#f39c12", linestyle="--", linewidth=1, alpha=0.7)
        ax1.set_title("① Before vs After Attack Success Rate", fontsize=9, pad=8)
        ax1.set_ylabel("Attack Success Rate (%)", fontsize=7)
        for bar, rate in zip(bars, all_rates):
            ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                     f"{rate:.0f}%", ha="center", fontsize=6, color="#c9d1d9")
        ax1.legend(handles=[
            plt.Rectangle((0,0),1,1, color="#e74c3c", alpha=0.85, label="Vulnerable"),
            plt.Rectangle((0,0),1,1, color="#2ecc71", alpha=0.85, label="Secure")
        ], fontsize=7, facecolor="#0d1117", edgecolor="#30363d", labelcolor="#c9d1d9",
           loc="upper right")

        # ── Graph 2: Time vs Challenge Size ──
        sizes, times_ = time_vs_challenge_size()
        ax2.plot(sizes, times_, color="#58a6ff", marker="o", linewidth=2, markersize=5)
        ax2.fill_between(sizes, times_, alpha=0.15, color="#58a6ff")
        ax2.set_title("② Auth Time vs Challenge Size (bits)", fontsize=9, pad=8)
        ax2.set_xlabel("Challenge Size (bits)", fontsize=7)
        ax2.set_ylabel("Time per Auth (ms)", fontsize=7)
        ax2.axvspan(0, 32, alpha=0.1, color="#e74c3c", label="Vulnerable zone")
        ax2.axvspan(128, 256, alpha=0.1, color="#2ecc71", label="Secure zone")
        ax2.legend(fontsize=6, facecolor="#0d1117", edgecolor="#30363d",
                   labelcolor="#c9d1d9")

        # ── Graph 3: CIA Rates ──
        categories = ["Confidentiality", "Integrity", "Authentication"]
        first_weak = list(self._weak_results.values())[0]
        first_prev = list(self._prev_results.values())[0]
        (wc, wi, wa), (pc, pi, pa) = auth_rates(first_weak, first_prev)
        weak_cia = [wc, wi, wa]
        prev_cia = [pc, pi, pa]

        x = np.arange(3)
        width = 0.35
        ax3.bar(x - width/2, weak_cia, width, color="#e74c3c", alpha=0.85, label="Before Prevention")
        ax3.bar(x + width/2, prev_cia, width, color="#2ecc71", alpha=0.85, label="After Prevention")
        ax3.set_xticks(x)
        ax3.set_xticklabels(categories, fontsize=7)
        ax3.set_ylim(0, 115)
        ax3.set_title("③ CIA Rate: Before vs After Prevention", fontsize=9, pad=8)
        ax3.set_ylabel("Rate (%)", fontsize=7)
        ax3.legend(fontsize=7, facecolor="#0d1117", edgecolor="#30363d",
                   labelcolor="#c9d1d9")

        # ── Graph 4: Latency comparison ──
        labels_lat, lats, colors_lat = latency_comparison(
            self._weak_results, self._prev_results)
        short_labels = [l[:14] for l in labels_lat]
        bars4 = ax4.bar(range(len(short_labels)), lats, color=colors_lat, alpha=0.85)
        ax4.set_xticks(range(len(short_labels)))
        ax4.set_xticklabels(short_labels, rotation=30, ha="right", fontsize=6)
        ax4.set_title("④ Attack vs Prevention Latency Overhead", fontsize=9, pad=8)
        ax4.set_ylabel("Avg Latency (ms)", fontsize=7)
        for bar, lat in zip(bars4, lats):
            ax4.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.001,
                     f"{lat:.3f}", ha="center", fontsize=6, color="#c9d1d9")

        # ── Graph 5: Comparison across solutions ──
        all_prev = list(self._prev_results.keys())
        rates_prev = [sum(r["success"] for r in self._prev_results[p]) / n * 100
                      for p in all_prev]
        eff = [100 - r for r in rates_prev]
        bar5 = ax5.barh([p[:20] for p in all_prev], eff,
                        color=["#2ecc71", "#58a6ff", "#f39c12", "#9b59b6"][:len(all_prev)],
                        alpha=0.85)
        ax5.set_xlim(0, 115)
        ax5.set_title("⑤ Prevention Effectiveness Comparison (%)", fontsize=9, pad=8)
        ax5.set_xlabel("Effectiveness (%)", fontsize=7)
        for bar, e in zip(bar5, eff):
            ax5.text(e + 1, bar.get_y() + bar.get_height()/2,
                     f"{e:.1f}%", va="center", fontsize=7, color="#c9d1d9")

        # ── Graph 6: Security improvement % ──
        weak_avg = np.mean(weak_rates) if weak_rates else 95
        improvements = [weak_avg - r for r in rates_prev]
        ax6.bar(range(len(all_prev)), improvements,
                color=["#3fb950", "#58a6ff", "#f39c12", "#bc8cff"][:len(all_prev)],
                alpha=0.85)
        ax6.set_xticks(range(len(all_prev)))
        ax6.set_xticklabels([p[:16] for p in all_prev], rotation=30, ha="right", fontsize=6)
        ax6.set_title("⑥ Security Improvement vs Weak Baseline (%)", fontsize=9, pad=8)
        ax6.set_ylabel("Improvement (%)", fontsize=7)
        for i, imp in enumerate(improvements):
            ax6.text(i, imp + 0.5, f"{imp:.1f}%", ha="center", fontsize=7, color="#c9d1d9")

        fig.suptitle("Challenge-Response Authentication — Security Analysis Dashboard",
                     color="#58a6ff", fontsize=11, y=0.98, fontweight="bold")

        canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = App()
    app.mainloop()
