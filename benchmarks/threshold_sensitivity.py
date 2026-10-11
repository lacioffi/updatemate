"""
Justifies check_bad_software's fixed threshold (theta=0.3) against the
reviewer's question "why 30% and not 25% or 40%?" -- rather than asserting
30% as a design choice, this sweeps theta itself and shows the concrete
trade-off it controls, using the real, unmodified (now theta-parameterized)
check_bad_software function from updatemate_client/heuristics.py.

Two things move in opposite directions as theta increases:
  - organic_false_positive_rate: how often ordinary, non-adversarial review
    noise (annoyed users, unrelated complaints) alone flips the verdict to
    BAD. This should FALL as theta rises -- a higher bar is harder to
    cross by accident.
  - sybil_reviews_needed: how many adversary-injected reviews are needed
    to deliberately flip a healthy population to BAD (same experiment as
    attack_sim.py's Experiment 1, but now repeated at each theta). This
    should RISE as theta rises -- a higher bar is also harder to cross
    on purpose, which is good against attackers but also means a
    genuinely malicious version needs a larger share of bad reviews
    before the heuristic fires, i.e. slower real detection.

theta=0.3 is not claimed to be optimal here -- this script exists to make
that choice inspectable and arguable rather than an unexplained constant.
"""
import csv
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "updatemate_client", "src"))
from updatemate_client.heuristics import check_bad_software

random.seed(2026)

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
THRESHOLDS = [0.20, 0.25, 0.30, 0.35, 0.40]
POOL_SIZES_FP = [10, 50, 200]
NOISE_FRACTIONS = [0.05, 0.10, 0.15, 0.20, 0.25, 0.30]
SYBIL_POOL_SIZE = 100
TRIALS = 500


def make_review(label):
    return {"reviewer": "x", "comment": "x", "review": label}


def organic_false_positive_rate(pool_size, noise, threshold, trials=TRIALS):
    fires = 0
    for _ in range(trials):
        reviews = [make_review("degraded" if random.random() < noise else "ok")
                   for _ in range(pool_size)]
        verdict, _ = check_bad_software(reviews, threshold=threshold)
        if verdict == "BAD":
            fires += 1
    return fires / trials


def sybil_reviews_needed_at_threshold(pool_size, threshold):
    genuine = [make_review("ok") for _ in range(pool_size)]
    injected = 0
    verdict = "OK"
    while verdict != "BAD" and injected <= pool_size * 5 + 50:
        reviews = genuine + [make_review("malicious") for _ in range(injected)]
        verdict, _ = check_bad_software(reviews, threshold=threshold)
        if verdict == "BAD":
            break
        injected += 1
    return injected


if __name__ == "__main__":
    os.makedirs(RESULTS_DIR, exist_ok=True)

    print("=== Organic false-positive rate vs. theta ===")
    fp_rows = []
    for threshold in THRESHOLDS:
        for pool in POOL_SIZES_FP:
            for noise in NOISE_FRACTIONS:
                rate = organic_false_positive_rate(pool, noise, threshold)
                fp_rows.append({
                    "threshold": threshold, "pool_size": pool,
                    "organic_negative_fraction": noise,
                    "false_positive_rate": round(rate, 4), "trials": TRIALS,
                })
        print(f"theta={threshold:.2f}  done ({len(POOL_SIZES_FP)}x{len(NOISE_FRACTIONS)} cells)")

    print(f"\n=== Sybil reviews needed to flip verdict vs. theta (pool={SYBIL_POOL_SIZE}) ===")
    sybil_rows = []
    for threshold in THRESHOLDS:
        needed = sybil_reviews_needed_at_threshold(SYBIL_POOL_SIZE, threshold)
        sybil_rows.append({
            "threshold": threshold, "genuine_reviews": SYBIL_POOL_SIZE,
            "sybil_reviews_needed": needed,
        })
        print(f"theta={threshold:.2f}  sybil_reviews_needed={needed}")

    with open(os.path.join(RESULTS_DIR, "threshold_sensitivity_fp.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(fp_rows[0].keys())); w.writeheader(); w.writerows(fp_rows)
    with open(os.path.join(RESULTS_DIR, "threshold_sensitivity_sybil.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(sybil_rows[0].keys())); w.writeheader(); w.writerows(sybil_rows)
    print("\nWrote results/threshold_sensitivity_fp.csv and results/threshold_sensitivity_sybil.csv")
