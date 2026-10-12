"""
Quantitative evaluation of UpdateMate's detection heuristics, calling the
ACTUAL functions from updatemate_client/src/updatemate_client/heuristics.py
(unmodified) against synthetic review/version populations.

Three experiments, directly answering reviewer feedback that no
experimental validation or false-positive-rate data was presented:

  1. check_bad_software: Sybil cost curve. For a population of N genuine
     "ok" reviews, how many adversary-injected negative reviews are needed
     to flip the verdict to BAD (widespread-malware alert), at the
     heuristic's fixed 30% threshold? This quantifies the cost of
     manipulating the reputation layer -- the limitation the tools paper
     already states qualitatively; here we give it numbers.

  2. check_bad_software: false-positive rate under organic (non-adversarial)
     review noise. If a genuinely fine update organically draws X% negative
     reviews (annoyed users, unrelated complaints, etc.) with no attacker
     involved, at what rate does the heuristic still fire?

  3. check_targeted_malware: minimum corroborating reviews an attacker must
     inject to make a targeted/malicious version indistinguishable from a
     widely-seen one, given the heuristic's fixed threshold of 2.
"""
import json
import random
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "updatemate_client", "src"))
from updatemate_client.heuristics import check_bad_software, check_targeted_malware

random.seed(2026)


def make_review(label):
    return {"reviewer": "x", "comment": "x", "review": label}


def sybil_cost_curve(pool_sizes):
    """For each genuine-review pool size, find the minimum number of
    injected 'malicious' reviews needed to flip check_bad_software to BAD."""
    rows = []
    for pool in pool_sizes:
        genuine = [make_review("ok") for _ in range(pool)]
        injected = 0
        verdict = "OK"
        while verdict != "BAD" and injected <= pool * 5 + 50:
            reviews = genuine + [make_review("malicious") for _ in range(injected)]
            verdict, _ = check_bad_software(reviews)
            if verdict == "BAD":
                break
            injected += 1
        rows.append({
            "genuine_reviews": pool,
            "sybil_reviews_needed": injected,
            "sybil_fraction_of_total": round(injected / (pool + injected), 4) if (pool + injected) else None,
        })
        print(f"pool={pool:>6}  sybil_needed={injected:>6}  "
              f"fraction_of_total={injected/(pool+injected):.3f}")
    return rows


def organic_noise_false_positive_rate(pool_size, noise_fractions, trials=500):
    """No attacker: genuine reviews are drawn i.i.d. as 'ok' with probability
    (1 - noise_fraction) and 'degraded' (a legitimate, non-malicious
    complaint label) otherwise. Measures how often check_bad_software fires
    BAD purely from organic dissatisfaction, at each noise level."""
    rows = []
    for noise in noise_fractions:
        fires = 0
        for _ in range(trials):
            reviews = [make_review("degraded" if random.random() < noise else "ok")
                       for _ in range(pool_size)]
            verdict, _ = check_bad_software(reviews)
            if verdict == "BAD":
                fires += 1
        rate = fires / trials
        rows.append({"pool_size": pool_size, "organic_negative_fraction": noise,
                      "false_positive_rate": round(rate, 4), "trials": trials})
        print(f"pool={pool_size:>5}  organic_negative_fraction={noise:.2f}  "
              f"BAD-fire-rate={rate:.3f} (n={trials})")
    return rows


def targeted_malware_evasion_cost():
    """check_targeted_malware fires BAD when fewer than 2 reviews exist.
    How many fabricated corroborating reviews does an attacker need to
    submit to make a freshly-published targeted version look 'established'?"""
    results = []
    for n_reviews in range(0, 5):
        reviews = [make_review("ok") for _ in range(n_reviews)]
        verdict, msg = check_targeted_malware(reviews)
        results.append({"reviews_present": n_reviews, "verdict": verdict})
        print(f"reviews_present={n_reviews}  verdict={verdict}")
    return results


if __name__ == "__main__":
    os.makedirs("results", exist_ok=True)

    print("\n=== Experiment 1: Sybil cost to flip check_bad_software ===")
    sybil_rows = sybil_cost_curve([2, 5, 10, 20, 50, 100, 500, 1000, 5000])

    print("\n=== Experiment 2: organic (non-adversarial) false-positive rate ===")
    fp_rows = []
    for pool in [10, 50, 200]:
        fp_rows += organic_noise_false_positive_rate(pool, [0.05, 0.10, 0.15, 0.20, 0.25, 0.30])

    print("\n=== Experiment 3: check_targeted_malware evasion cost ===")
    targeted_rows = targeted_malware_evasion_cost()

    import csv
    with open("results/sybil_cost.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(sybil_rows[0].keys())); w.writeheader(); w.writerows(sybil_rows)
    with open("results/organic_false_positive.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(fp_rows[0].keys())); w.writeheader(); w.writerows(fp_rows)
    with open("results/targeted_evasion.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(targeted_rows[0].keys())); w.writeheader(); w.writerows(targeted_rows)
    print("\nWrote CSVs to results/")
