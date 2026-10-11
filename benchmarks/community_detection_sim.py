"""
Simulated detection of malicious updates using the ACTUAL functions from
updatemate_client/src/updatemate_client/heuristics.py (unmodified), directly
answering a specific reviewer-facing gap: the paper has no real-world
deployment to draw review data from (UP2DATE has not been fielded at
scale), and determining ground-truth "is this binary malicious" is a
separate malware-analysis problem outside UP2DATE's scope. What we CAN
evaluate with the real heuristic code is the other half of the question:
*given* a malicious update was released, and *given* that some fraction of
the users who received it correctly recognize and report it as such, does
UP2DATE's detection layer raise an alarm, and at what fraction?

Two experiments, modeled on two real incidents with structurally different
distribution patterns:

  1. Subset-targeted release (modeled on the 2017 CCleaner supply-chain
     attack): the compromised CCleaner 5.33 build reached roughly 2.27
     million machines, but its second-stage payload activated only for a
     hardcoded whitelist of a few dozen corporate domains -- a small,
     targeted subset of the full user base, structurally identical to
     ShadowHammer's ~600 MAC-address whitelist but not firmware/BIOS
     related, and, being itself a software auto-updater, an unusually
     direct match for UP2DATE's own threat model. We simulate small
     recipient subsets and sweep the fraction of that subset that
     correctly reports the update as malicious/vulnerable.

  2. Broadly distributed release (modeled on the 2017 NotPetya wiper,
     delivered indiscriminately to the entire user base of the Ukrainian
     accounting package M.E.Doc via its own auto-update mechanism, with no
     targeting logic at all): we simulate full community sizes and sweep
     the fraction of the community that correctly reports the update.

Both experiments call check_bad_software and check_targeted_malware
directly; no heuristic code is modified or approximated for this
experiment, only the synthetic review population is.
"""
import csv
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "updatemate_client", "src"))
from updatemate_client.heuristics import check_bad_software, check_targeted_malware

random.seed(2026)


def make_review(label):
    return {"reviewer": "x", "comment": "x", "review": label}


def simulate_release(pool_size, detection_fraction, trials):
    """`pool_size` users receive this version; each independently reports it
    as 'vulnerable' (correctly identifying the malicious update) with
    probability `detection_fraction`, and 'ok' otherwise (a user who
    noticed nothing wrong). Returns the fraction of trials in which either
    real detection heuristic fires BAD."""
    detections = 0
    for _ in range(trials):
        reviews = [
            make_review("vulnerable" if random.random() < detection_fraction else "ok")
            for _ in range(pool_size)
        ]
        targeted_verdict, _ = check_targeted_malware(reviews)
        bad_verdict, _ = check_bad_software(reviews)
        if targeted_verdict == "BAD" or bad_verdict == "BAD":
            detections += 1
    return detections / trials


DETECTION_FRACTIONS = [0.0, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.40, 0.50, 0.70, 1.00]


def subset_targeted_experiment(subset_sizes, trials=500):
    """CCleaner-style: only a small subset of users ever receives this
    version at all, so total visibility is inherently low."""
    rows = []
    for subset_size in subset_sizes:
        for frac in DETECTION_FRACTIONS:
            rate = simulate_release(subset_size, frac, trials)
            rows.append({
                "subset_size": subset_size,
                "detection_fraction": frac,
                "detection_rate": round(rate, 4),
                "trials": trials,
            })
            print(f"subset_size={subset_size:>4}  detection_fraction={frac:.2f}  "
                  f"alarm_rate={rate:.3f}")
    return rows


def broad_release_experiment(community_sizes, trials=500):
    """NotPetya-style: the entire community receives this version, so
    visibility is never the issue -- only the proportion of correct
    reports is."""
    rows = []
    for community_size in community_sizes:
        for frac in DETECTION_FRACTIONS:
            rate = simulate_release(community_size, frac, trials)
            rows.append({
                "community_size": community_size,
                "detection_fraction": frac,
                "detection_rate": round(rate, 4),
                "trials": trials,
            })
            print(f"community_size={community_size:>5}  detection_fraction={frac:.2f}  "
                  f"alarm_rate={rate:.3f}")
    return rows


if __name__ == "__main__":
    os.makedirs("results", exist_ok=True)

    print("\n=== Experiment 1: subset-targeted release detection (CCleaner-style) ===")
    subset_rows = subset_targeted_experiment([3, 5, 10, 20, 50])

    print("\n=== Experiment 2: broad-release detection (NotPetya-style) ===")
    broad_rows = broad_release_experiment([10, 50, 200, 1000])

    with open("results/subset_targeted_detection.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(subset_rows[0].keys())); w.writeheader(); w.writerows(subset_rows)
    with open("results/broad_release_detection.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(broad_rows[0].keys())); w.writeheader(); w.writerows(broad_rows)
    print("\nWrote CSVs to results/")
