#!/usr/bin/env python3
"""
Reproduces the Section 7.2 detection-rate sweep: how does each content-
dependent heuristic's BAD rate respond as the underlying problem becomes
more or less conspicuous to the people who actually run the software?

Per-user reviewing model:
  - Population: 1,000 users.
  - A user who notices nothing wrong with a release leaves a positive
    ("ok") review with probability AMBIENT_RATE = 10%.
  - A user who does detect the release's actual problem leaves a negative
    review instead, with probability REPORT_RATE_ON_DETECT = 50%,
    reflecting that people are more likely to report a real problem than
    to leave a routine positive review.
  - Whether a user detects the problem at all is the swept parameter
    (0-100%): 0% is a flaw nobody using the release would ever notice,
    100% is a flaw every affected user notices.

This replaces the earlier, fixed-range version of this simulation. The
50%/10% split and the detection-rate sweep are modeling choices, stated
here and in the paper, not measured quantities (Section 8.6).

Calls the project's own, unmodified updatemate_client.heuristics functions
-- no heuristic logic is touched or special-cased by this script.

Usage: run from the repository root.
    python3 evaluate_heuristic_detection.py
Writes detection_rate_sweep.pdf and sweep_results.json next to this file.
"""
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "updatemate_client", "src"))
from updatemate_client import heuristics

OUT_DIR = os.path.dirname(os.path.abspath(__file__))

rng = np.random.default_rng(42)

N_TRIALS = 5000
POPULATION = 1000
AMBIENT_RATE = 0.10
REPORT_RATE_ON_DETECT = 0.50
RATES = list(range(0, 21, 1)) + [25, 30, 40, 50, 60, 70, 80, 90, 100]  # dense near the transition


def make_review(tag):
    return json.dumps({"review": tag, "comment": "", "reviewer": "u"})


def make_version(version_id, file_version):
    return json.dumps({"software_version_id": version_id, "file_properties": {"FileVersion": file_version}})


def sample_reviews(detect_rate_pct, bad_tag):
    detect_p = detect_rate_pct / 100.0
    n_detectors = rng.binomial(POPULATION, detect_p)
    n_reporters = rng.binomial(n_detectors, REPORT_RATE_ON_DETECT)
    n_non_detectors = POPULATION - n_detectors
    n_ambient_ok = rng.binomial(n_non_detectors, AMBIENT_RATE)
    return [make_review(bad_tag)] * int(n_reporters) + [make_review("ok")] * int(n_ambient_ok)


def run_sweep():
    results = {"degraded": {}, "malicious": {}, "targeted": {}}

    # Degraded release: single known version, sweep x = detection rate.
    for rate in RATES:
        bad = 0
        for _ in range(N_TRIALS):
            reviews = sample_reviews(rate, "degraded")
            status, _ = heuristics.check_bad_software(reviews)
            if status == "BAD":
                bad += 1
        results["degraded"][rate] = bad / N_TRIALS

    # Freeze/replay victim: two known versions, sweep y = detection rate.
    versions_two = [make_version("prod-v3", "3"), make_version("prod-v4", "4")]
    for rate in RATES:
        bad_bs = 0
        bad_fr = 0
        for _ in range(N_TRIALS):
            reviews = sample_reviews(rate, "vulnerable")
            s_bs, _ = heuristics.check_bad_software(reviews)
            s_fr, _ = heuristics.check_freeze_replay_attack(reviews, versions_two, "3")
            if s_bs == "BAD":
                bad_bs += 1
            if s_fr == "BAD":
                bad_fr += 1
        results["malicious"][rate] = {"bad_software": bad_bs / N_TRIALS, "freeze_replay": bad_fr / N_TRIALS}

    # Targeted malicious build: at most 1 possible reviewer, version absent from the ledger.
    # Checked at three representative rates to confirm check_known_version and
    # check_targeted_malware don't depend on detection rate at all.
    for rate in [0, 50, 100]:
        tallies = {name: {"OK": 0, "BAD": 0, "UNKNOWN": 0} for name in
                   ["check_known_version", "check_targeted_malware", "check_bad_software", "check_freeze_replay_attack"]}
        detect_p = rate / 100.0
        for _ in range(N_TRIALS):
            if rng.random() < detect_p:
                reviews = [make_review("malicious")] if rng.random() < REPORT_RATE_ON_DETECT else []
            else:
                reviews = [make_review("ok")] if rng.random() < AMBIENT_RATE else []
            s1, _ = heuristics.check_known_version([], "prod-vX-targeted")
            s2, _ = heuristics.check_targeted_malware(reviews)
            s3, _ = heuristics.check_bad_software(reviews)
            s4, _ = heuristics.check_freeze_replay_attack(reviews, [], "9")
            tallies["check_known_version"][s1] += 1
            tallies["check_targeted_malware"][s2] += 1
            tallies["check_bad_software"][s3] += 1
            tallies["check_freeze_replay_attack"][s4] += 1
        results["targeted"][rate] = {k: {kk: vv / N_TRIALS for kk, vv in v.items()} for k, v in tallies.items()}

    return results


def plot(results, out_path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    rates = sorted(results["degraded"].keys())
    degraded_bs = [results["degraded"][x] for x in rates]
    malicious_bs = [results["malicious"][x]["bad_software"] for x in rates]
    malicious_fr = [results["malicious"][x]["freeze_replay"] for x in rates]

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot(rates, degraded_bs, marker="o", markersize=4, linewidth=1.6,
            label="Degraded release -> check_bad_software", color="#1f77b4")
    ax.plot(rates, malicious_bs, marker="s", markersize=4, linewidth=1.6, linestyle="--",
            label="Malicious build -> check_bad_software", color="#ff7f0e")
    ax.plot(rates, malicious_fr, marker="^", markersize=4, linewidth=1.6, linestyle=":",
            label="Malicious build -> check_freeze_replay_attack", color="#2ca02c")

    ax.axvline(7.9, color="gray", linestyle="--", linewidth=1, alpha=0.7)
    ax.text(8.6, 0.5, "analytic crossover\n≈ 7.9%\n(expected bad-review\nshare = 30%)",
            fontsize=8, color="gray", va="center")

    ax.set_xlabel("Detection rate (% of population that notices the problem)")
    ax.set_ylabel("P(heuristic flags BAD)")
    ax.set_xlim(0, 100)
    ax.set_ylim(-0.03, 1.03)
    ax.grid(True, alpha=0.3)
    ax.legend(loc="center right", fontsize=8, frameon=True)
    fig.tight_layout()
    fig.savefig(out_path)


if __name__ == "__main__":
    results = run_sweep()

    json_path = os.path.join(OUT_DIR, "sweep_results.json")
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Wrote {json_path}")

    pdf_path = os.path.join(OUT_DIR, "detection_rate_sweep.pdf")
    plot(results, pdf_path)
    print(f"Wrote {pdf_path}")
