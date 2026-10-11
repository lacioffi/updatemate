"""
Reproduces the CAPTCHA-cost numbers cited in Section 6.5 of the paper --
what it costs a funded attacker, in real dollars, to defeat the CAPTCHA
gate (updatemate_server/captcha.py) enough times to flip check_bad_software's
verdict.

We do not solve real commercial CAPTCHAs here (that would require paying a
third-party service); instead we combine results/sybil_cost.csv (the
sybil_reviews_needed column, produced by attack_sim.py against the real,
unmodified check_bad_software heuristic) with publicly listed commercial
CAPTCHA-solving-service pricing for plain image/text challenges -- the
same category as updatemate_server/captcha.py's own barebones challenge --
cited in the paper:

  2Captcha, "for-customer" pricing page (accessed 2026):
    normal text/image captchas: $0.50 - $1.00 per 1,000 solves
  Anti-Captcha, homepage pricing table (accessed 2026):
    image/text captchas: $0.50 - $0.70 per 1,000 solves

We use the wider of the two ranges, $0.50-$1.00 per 1,000, i.e.
$0.0005-$0.001 per solved CAPTCHA, as the per-review cost. This is a
pricing calculation, not a live solve -- unlike the (now-removed)
proof-of-work mechanism this replaced, there is no local "solve time" to
measure, since the point of a CAPTCHA is precisely that solving it is not
something the attacker's own machine can cheaply do.
"""
import csv
import os

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
PRICE_LOW_PER_1000 = 0.50   # dollars, cheap end of the cited range
PRICE_HIGH_PER_1000 = 1.00  # dollars, expensive end of the cited range


def load(path):
    with open(path) as f:
        return list(csv.DictReader(f))


if __name__ == "__main__":
    sybil_rows = load(os.path.join(RESULTS_DIR, "sybil_cost.csv"))

    out_rows = []
    for row in sybil_rows:
        needed = int(row["sybil_reviews_needed"])
        cost_low = needed * PRICE_LOW_PER_1000 / 1000
        cost_high = needed * PRICE_HIGH_PER_1000 / 1000
        out_rows.append({
            "genuine_reviews": row["genuine_reviews"],
            "sybil_reviews_needed": needed,
            "captcha_cost_usd_low": round(cost_low, 4),
            "captcha_cost_usd_high": round(cost_high, 4),
        })
        print(f"genuine={row['genuine_reviews']:>6}  sybil_needed={needed:>6}  "
              f"cost=${cost_low:.4f}-${cost_high:.4f}")

    out_path = os.path.join(RESULTS_DIR, "captcha_cost.csv")
    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out_rows[0].keys()))
        w.writeheader()
        w.writerows(out_rows)
    print(f"\nWrote {out_path}")
