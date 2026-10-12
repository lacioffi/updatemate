"""
Merges what were previously two separate figures (Section 7.2's Sybil-cost
curve and Section 8's broad-release detection curve) into one two-panel
figure, per reviewer feedback that both told the same "converges to 30%"
story from two directions and should not occupy two separate figure slots.

Left panel: cost to an ATTACKER of manufacturing a false BAD verdict
(Sybil reviews needed / total, as genuine pool size grows) -- Section 7.2.
Right panel: probability that a REAL malicious broad release is caught,
as the community's correct-report fraction crosses the same 30% threshold
-- Section 8. Same mechanism (check_bad_software's fixed threshold), two
different actors' perspectives on it, side by side instead of ten pages
apart.
"""
import csv
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams.update({"font.size": 9, "figure.dpi": 200})
OUT = "/home/claude/paper/figures"
RESULTS = os.path.join(os.path.dirname(__file__), "results")
os.makedirs(OUT, exist_ok=True)


def load(path):
    with open(path) as f:
        return list(csv.DictReader(f))


fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9.4, 3.4))

# --- Left: Sybil cost curve (attacker's view) ---
sybil = load(os.path.join(RESULTS, "sybil_cost.csv"))
gr = [int(r["genuine_reviews"]) for r in sybil]
frac = [float(r["sybil_fraction_of_total"]) for r in sybil]
ax1.plot(gr, frac, marker="o", color="crimson")
ax1.axhline(0.30, color="gray", linestyle="--", linewidth=1, label="30% threshold")
ax1.set_xscale("log")
ax1.set_xlabel("Genuine reviews in community pool")
ax1.set_ylabel("Sybil reviews needed / total reviews")
ax1.set_ylim(0.25, 0.40)
ax1.set_title("(a) Attacker's cost to force a false alarm", fontsize=9)
ax1.legend(fontsize=7)
ax1.grid(True, which="both", alpha=0.3)

# --- Right: broad-release detection rate (defender's view) ---
broad = load(os.path.join(RESULTS, "broad_release_detection.csv"))
for size in sorted(set(int(r["community_size"]) for r in broad)):
    rows = [r for r in broad if int(r["community_size"]) == size]
    rows.sort(key=lambda r: float(r["detection_fraction"]))
    x = [float(r["detection_fraction"]) for r in rows]
    y = [float(r["detection_rate"]) for r in rows]
    ax2.plot(x, y, marker="o", label=f"N = {size}", markersize=3)
ax2.axvline(0.30, color="gray", linestyle="--", linewidth=1, label="30% threshold")
ax2.set_xlabel("Fraction of community correctly reporting")
ax2.set_ylabel("P(UpdateMate raises an alarm)")
ax2.set_title("(b) Real detection of a broad release", fontsize=9)
ax2.legend(fontsize=6, loc="lower right")
ax2.grid(True, alpha=0.3)

fig.tight_layout()
fig.savefig(f"{OUT}/sybil_and_detection_convergence.pdf")
plt.close(fig)

print("Wrote", f"{OUT}/sybil_and_detection_convergence.pdf")
