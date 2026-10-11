import csv, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams.update({"font.size": 9, "figure.dpi": 200})
OUT = "/home/claude/paper/figures"
os.makedirs(OUT, exist_ok=True)


def load(path):
    with open(path) as f:
        return list(csv.DictReader(f))


# --- Figure: subset-targeted release detection rate vs correct-report fraction ---
subset = load("results/subset_targeted_detection.csv")
fig, ax = plt.subplots(figsize=(5.2, 3.4))
for size in sorted(set(int(r["subset_size"]) for r in subset)):
    rows = [r for r in subset if int(r["subset_size"]) == size]
    rows.sort(key=lambda r: float(r["detection_fraction"]))
    x = [float(r["detection_fraction"]) for r in rows]
    y = [float(r["detection_rate"]) for r in rows]
    ax.plot(x, y, marker="o", label=f"Subset size = {size}")
ax.axvline(0.30, color="gray", linestyle="--", linewidth=1, label="30% threshold (check_bad_software)")
ax.set_xlabel("Fraction of recipients correctly reporting the update")
ax.set_ylabel("P(UP2DATE raises an alarm)")
ax.legend(fontsize=7, loc="lower right")
ax.grid(True, alpha=0.3)
fig.tight_layout()
fig.savefig(f"{OUT}/subset_targeted_detection.pdf")
plt.close(fig)

# --- Figure: broad-release detection rate vs correct-report fraction ---
broad = load("results/broad_release_detection.csv")
fig, ax = plt.subplots(figsize=(5.2, 3.4))
for size in sorted(set(int(r["community_size"]) for r in broad)):
    rows = [r for r in broad if int(r["community_size"]) == size]
    rows.sort(key=lambda r: float(r["detection_fraction"]))
    x = [float(r["detection_fraction"]) for r in rows]
    y = [float(r["detection_rate"]) for r in rows]
    ax.plot(x, y, marker="o", label=f"Community size = {size}")
ax.axvline(0.30, color="gray", linestyle="--", linewidth=1, label="30% threshold (check_bad_software)")
ax.set_xlabel("Fraction of community correctly reporting the update")
ax.set_ylabel("P(UP2DATE raises an alarm)")
ax.legend(fontsize=7, loc="lower right")
ax.grid(True, alpha=0.3)
fig.tight_layout()
fig.savefig(f"{OUT}/broad_release_detection.pdf")
plt.close(fig)

print("Figures written:", ["subset_targeted_detection.pdf", "broad_release_detection.pdf"])
