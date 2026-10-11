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

review = load("results/merkle_bench.csv")
review = [r for r in review if r["regime"] == "review"]
version_rows = load("results/merkle_bench_version.csv")

# --- Figure: proof gen/verify time vs N (review regime, log-log) ---
fig, ax = plt.subplots(figsize=(5.2, 3.4))
ns = [int(r["n_entries"]) for r in review]
gen = [float(r["inclusion_proof_gen_ms"]) for r in review]
ver = [float(r["inclusion_proof_verify_ms"]) for r in review]
cons_gen = [float(r["consistency_proof_gen_ms"]) for r in review]
ns_cons = [n for n, c in zip(ns, cons_gen) if c > 0]
cons_gen_nz = [c for c in cons_gen if c > 0]
ax.plot(ns, gen, marker="o", label="Inclusion proof — generation")
ax.plot(ns, ver, marker="s", label="Inclusion proof — verification")
ax.plot(ns_cons, cons_gen_nz, marker="^", label="Consistency proof — generation")
ax.set_xscale("log"); ax.set_yscale("log")
ax.set_xlabel("Ledger size N (entries)")
ax.set_ylabel("Time (ms)")
ax.legend(fontsize=7, loc="upper left")
ax.grid(True, which="both", alpha=0.3)
fig.tight_layout()
fig.savefig(f"{OUT}/proof_time_vs_n.pdf")
plt.close(fig)

# --- Figure: proof size vs N ---
fig, ax = plt.subplots(figsize=(5.2, 3.4))
incl_sz = [int(r["inclusion_proof_bytes"]) for r in review]
cons_sz = [int(r["consistency_proof_bytes"]) for r in review]
ax.plot(ns, incl_sz, marker="o", label="Inclusion proof size")
ax.plot(ns, cons_sz, marker="s", label="Consistency proof size")
ax.set_xscale("log")
ax.set_xlabel("Ledger size N (entries)")
ax.set_ylabel("Serialized proof size (bytes)")
ax.legend(fontsize=8)
ax.grid(True, which="both", alpha=0.3)
fig.tight_layout()
fig.savefig(f"{OUT}/proof_size_vs_n.pdf")
plt.close(fig)

# --- Figure: storage overhead ratio vs N, both regimes ---
fig, ax = plt.subplots(figsize=(5.2, 3.4))
ratio_r = [float(r["storage_overhead_ratio"]) for r in review]
ns_v = [int(r["n_entries"]) for r in version_rows]
ratio_v = [float(r["storage_overhead_ratio"]) for r in version_rows]
ax.plot(ns, ratio_r, marker="o", label="Review entries (~250B)")
ax.plot(ns_v, ratio_v, marker="s", label="Version entries (~30KB)")
ax.axhline(1.0, color="gray", linestyle="--", linewidth=1, label="No overhead (ratio = 1)")
ax.set_xscale("log")
ax.set_xlabel("Ledger size N (entries)")
ax.set_ylabel("DB size / raw payload size")
ax.legend(fontsize=8)
ax.grid(True, which="both", alpha=0.3)
fig.tight_layout()
fig.savefig(f"{OUT}/storage_overhead.pdf")
plt.close(fig)

# --- Figure: Sybil cost curve ---
sybil = load("results/sybil_cost.csv")
fig, ax = plt.subplots(figsize=(5.2, 3.4))
gr = [int(r["genuine_reviews"]) for r in sybil]
frac = [float(r["sybil_fraction_of_total"]) for r in sybil]
ax.plot(gr, frac, marker="o", color="crimson")
ax.axhline(0.30, color="gray", linestyle="--", linewidth=1, label="Asymptotic 30% threshold")
ax.set_xscale("log")
ax.set_xlabel("Genuine reviews in community pool")
ax.set_ylabel("Sybil reviews needed / total reviews")
ax.set_ylim(0.25, 0.40)
ax.legend(fontsize=8)
ax.grid(True, which="both", alpha=0.3)
fig.tight_layout()
fig.savefig(f"{OUT}/sybil_cost.pdf")
plt.close(fig)

# --- Figure: organic false-positive rate heat/line ---
fp = load("results/organic_false_positive.csv")
fig, ax = plt.subplots(figsize=(5.2, 3.4))
for pool in sorted(set(int(r["pool_size"]) for r in fp)):
    rows = [r for r in fp if int(r["pool_size"]) == pool]
    rows.sort(key=lambda r: float(r["organic_negative_fraction"]))
    x = [float(r["organic_negative_fraction"]) for r in rows]
    y = [float(r["false_positive_rate"]) for r in rows]
    ax.plot(x, y, marker="o", label=f"Pool size = {pool}")
ax.set_xlabel("Organic (non-adversarial) negative-review fraction")
ax.set_ylabel("check_bad_software false-positive rate")
ax.legend(fontsize=8)
ax.grid(True, alpha=0.3)
fig.tight_layout()
fig.savefig(f"{OUT}/organic_fp.pdf")
plt.close(fig)

print("Figures written:", os.listdir(OUT))
