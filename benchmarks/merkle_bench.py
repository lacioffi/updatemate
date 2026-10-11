"""
Benchmark for UP2DATE's Merkle-tree ledger, built directly on pymerkle 6.1.0
(the exact library and version pinned in updatemate_server/pyproject.toml),
using pymerkle.SqliteTree (the exact tree class used by updatemate_server's
SoftwareRegistry in merkle.py).

Measures, as a function of ledger size N:
  - append throughput (entries/sec)
  - on-disk storage overhead (SQLite tree file size vs. raw payload bytes)
  - inclusion proof generation time, verification time, and serialized size
  - consistency proof generation time, verification time, and serialized size

Two entry-size regimes are benchmarked, matching UP2DATE's real data shapes:
  - "version" entries (~30KB): full software-version submissions with
    certificate chains, taken from the shape of the project's own test
    fixtures (updatemate_server/tests/data/chrome_1.json).
  - "review" entries (~250B): community review submissions.

Run: PYTHONPATH=/home/claude/vendor:/home/claude/pymerkle python3 merkle_bench.py
"""
import json
import os
import random
import shutil
import string
import time
import csv

from pymerkle import SqliteTree, verify_inclusion, verify_consistency, InvalidProof


def proof_size_bytes(proof):
    return len(json.dumps(proof.serialize()).encode("utf-8"))


def try_verify(fn, *args):
    try:
        fn(*args)
        return True
    except InvalidProof:
        return False

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
DB_DIR = "/tmp/merkle_bench_dbs"

random.seed(1337)


def make_version_entry(i):
    """~30KB entry approximating a real UP2DATE software-version submission
    (dominated by the base64 signature raw_data field + cert chain), matching
    the byte scale of updatemate_server/tests/data/chrome_1.json (32,127 bytes)."""
    raw_data = ''.join(random.choices(string.ascii_letters + string.digits, k=20768))
    general = ''.join(random.choices(string.ascii_letters + string.digits + " \n:", k=1210))
    certs = [{
        "issuer": f"C=US, O=Vendor{i}, CN=Vendor{i} Root CA",
        "subject": f"C=US, O=Vendor{i}, CN=Vendor{i} Signing CA",
        "signature_algorithm": "sha256WithRSAEncryption",
        "valid_from": [2024, 1, 1],
        "valid_to": [2027, 1, 1],
    } for _ in range(5)]
    entry = {
        "software_version_id": f"Software{i}-{i:064x}",
        "first_seen": "2026-08-23 00:00:00",
        "file_properties": {"StringFileInfo": {"ProductName": f"Software{i}", "ProductVersion": f"1.{i}.0"}},
        "signatures": [{"general": general, "hash": f"{i:064x}", "raw_data": raw_data, "certificates": certs}],
    }
    return json.dumps(entry, sort_keys=True).encode("utf-8")


def make_review_entry(i):
    """~250B entry approximating a real UP2DATE community review submission."""
    entry = {
        "reviewer": f"user{i}",
        "comment": "Works as expected, no issues found after a week of use.",
        "review": random.choice(["ok", "ok", "ok", "vulnerable", "malicious", "degraded"]),
        "time_received": "2026-08-23 00:00:00",
    }
    return json.dumps(entry, sort_keys=True).encode("utf-8")


def bench_regime(name, entry_fn, sizes):
    if os.path.exists(DB_DIR):
        shutil.rmtree(DB_DIR)
    os.makedirs(DB_DIR, exist_ok=True)
    db_path = os.path.join(DB_DIR, f"{name}_tree.db")

    tree = SqliteTree(db_path)
    rows = []
    raw_bytes_total = 0
    cumulative_time = 0.0
    prev_size = 0
    prev_state = None

    checkpoint_set = set(sizes)
    max_n = max(sizes)

    for i in range(1, max_n + 1):
        entry = entry_fn(i)
        raw_bytes_total += len(entry)
        t0 = time.perf_counter()
        tree.append_entry(entry)
        cumulative_time += time.perf_counter() - t0

        if i in checkpoint_set:
            n = i
            db_size = os.path.getsize(db_path)

            # Inclusion proof for a leaf near the middle of the tree
            target_index = max(1, n // 2)
            t0 = time.perf_counter()
            incl_proof = tree.prove_inclusion(target_index)
            t_incl_gen = time.perf_counter() - t0

            state_n = tree.get_state()
            leaf_hash = tree.get_leaf(target_index)
            t0 = time.perf_counter()
            incl_ok = try_verify(verify_inclusion, leaf_hash, state_n, incl_proof)
            t_incl_ver = time.perf_counter() - t0
            incl_proof_size = proof_size_bytes(incl_proof)

            # Consistency proof between the previous checkpoint and now
            t_cons_gen = t_cons_ver = 0.0
            cons_proof_size = 0
            cons_ok = None
            if prev_size > 0:
                t0 = time.perf_counter()
                cons_proof = tree.prove_consistency(prev_size, n)
                t_cons_gen = time.perf_counter() - t0
                t0 = time.perf_counter()
                cons_ok = try_verify(verify_consistency, prev_state, state_n, cons_proof)
                t_cons_ver = time.perf_counter() - t0
                cons_proof_size = proof_size_bytes(cons_proof)

            rows.append({
                "regime": name,
                "n_entries": n,
                "cumulative_append_time_s": round(cumulative_time, 4),
                "append_throughput_entries_per_s": round(n / cumulative_time, 1),
                "raw_payload_bytes": raw_bytes_total,
                "db_file_bytes": db_size,
                "storage_overhead_ratio": round(db_size / raw_bytes_total, 4),
                "bytes_per_entry_overhead": round((db_size - raw_bytes_total) / n, 2),
                "inclusion_proof_gen_ms": round(t_incl_gen * 1000, 4),
                "inclusion_proof_verify_ms": round(t_incl_ver * 1000, 4),
                "inclusion_proof_bytes": incl_proof_size,
                "inclusion_verified_ok": incl_ok,
                "consistency_proof_gen_ms": round(t_cons_gen * 1000, 4),
                "consistency_proof_verify_ms": round(t_cons_ver * 1000, 4),
                "consistency_proof_bytes": cons_proof_size,
                "consistency_verified_ok": cons_ok,
                "consistency_prev_n": prev_size,
            })
            prev_size = n
            prev_state = state_n
            print(f"[{name}] n={n:>7}  append={cumulative_time:8.3f}s  "
                  f"db={db_size/1024/1024:8.3f}MB  overhead_ratio={db_size/raw_bytes_total:.3f}  "
                  f"incl_gen={t_incl_gen*1000:.3f}ms  incl_ver={t_incl_ver*1000:.3f}ms  "
                  f"incl_bytes={incl_proof_size}  cons_gen={t_cons_gen*1000:.3f}ms  cons_bytes={cons_proof_size}")

    tree.con.close()
    return rows


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    review_sizes = [10, 100, 1000, 10000, 100000, 500000, 1000000]
    version_sizes = [10, 50, 100, 500, 1000, 5000]

    all_rows = []
    all_rows += bench_regime("review", make_review_entry, review_sizes)
    all_rows += bench_regime("version", make_version_entry, version_sizes)

    out_csv = os.path.join(RESULTS_DIR, "merkle_bench.csv")
    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(all_rows[0].keys()))
        writer.writeheader()
        writer.writerows(all_rows)
    print(f"\nWrote {out_csv}")


if __name__ == "__main__":
    main()
