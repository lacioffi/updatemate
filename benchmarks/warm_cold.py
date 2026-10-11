"""Warm-cache vs cold-cache inclusion proof generation at fixed tree size,
to characterize why proof generation deviates from theoretical O(log n)
in the SQLite-backed implementation (see merkle_bench.py results)."""
import json, os, shutil, time, sys
sys.path.insert(0, os.path.dirname(__file__))
from merkle_bench import make_review_entry, proof_size_bytes
from pymerkle import SqliteTree

DB_DIR = "/tmp/warm_cold_bench"
if os.path.exists(DB_DIR):
    shutil.rmtree(DB_DIR)
os.makedirs(DB_DIR)
db_path = os.path.join(DB_DIR, "tree.db")

N = 100000
tree = SqliteTree(db_path)
for i in range(1, N + 1):
    tree.append_entry(make_review_entry(i))

# COLD: never-before-queried leaf near the middle
cold_index = N // 3
t0 = time.perf_counter()
p1 = tree.prove_inclusion(cold_index)
cold_ms = (time.perf_counter() - t0) * 1000

# WARM: immediately re-query the SAME leaf (subroots now cached)
t0 = time.perf_counter()
p2 = tree.prove_inclusion(cold_index)
warm_ms = (time.perf_counter() - t0) * 1000

# WARM: query the most-recently-appended leaf (touched during last appends)
t0 = time.perf_counter()
p3 = tree.prove_inclusion(N)
recent_ms = (time.perf_counter() - t0) * 1000

print(f"N={N}")
print(f"cold (first query, arbitrary leaf {cold_index}):      {cold_ms:.3f} ms, proof={proof_size_bytes(p1)}B")
print(f"warm (repeat query, same leaf, cache hit):    {warm_ms:.3f} ms, proof={proof_size_bytes(p2)}B")
print(f"warm (most recently appended leaf {N}):        {recent_ms:.3f} ms, proof={proof_size_bytes(p3)}B")

tree.con.close()

with open("results/warm_cold.txt", "w") as f:
    f.write(f"N={N}\n")
    f.write(f"cold_first_query_ms={cold_ms:.3f}\n")
    f.write(f"warm_repeat_query_ms={warm_ms:.3f}\n")
    f.write(f"warm_recent_leaf_ms={recent_ms:.3f}\n")
