"""Off-chain Merkle batching costs vs. N (Table VIII, Fig. 5).
Tree build (leaf hashing + internal nodes + all proofs), proof size, single-proof
verification time, and IPFS manifest size, for N = 1, 10, 100, 1,000, 10,000.
Build is repeated R times (R = 1000 for N <= 100, 100 for 1,000, 20 for 10,000);
verification is repeated 1,000 times after 50 warm-up runs.
Run: python scripts/bench_merkle.py
"""
import csv, math, os, statistics, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import psutil
from eth_abi import encode as abi_encode
from eth_utils import keccak
import pqc_lib as P

try:
    psutil.Process().cpu_affinity([2])
except Exception:
    pass
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")
CID = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"  # 59-char CIDv1
rows, raw = [], []
for N in (1, 10, 100, 1000, 10000):
    cs = [keccak(f"c-{N}-{i}".encode()) for i in range(N)]
    R = 1000 if N <= 100 else (100 if N == 1000 else 20)
    bt = []
    for r in range(R + 5):
        t0 = time.perf_counter_ns()
        leaves = [P.leaf_hash(c) for c in cs]
        lv = P.merkle_build(leaves)
        root = P.merkle_root(lv)
        proofs = [P.merkle_proof(lv, i) for i in range(N)]
        t1 = time.perf_counter_ns()
        if r >= 5:
            bt.append(t1 - t0); raw.append(("build", N, r - 5, t1 - t0))
    lens = [len(p) for p in proofs]
    idx = max(range(N), key=lambda i: lens[i])
    vt = []
    for r in range(1050):
        t0 = time.perf_counter_ns()
        ok = P.merkle_verify(leaves[idx], proofs[idx], root)
        t1 = time.perf_counter_ns()
        assert ok
        if r >= 50:
            vt.append(t1 - t0); raw.append(("verify", N, r - 50, t1 - t0))
    manifest = abi_encode(["bytes32", "bytes32[]", "string[]"], [root, leaves, [CID] * N])
    b = [x / 1e6 for x in bt]; v = [x / 1e3 for x in vt]
    rows.append([N, R, f"{statistics.fmean(b):.4f}", f"{statistics.median(b):.4f}", f"{(statistics.stdev(b) if len(b) > 1 else 0):.4f}",
                 max(lens), 32 * max(lens), f"{statistics.mean(lens):.2f}", math.ceil(math.log2(N)) if N > 1 else 0,
                 f"{statistics.fmean(v):.3f}", f"{statistics.median(v):.3f}", f"{statistics.stdev(v):.3f}", len(manifest)])
    print(rows[-1])
with open(os.path.join(OUT, "merkle_offchain.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["N", "build_reps", "build_mean_ms", "build_median_ms", "build_sd_ms", "max_proof_len", "max_proof_bytes",
                "mean_proof_len", "ceil_log2_N", "verify_mean_us", "verify_median_us", "verify_sd_us", "manifest_bytes"])
    w.writerows(rows)
with open(os.path.join(OUT, "merkle_offchain_raw.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["phase", "N", "rep", "ns"]); w.writerows(raw)
