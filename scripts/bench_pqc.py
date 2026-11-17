"""Per-primitive and combined dual-signature latency benchmark (Table VI / VI-b).

* 1,000 measured iterations per operation, preceded by 50 warm-up iterations
  that are discarded.  time.perf_counter_ns(); single thread; process pinned to
  one logical core with HIGH priority (psutil).
* Writes one raw CSV per run (results/pqc_raw.csv: operation, iteration, ns)
  and a summary (results/pqc_summary.csv: mean, median, sd, min, max, 95% CI).
* Also times sign/verify through a direct ctypes call with pre-allocated
  buffers, to estimate the liboqs-python wrapper overhead.

Run:  python scripts/bench_pqc.py  [--iters 1000]
"""
import argparse, csv, ctypes as ct, json, math, os, platform, statistics, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import oqs, oqs.oqs as oqsn
import psutil
import pqc_lib as P
from eth_utils import keccak

ap = argparse.ArgumentParser()
ap.add_argument("--iters", type=int, default=1000)
ap.add_argument("--warmup", type=int, default=50)
args = ap.parse_args()
N, W = args.iters, args.warmup
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")
os.makedirs(OUT, exist_ok=True)

proc = psutil.Process()
try:
    proc.cpu_affinity([2])
    proc.nice(psutil.HIGH_PRIORITY_CLASS if os.name == "nt" else -10)
except Exception as e:  # noqa
    print("affinity/priority not set:", e)

CHAIN_ID, CONTRACT = 31337, "0x5FbDB2315678afecb367f032d93F642f64180aa3"
raw_rows, summary = [], []


def bench(name, fn, setup=None, n=N, w=W):
    """fn(state) is timed; setup() -> state is run before each call, untimed."""
    ts = []
    for i in range(w + n):
        st = setup() if setup else None
        t0 = time.perf_counter_ns()
        fn(st)
        t1 = time.perf_counter_ns()
        if i >= w:
            ts.append(t1 - t0)
    for i, t in enumerate(ts):
        raw_rows.append((name, i, t))
    ms = [t / 1e6 for t in ts]
    mean = statistics.fmean(ms); sd = statistics.stdev(ms)
    ci = 1.96 * sd / math.sqrt(len(ms))
    summary.append({"operation": name, "n": len(ms), "mean_ms": mean, "median_ms": statistics.median(ms),
                    "sd_ms": sd, "min_ms": min(ms), "max_ms": max(ms), "ci95_lo": mean - ci, "ci95_hi": mean + ci})
    print(f"{name:45s} mean {mean:9.4f}  med {statistics.median(ms):9.4f}  sd {sd:8.4f}  min {min(ms):8.4f}  max {max(ms):9.4f} ms")


MSG = os.urandom(32)
# ------------------------------------------------------------- primitives
for alg in (P.SIG_D, P.SIG_F):
    s = oqs.Signature(alg)
    bench(f"{alg} keygen", lambda _: s.generate_keypair())
    pk = s.generate_keypair()
    sig = s.sign(MSG)
    bench(f"{alg} sign", lambda _: s.sign(MSG))
    bench(f"{alg} verify", lambda _: s.verify(MSG, sig, pk))

k = oqs.KeyEncapsulation(P.KEM)
bench(f"{P.KEM} keygen", lambda _: k.generate_keypair())
pk_r = k.generate_keypair()
ct_, ss = k.encap_secret(pk_r)
bench(f"{P.KEM} encaps", lambda _: k.encap_secret(pk_r))
bench(f"{P.KEM} decaps", lambda _: k.decap_secret(ct_))

# ---------------------------------------------- wrapper-overhead estimate
lib = oqsn.native()
for alg in (P.SIG_D, P.SIG_F):
    s = oqs.Signature(alg)
    pk = s.generate_keypair()
    sigp = s._sig
    sk = s.secret_key
    sbuf = ct.create_string_buffer(sigp.contents.length_signature)
    slen = ct.c_size_t(0)
    mbuf = ct.create_string_buffer(MSG, len(MSG))
    def raw_sign(_):
        slen.value = sigp.contents.length_signature
        assert lib.OQS_SIG_sign(sigp, ct.byref(sbuf), ct.byref(slen), mbuf, ct.c_size_t(len(MSG)), sk) == 0
    bench(f"{alg} sign (direct ctypes)", raw_sign)
    raw_sign(None)
    sig_b = ct.create_string_buffer(sbuf.raw[: slen.value], slen.value)
    pkb = ct.create_string_buffer(pk, len(pk))
    L = slen.value
    def raw_verify(_):
        assert lib.OQS_SIG_verify(sigp, mbuf, ct.c_size_t(len(MSG)), sig_b, ct.c_size_t(L), pkb) == 0
    bench(f"{alg} verify (direct ctypes)", raw_verify)

# ------------------------------------------------ combined dual signature
ident = P.keygen()
vd, vf = oqs.Signature(P.SIG_D), oqs.Signature(P.SIG_F)

def combined_keygen(_):
    P.keygen()
bench("Dual keygen (ML-DSA-65 + Falcon-512)", combined_keygen)

payload = P.signed_payload(CHAIN_ID, CONTRACT, 0, ident.key_id, keccak(MSG))
bench("Dual sign (Sign_D + Sign_F)", lambda _: P.dual_sign(ident, payload))
sd, sf = P.dual_sign(ident, payload)
bench("Dual verify (Verify_D AND Verify_F)", lambda _: P.dual_verify(ident.pk_d, ident.pk_f, payload, sd, sf, vd, vf))
c = P.commitment(CHAIN_ID, CONTRACT, 0, sd, sf, ident.key_id, keccak(MSG))
bench("Commitment C (abi.encode + keccak256)", lambda _: P.commitment(CHAIN_ID, CONTRACT, 0, sd, sf, ident.key_id, keccak(MSG)))
bench("keyId (abi.encode + keccak256)", lambda _: P.key_id(ident.pk_d, ident.pk_f))
bench("Record build (hash m, payload, dual sign, C)", lambda _: P.make_record(ident, MSG, CHAIN_ID, CONTRACT, 0))
rec = P.make_record(ident, MSG, CHAIN_ID, CONTRACT, 0)
bench("Record verify (keyId, C, Verify_D, Verify_F)", lambda _: P.verify_record(rec, ident.pk_d, ident.pk_f, CHAIN_ID, CONTRACT, vd, vf))

# ------------------------------------------------- optional ML-KEM path
pk_r, sk_r = P.kem_keygen()
kem_e = oqs.KeyEncapsulation(P.KEM)
kem_d = oqs.KeyEncapsulation(P.KEM, sk_r)
sizes = {}
for L_ in (32, 256, 1024):
    pt = os.urandom(L_)
    bench(f"KEM encrypt {L_} B (Encaps+HKDF+AES-GCM)", lambda _: P.encrypt_for(pk_r, pt, CHAIN_ID, 1, kem_e))
    b = P.encrypt_for(pk_r, pt, CHAIN_ID, 1, kem_e)
    sizes[L_] = len(b)
    bench(f"KEM decrypt {L_} B (Decaps+HKDF+AES-GCM)", lambda _: P.decrypt_bundle(sk_r, b, CHAIN_ID, 1, kem_d))
    assert P.decrypt_bundle(sk_r, b, CHAIN_ID, 1, kem_d) == pt

# ----------------------------------------------- Falcon signature lengths
fl = [len(ident.signer_f().sign(os.urandom(32))) for _ in range(N)]

# -------------------------------------------------------------- outputs
with open(os.path.join(OUT, "pqc_raw.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["operation", "iteration", "ns"]); w.writerows(raw_rows)
with open(os.path.join(OUT, "pqc_summary.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(summary[0].keys())); w.writeheader()
    for r in summary:
        w.writerow({k: (f"{v:.5f}" if isinstance(v, float) else v) for k, v in r.items()})

sizes_tbl = {}
for alg in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Dilithium3", "Falcon-512", "Falcon-1024"]:
    s = oqs.Signature(alg)
    sizes_tbl[alg] = {"pk": s.length_public_key, "sk": s.length_secret_key, "sig_max": s.length_signature,
                      "claimed_nist_level": s.claimed_nist_level, "alg_version": (s.alg_version.decode() if isinstance(s.alg_version, bytes) else str(s.alg_version))}
for alg in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
    kk = oqs.KeyEncapsulation(alg)
    sizes_tbl[alg] = {"pk": kk.length_public_key, "sk": kk.length_secret_key, "ct": kk.length_ciphertext,
                      "ss": kk.length_shared_secret, "claimed_nist_level": kk.claimed_nist_level}
with open(os.path.join(OUT, "falcon512_sig_lengths.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["iteration", "sig_bytes"]); w.writerows(enumerate(fl))
env = {
    "cpu": platform.processor(), "cpu_name": "Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz",
    "logical_cpus": psutil.cpu_count(), "ram_gb": round(psutil.virtual_memory().total / 2**30, 1),
    "os": platform.platform(), "python": platform.python_version(),
    "liboqs": oqs.oqs_version(), "liboqs_python": oqs.oqs_python_version(),
    "affinity": proc.cpu_affinity(), "iters": N, "warmup": W,
    "cpu_freq_start_mhz": psutil.cpu_freq().current if psutil.cpu_freq() else None,
    "sizes": sizes_tbl, "kem_bundle_bytes": sizes,
    "falcon512_sig_len": {"mean": statistics.fmean(fl), "min": min(fl), "max": max(fl)},
    "record_bytes": {"sig_d": len(sd), "sig_f": len(sf), "pk_d": len(ident.pk_d), "pk_f": len(ident.pk_f)},
    "date": time.strftime("%Y-%m-%d %H:%M:%S"),
}
with open(os.path.join(OUT, "pqc_env.json"), "w") as f:
    json.dump(env, f, indent=1)
print(json.dumps(env, indent=1))
