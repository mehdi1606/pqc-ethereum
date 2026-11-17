"""Recomputes every derived number in the paper from results/*.csv:
  - security-level table (Table I) with the primary-source values (constants below, cited)
  - QARL, QSM, COE (Eqs. in Sec. III-A) with all inputs printed
  - USD cost sensitivity table and the Merkle "below one cent" threshold
  - combined pipeline totals and storage/communication bytes per record
Writes results/metrics.json, results/cost_sensitivity.csv, results/security_levels.csv
Run: python scripts/compute_metrics.py
"""
import csv, json, math, os, statistics

R = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")


def rcsv(name):
    with open(os.path.join(R, name), newline="") as f:
        return list(csv.DictReader(f))


summ = {r["operation"]: r for r in rcsv("pqc_summary.csv")}
mean = lambda op: float(summ[op]["mean_ms"])
env = json.load(open(os.path.join(R, "pqc_env.json")))
ops = {r["operation"]: int(r["gasUsed"]) for r in rcsv("gas_operations.csv")}
batch = {int(r["N"]): int(r["anchorBatchRoot_gasUsed"]) for r in rcsv("gas_batch.csv")}
incl = {int(r["N"]): r for r in rcsv("gas_inclusion.csv")}

# ---------------------------------------------------------- D6 security table
# Values transcribed from the primary specifications (see research/FACTS_VERIFIED.md):
#  ML-KEM-768: Kyber round-3 spec v3.02, Table 4 (primal attack)
#  ML-DSA-65:  Dilithium round-3 spec v3.1, Table 1 (MLWE and MSIS); FIPS 204 Sec. 4 category
#  Falcon-512: Falcon spec v1.2, Table 3.3 (key recovery and forgery)
SEC = [
    # scheme, NIST category, reference primitive, attack, beta, classical, quantum
    ("ML-KEM-768", 3, "AES-192 key search", "MLWE (primal)", 626, 183, 166),
    ("ML-DSA-65", 3, "AES-192 key search", "MLWE (key recovery)", 624, 182, 165),
    ("ML-DSA-65", 3, "AES-192 key search", "MSIS (forgery)", 638, 186, 169),
    ("Falcon-512", 1, "AES-128 key search", "NTRU key recovery", 458, 133, 121),
    ("Falcon-512", 1, "AES-128 key search", "NTRU-SIS forgery", 411, 120, 108),
]
for s in SEC:   # core-SVP model: classical 0.292*beta, quantum 0.265*beta (rounded as in the specs)
    assert abs(0.292 * s[4] - s[5]) < 1.0 and abs(0.265 * s[4] - s[6]) < 1.0, s
with open(os.path.join(R, "security_levels.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["scheme", "nist_category", "category_reference", "attack", "beta", "coreSVP_classical_bits", "coreSVP_quantum_bits",
                "0.292beta", "0.265beta"])
    for s in SEC:
        w.writerow(list(s) + [f"{0.292*s[4]:.1f}", f"{0.265*s[4]:.1f}"])

lam_D = min(s[6] for s in SEC if s[0] == "ML-DSA-65")    # 165
lam_F = min(s[6] for s in SEC if s[0] == "Falcon-512")   # 108
lam_min, lam_max = min(lam_D, lam_F), max(lam_D, lam_F)

# ---------------------------------------------------------- measured inputs
sz = env["sizes"]
pk_D, pk_F = sz["ML-DSA-65"]["pk"], sz["Falcon-512"]["pk"]
sig_D, sig_F = sz["ML-DSA-65"]["sig_max"], env["falcon512_sig_len"]["mean"]
T_sign_D, T_ver_D = mean("ML-DSA-65 sign"), mean("ML-DSA-65 verify")
T_dual_sign, T_dual_ver = mean("Dual sign (Sign_D + Sign_F)"), mean("Dual verify (Verify_D AND Verify_F)")

# ---------------------------------------------------------- metrics
# QARL (heuristic, concrete security): an adversary of cost 2^t succeeds w.p. <= 2^(t - lambda);
# for a single unit-cost attempt the residual probability is 2^-lambda_min.
QARL = (1 - 2.0 ** (-lam_min)) * 100
# QSM = (lambda_proposed - lambda_ECDSA) / lambda_ref ; lambda_ECDSA (quantum) = 0 (Shor);
# lambda_ref = 128 = classical security of the secp256k1 ECDSA being backed up.
LAM_REF_QSM = 128
QSM_min = (lam_min - 0) / LAM_REF_QSM * 100
QSM_max = (lam_max - 0) / LAM_REF_QSM * 100
# COE = (lam/lam_ref) / ( (k_s/k_ref + S_s/S_ref + T_s/T_ref) / 3 )
# reference = the single-signature ML-DSA-65 configuration measured on the same machine
k_s, S_s, T_s = pk_D + pk_F, sig_D + sig_F, T_dual_sign + T_dual_ver
k_ref, S_ref, T_ref, lam_ref = pk_D, sig_D, T_sign_D + T_ver_D, lam_D
den = (k_s / k_ref + S_s / S_ref + T_s / T_ref) / 3
COE_min = (lam_min / lam_ref) / den
COE_max = (lam_max / lam_ref) / den

# ---------------------------------------------------------- costs
G_single = ops["anchorCommitment_next1"]
G_batch = {n: g for n, g in batch.items()}
G_b = statistics.median(G_batch.values())
prices = [0.2, 0.5, 2, 5, 20]       # gwei
eth = [2000, 3500]                  # USD/ETH
cost_rows = []
for p in prices:
    for e in eth:
        usd = lambda g: g * p * 1e-9 * e
        row = {"gwei": p, "eth_usd": e, "single_anchor_usd": usd(G_single), "register_usd": usd(ops["registerPQKey"])}
        for n in (10, 100, 1000, 10000):
            row[f"batch_N{n}_per_record_usd"] = usd(G_batch[n]) / n
        row["N_min_below_1cent"] = math.ceil(usd(G_b) / 0.01) if usd(G_b) > 0.01 else 1
        cost_rows.append(row)
with open(os.path.join(R, "cost_sensitivity.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(cost_rows[0].keys())); w.writeheader()
    for r in cost_rows:
        w.writerow({k: (f"{v:.5f}" if isinstance(v, float) else v) for k, v in r.items()})
savings = {n: (1 - (G_batch[n] / n) / G_single) * 100 for n in (10, 100, 1000, 10000)}
# same threshold with the 55,000-gas estimate of the first submission, kept for comparison
legacy_threshold = math.ceil(55000 * 20e-9 * 3000 / 0.01)
ref_threshold = math.ceil(G_b * 20e-9 * 3000 / 0.01)

# ---------------------------------------------------------- pipeline totals
ps = rcsv("pipeline_signer.csv"); pv = rcsv("pipeline_verifier.csv")
med = lambda rows, k: statistics.median(float(r[k]) for r in rows) / 1e6
mn = lambda rows, k: statistics.fmean(float(r[k]) for r in rows) / 1e6
signer = {k: (mn(ps, k), med(ps, k)) for k in ("record_build_ns", "ecdsa_tx_sign_ns", "ipfs_add_ns", "submit_confirm_ns")}
verifier = {k: (mn(pv, k), med(pv, k)) for k in ("ipfs_cat_record_ns", "eth_call_registry_ns", "key_fetch_cached_ns", "recompute_C_ns", "eth_call_anchor_ns", "dual_verify_ns")}
rec_bytes = int(ps[0]["ipfs_record_bytes"])

out = {
    "lambda": {"ML-DSA-65_q": lam_D, "Falcon-512_q": lam_F, "min": lam_min, "max": lam_max},
    "QARL_pct": QARL, "QSM_min_pct": QSM_min, "QSM_max_pct": QSM_max, "QSM_lambda_ref": LAM_REF_QSM,
    "COE": {"inputs": {"k_s": k_s, "S_s": S_s, "T_s_ms": T_s, "k_ref": k_ref, "S_ref": S_ref, "T_ref_ms": T_ref,
                       "lambda_ref": lam_ref, "ratio_k": k_s / k_ref, "ratio_S": S_s / S_ref, "ratio_T": T_s / T_ref, "denominator": den},
            "COE_lambda_min": COE_min, "COE_lambda_max": COE_max},
    "gas": {"single": G_single, "batch": G_batch, "register": ops["registerPQKey"], "deploy": ops["deploy"]},
    "savings_pct": savings, "threshold_20gwei_3000usd": ref_threshold, "legacy_threshold_55000gas": legacy_threshold,
    "signer_ms_mean_median": signer, "verifier_ms_mean_median": verifier,
    "signer_total_mean_ms": sum(v[0] for v in signer.values()),
    "verifier_total_mean_ms": sum(v[0] for v in verifier.values()),
    "crypto_only": {"dual_keygen": mean("Dual keygen (ML-DSA-65 + Falcon-512)"), "dual_sign": T_dual_sign, "dual_verify": T_dual_ver,
                    "record_build": mean("Record build (hash m, payload, dual sign, C)"), "record_verify": mean("Record verify (keyId, C, Verify_D, Verify_F)")},
    "bytes": {"sig_D": sig_D, "sig_F_mean": sig_F, "pk_D": pk_D, "pk_F": pk_F, "sigs": sig_D + sig_F, "pks": pk_D + pk_F,
              "ipfs_record_256B_msg": rec_bytes, "kem_bundle": env["kem_bundle_bytes"], "ml_kem_ct": sz["ML-KEM-768"]["ct"]},
}
json.dump(out, open(os.path.join(R, "metrics.json"), "w"), indent=1)
print(json.dumps(out, indent=1))
