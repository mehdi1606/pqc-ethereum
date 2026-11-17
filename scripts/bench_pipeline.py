"""End-to-end benchmark of the real dual-signature pipeline (Table VI-b, Table VIII-b).

Requires:  Hardhat node on 127.0.0.1:8545  (npx hardhat node)
           Kubo IPFS API on 127.0.0.1:5001  (docker run ... ipfs/kubo:v0.32.1)
Signer side per record:   build record (hash m, dual sign, C) -> ECDSA-sign anchor tx ->
                          IPFS add (binary record) -> submit tx + wait receipt
Verifier side per record: IPFS cat record -> eth_call commitments(account,C) ->
                          eth_call accounts(account) (registry) -> [IPFS cat key bundle, cached]
                          -> recompute C, Verify_D AND Verify_F, keyId == registry, block order
Batched mode:             N records -> Merkle tree -> IPFS manifest -> anchorBatchRoot;
                          verifier additionally checks the Merkle proof off-chain.
Outputs raw per-iteration CSVs in results/.     Run: python scripts/bench_pipeline.py
"""
import argparse, csv, json, os, statistics, sys, time, math
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import requests, oqs, psutil
from web3 import Web3
from eth_abi import encode as abi_encode, decode as abi_decode
from eth_utils import keccak
import pqc_lib as P

ap = argparse.ArgumentParser()
ap.add_argument("--iters", type=int, default=1000)
ap.add_argument("--warmup", type=int, default=20)
args = ap.parse_args()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "results")
IPFS = "http://127.0.0.1:5001/api/v0"
# Hardhat default test account #0 (publicly known development key; local chain only)
PRIV = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

try:
    psutil.Process().cpu_affinity([2])
except Exception:
    pass

w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
acct = w3.eth.account.from_key(PRIV)
art = json.load(open(os.path.join(ROOT, "artifacts", "contracts", "PQCAnchor.sol", "PQCAnchor.json")))
CHAIN_ID = w3.eth.chain_id
S = requests.Session()


def ipfs_add(data: bytes) -> str:
    r = S.post(f"{IPFS}/add", params={"cid-version": 1, "pin": "true", "quieter": "true"}, files={"file": data})
    r.raise_for_status()
    return r.json()["Hash"]


def ipfs_cat(cid: str) -> bytes:
    r = S.post(f"{IPFS}/cat", params={"arg": cid})
    r.raise_for_status()
    return r.content


def send(fn, nonce, gas=500_000):
    tx = fn.build_transaction({"from": acct.address, "nonce": nonce, "chainId": CHAIN_ID, "gas": gas,
                               "maxFeePerGas": w3.to_wei(2, "gwei"), "maxPriorityFeePerGas": w3.to_wei(1, "gwei")})
    t0 = time.perf_counter_ns()
    signed = acct.sign_transaction(tx)
    t1 = time.perf_counter_ns()
    h = w3.eth.send_raw_transaction(signed.raw_transaction)
    rc = w3.eth.wait_for_transaction_receipt(h, poll_latency=0.001)
    t2 = time.perf_counter_ns()
    assert rc.status == 1
    return rc, t1 - t0, t2 - t1


def ser_record(r: P.Record) -> bytes:   # canonical binary record stored on IPFS (abi.encode)
    return abi_encode(["uint256", "bytes", "bytes", "bytes", "bytes32"], [r.nonce, r.m, r.sig_d, r.sig_f, r.key_id])


def de_record(b: bytes) -> P.Record:
    n, m, sd, sf, kid = abi_decode(["uint256", "bytes", "bytes", "bytes", "bytes32"], b)
    mh = keccak(m)
    return P.Record(n, m, sd, sf, kid, b"")


# ---------------------------------------------------------------- deploy
C_ = w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"])
txn = acct.address and w3.eth.get_transaction_count(acct.address)
rc, _, _ = send(C_.constructor(), txn, gas=3_000_000)
contract = w3.eth.contract(address=rc.contractAddress, abi=art["abi"])
CADDR = rc.contractAddress
nonce_eoa = txn + 1

# ------------------------------------------------------ one-off: registration
one_off = []
t0 = time.perf_counter_ns(); ident = P.keygen(); t1 = time.perf_counter_ns()
one_off.append(("Dual keygen", t1 - t0))
t0 = time.perf_counter_ns(); pop = P.proof_of_possession(ident, acct.address, CHAIN_ID, CADDR); t1 = time.perf_counter_ns()
one_off.append(("Proof of possession (2 PQ signatures)", t1 - t0))
bundle = abi_encode(["bytes", "bytes", "bytes", "bytes"], [pop["pk_d"], pop["pk_f"], pop["pop_d"], pop["pop_f"]])
t0 = time.perf_counter_ns(); pk_cid = ipfs_add(bundle); t1 = time.perf_counter_ns()
one_off.append(("IPFS add key bundle", t1 - t0))
rc, tsig, tconf = send(contract.functions.registerPQKey(ident.key_id, pk_cid), nonce_eoa); nonce_eoa += 1
one_off.append(("ECDSA sign registerPQKey tx", tsig)); one_off.append(("Submit + receipt registerPQKey", tconf))
reg_gas = rc.gasUsed
with open(os.path.join(OUT, "pipeline_oneoff.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["step", "ns"]); w.writerows(one_off)
    w.writerow(["registerPQKey gasUsed", reg_gas]); w.writerow(["key bundle bytes", len(bundle)])

vd, vf = oqs.Signature(P.SIG_D), oqs.Signature(P.SIG_F)
key_cache = {}


def verifier(account: str, rec_cid: str, batch=None, use_cache=True):
    """Returns (ok, per-stage ns dict, round_trips)."""
    t = {}; rt = 0
    a = time.perf_counter_ns(); raw = ipfs_cat(rec_cid); rt += 1; t["ipfs_cat_record"] = time.perf_counter_ns() - a
    rec = de_record(raw)
    mh = keccak(rec.m)
    a = time.perf_counter_ns()
    reg = contract.functions.accounts(account).call(); rt += 1
    t["eth_call_registry"] = time.perf_counter_ns() - a
    kid_reg, reg_block = reg[0], reg[1]
    a = time.perf_counter_ns()
    if use_cache and kid_reg in key_cache:
        pk_d, pk_f = key_cache[kid_reg]
    else:
        ev = contract.events.KeyRegistered().get_logs(from_block=0, argument_filters={"account": account}); rt += 1
        kb = ipfs_cat(ev[-1].args.pkCID); rt += 1
        pk_d, pk_f, pop_d, pop_f = abi_decode(["bytes", "bytes", "bytes", "bytes"], kb)
        msg = P.registration_message(account, CHAIN_ID, CADDR, kid_reg)
        assert vd.verify(msg, pop_d, pk_d) and vf.verify(msg, pop_f, pk_f)   # proof of possession
        key_cache[kid_reg] = (pk_d, pk_f)
    t["key_fetch"] = time.perf_counter_ns() - a
    a = time.perf_counter_ns()
    c = P.commitment(CHAIN_ID, CADDR, rec.nonce, rec.sig_d, rec.sig_f, rec.key_id, mh)
    t["recompute_C"] = time.perf_counter_ns() - a
    a = time.perf_counter_ns()
    if batch is None:
        packed = contract.functions.commitments(account, c).call(); rt += 1
        anchor_block, anchored_nonce = packed >> 64, packed & ((1 << 64) - 1)
        ok_chain = packed != 0 and anchored_nonce == rec.nonce
    else:
        proof, root = batch
        b = contract.functions.batches(account, root).call(); rt += 1
        anchor_block, first, n = b
        ok_chain = anchor_block != 0 and first <= rec.nonce < first + n
    t["eth_call_anchor"] = time.perf_counter_ns() - a
    if batch is not None:
        a = time.perf_counter_ns()
        ok_chain = ok_chain and P.merkle_verify(P.leaf_hash(c), proof, root)
        t["merkle_verify"] = time.perf_counter_ns() - a
    a = time.perf_counter_ns()
    payload = P.signed_payload(CHAIN_ID, CADDR, rec.nonce, rec.key_id, mh)
    ok_sig = P.dual_verify(pk_d, pk_f, payload, rec.sig_d, rec.sig_f, vd, vf)
    t["dual_verify"] = time.perf_counter_ns() - a
    ok = ok_sig and ok_chain and rec.key_id == kid_reg and reg_block < anchor_block
    return ok, t, rt


# -------------------------------------------------- single-record pipeline
rows_s, rows_v, sizes = [], [], []
first_verify = None
for i in range(args.warmup + args.iters):
    m = os.urandom(256)
    nonce = contract.functions.accounts(acct.address).call()[3]
    a = time.perf_counter_ns(); rec = P.make_record(ident, m, CHAIN_ID, CADDR, nonce); t_build = time.perf_counter_ns() - a
    blob = ser_record(rec)
    a = time.perf_counter_ns(); cid = ipfs_add(blob); t_ipfs = time.perf_counter_ns() - a
    rc, t_ecdsa, t_conf = send(contract.functions.anchorCommitment(rec.c, nonce, cid), nonce_eoa); nonce_eoa += 1
    if i == args.warmup:
        key_cache.clear()
        ok, tv, rt = verifier(acct.address, cid, use_cache=False)   # cold verifier (fetches keys)
        first_verify = (tv, rt)
    ok, tv, rt = verifier(acct.address, cid)
    assert ok, "verification failed"
    if i >= args.warmup:
        rows_s.append([i - args.warmup, t_build, t_ecdsa, t_ipfs, t_conf, rc.gasUsed, len(blob)])
        rows_v.append([i - args.warmup] + [tv[k] for k in ("ipfs_cat_record", "eth_call_registry", "key_fetch", "recompute_C", "eth_call_anchor", "dual_verify")] + [rt])

with open(os.path.join(OUT, "pipeline_signer.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["iter", "record_build_ns", "ecdsa_tx_sign_ns", "ipfs_add_ns", "submit_confirm_ns", "gasUsed", "ipfs_record_bytes"]); w.writerows(rows_s)
with open(os.path.join(OUT, "pipeline_verifier.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["iter", "ipfs_cat_record_ns", "eth_call_registry_ns", "key_fetch_cached_ns", "recompute_C_ns", "eth_call_anchor_ns", "dual_verify_ns", "round_trips"]); w.writerows(rows_v)
with open(os.path.join(OUT, "pipeline_verifier_cold.json"), "w") as f:
    json.dump({"stages_ns": first_verify[0], "round_trips": first_verify[1]}, f, indent=1)

# ---------------------------------------------------- tampering checks
rec_t = P.make_record(ident, b"genuine", CHAIN_ID, CADDR, contract.functions.accounts(acct.address).call()[3])
cid_t = ipfs_add(ser_record(rec_t))
send(contract.functions.anchorCommitment(rec_t.c, rec_t.nonce, cid_t), nonce_eoa); nonce_eoa += 1
forged = P.Record(rec_t.nonce, b"forged", rec_t.sig_d, rec_t.sig_f, rec_t.key_id, b"")
ok_forged, _, _ = verifier(acct.address, ipfs_add(ser_record(forged)))
attacker = P.keygen()   # Q-day attacker controls the ECDSA account but not the PQ keys
rec_a = P.make_record(attacker, b"attacker", CHAIN_ID, CADDR, contract.functions.accounts(acct.address).call()[3])
cid_a = ipfs_add(ser_record(rec_a))
send(contract.functions.anchorCommitment(rec_a.c, rec_a.nonce, cid_a), nonce_eoa); nonce_eoa += 1
ok_attacker, _, _ = verifier(acct.address, cid_a)
with open(os.path.join(OUT, "pipeline_negative_tests.json"), "w") as f:
    json.dump({"tampered_message_accepted": ok_forged,
               "ecdsa_controlled_account_with_foreign_pq_key_accepted": ok_attacker}, f, indent=1)
assert not ok_forged and not ok_attacker

# ---------------------------------------------------- batched pipeline
brow = []
for N in (10, 100, 1000):
    first = contract.functions.accounts(acct.address).call()[3]
    recs, cids = [], []
    a = time.perf_counter_ns()
    for j in range(N):
        recs.append(P.make_record(ident, os.urandom(256), CHAIN_ID, CADDR, first + j))
    t_sign = time.perf_counter_ns() - a
    a = time.perf_counter_ns()
    leaves = [P.leaf_hash(r.c) for r in recs]
    lv = P.merkle_build(leaves); root = P.merkle_root(lv)
    proofs = [P.merkle_proof(lv, j) for j in range(N)]
    t_tree = time.perf_counter_ns() - a
    a = time.perf_counter_ns()
    for j, r in enumerate(recs):   # each record object stores its own inclusion proof
        cids.append(ipfs_add(ser_record(r) + b"".join(proofs[j])))
    t_ipfs = time.perf_counter_ns() - a
    manifest = abi_encode(["bytes32", "bytes32[]", "string[]"], [root, leaves, cids])
    mcid = ipfs_add(manifest)
    rc, t_e, t_c = send(contract.functions.anchorBatchRoot(root, N, mcid), nonce_eoa); nonce_eoa += 1
    # verify a sample of records (all if N <= 100)
    sample = range(N) if N <= 100 else range(0, N, N // 100)
    vt = []
    for j in sample:
        raw = ipfs_cat(cids[j])
        body, prf = raw[: len(ser_record(recs[j]))], raw[len(ser_record(recs[j])):]
        proof = [prf[k:k + 32] for k in range(0, len(prf), 32)]
        ok, tv, rt = verifier(acct.address, ipfs_add(body), batch=(proof, root))
        assert ok
        vt.append((tv["merkle_verify"], tv["dual_verify"], rt, len(proof)))
    brow.append([N, rc.gasUsed, t_sign, t_tree, t_ipfs, t_c, len(manifest),
                 statistics.fmean(v[0] for v in vt), statistics.fmean(v[1] for v in vt), vt[0][2], max(v[3] for v in vt)])
with open(os.path.join(OUT, "pipeline_batch.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["N", "anchorBatchRoot_gasUsed", "sign_all_ns", "tree_and_proofs_ns", "ipfs_add_all_ns", "submit_confirm_ns",
                "manifest_bytes", "merkle_verify_mean_ns", "dual_verify_mean_ns", "verifier_round_trips", "max_proof_len"])
    w.writerows(brow)
print("pipeline done", len(rows_s), "records; batches", [b[0] for b in brow])
