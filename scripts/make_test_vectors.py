"""Generate real ML-DSA-65 / Falcon-512 test vectors for the Hardhat test-suite
(test/PQCAnchor.test.js checks that Solidity and Python encode C, keyId and the
Merkle tree identically) and run the Python-side self-tests."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pqc_lib as P
from eth_utils import keccak

CHAIN_ID = 31337
# Address of the first contract deployed by Hardhat account #0 (deterministic).
CONTRACT = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
ACCOUNT = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

ident = P.keygen()
recs = [P.make_record(ident, f"record-{i}".encode(), CHAIN_ID, CONTRACT, i) for i in range(5)]
for r in recs:
    assert P.verify_record(r, ident.pk_d, ident.pk_f, CHAIN_ID, CONTRACT)
# tamper tests
bad = P.Record(recs[0].nonce, b"tampered", recs[0].sig_d, recs[0].sig_f, recs[0].key_id, recs[0].c)
assert not P.verify_record(bad, ident.pk_d, ident.pk_f, CHAIN_ID, CONTRACT)
other = P.keygen()
assert not P.verify_record(recs[0], other.pk_d, other.pk_f, CHAIN_ID, CONTRACT)
# cross-chain replay: same record checked under another chainId must fail
assert not P.verify_record(recs[0], ident.pk_d, ident.pk_f, 1, CONTRACT)
# PoP
pop = P.proof_of_possession(ident, ACCOUNT, CHAIN_ID, CONTRACT)
assert P.verify_pop(pop, ACCOUNT, CHAIN_ID, CONTRACT)
assert not P.verify_pop(pop, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", CHAIN_ID, CONTRACT)
# Merkle
leaves = [P.leaf_hash(r.c) for r in recs]
lv = P.merkle_build(leaves)
root = P.merkle_root(lv)
proofs = [P.merkle_proof(lv, i) for i in range(len(leaves))]
assert all(P.merkle_verify(leaves[i], proofs[i], root) for i in range(len(leaves)))
# KEM path
pk_r, sk_r = P.kem_keygen()
bundle = P.encrypt_for(pk_r, b"secret payload", CHAIN_ID, 7)
assert P.decrypt_bundle(sk_r, bundle, CHAIN_ID, 7) == b"secret payload"
try:
    P.decrypt_bundle(sk_r, bundle, CHAIN_ID, 8); raise SystemExit("KEM: wrong-context decrypt succeeded")
except Exception as e:
    assert "InvalidTag" in type(e).__name__
enc_rec = P.make_record(ident, bundle, CHAIN_ID, CONTRACT, 5)  # encrypt-then-sign
assert P.verify_record(enc_rec, ident.pk_d, ident.pk_f, CHAIN_ID, CONTRACT)

out = {
    "chainId": CHAIN_ID, "contract": CONTRACT, "account": ACCOUNT,
    "pk_d": "0x" + ident.pk_d.hex(), "pk_f": "0x" + ident.pk_f.hex(), "keyId": "0x" + ident.key_id.hex(),
    "records": [{"nonce": r.nonce, "sig_d": "0x" + r.sig_d.hex(), "sig_f": "0x" + r.sig_f.hex(),
                 "msgHash": "0x" + keccak(r.m).hex(), "c": "0x" + r.c.hex()} for r in recs],
    "leaves": ["0x" + l.hex() for l in leaves], "root": "0x" + root.hex(),
    "proofs": [["0x" + p.hex() for p in pr] for pr in proofs],
}
os.makedirs(os.path.join(os.path.dirname(__file__), "..", "test"), exist_ok=True)
with open(os.path.join(os.path.dirname(__file__), "..", "test", "vectors.json"), "w") as f:
    json.dump(out, f, indent=1)
print("python self-tests passed; sizes sig_d", len(recs[0].sig_d), "sig_f", [len(r.sig_f) for r in recs],
      "pk_d", len(ident.pk_d), "pk_f", len(ident.pk_f))
