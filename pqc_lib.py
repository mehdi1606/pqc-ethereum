"""
pqc_lib.py - off-chain client of the hybrid PQC/Ethereum anchoring scheme (JASTT paper).

Configuration: mandatory dual signature
    ML-DSA-65 (FIPS 204)  AND  Falcon-512 (FN-DSA-512, FIPS 206 draft)
via liboqs / liboqs-python (`import oqs`).  ML-KEM-768 (FIPS 203) is used ONLY
for optional payload confidentiality.

All encodings use Solidity `abi.encode` (length-prefixed, 32-byte aligned), so
variable-length Falcon signatures cannot be parsed ambiguously:

  keyId = keccak256(abi.encode(bytes pk_D, bytes pk_F))
  mu    = abi.encode("PQC-ETH-SIGN-v1", chainId, contract, nonce, keyId, keccak256(m))
          (the byte string signed by BOTH PQ schemes)
  C     = keccak256(abi.encode("PQC-ETH-ANCHOR-v1", chainId, contract, nonce,
                               bytes sig_D, bytes sig_F, keyId, keccak256(m)))
  leaf  = keccak256(keccak256(abi.encode(C)))          (OpenZeppelin double hash)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

import oqs
from eth_abi import encode as abi_encode
from eth_utils import keccak
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

SIG_D = "ML-DSA-65"
SIG_F = "Falcon-512"
KEM = "ML-KEM-768"

DST_ANCHOR = "PQC-ETH-ANCHOR-v1"
DST_SIGN = "PQC-ETH-SIGN-v1"
DST_REGISTER = "PQC-ETH-REGISTER-v1"
DST_ROTATE = "PQC-ETH-ROTATE-v1"
DST_KEM = b"PQC-ETH-KEM-v1"


# --------------------------------------------------------------------- keys
@dataclass
class PQIdentity:
    pk_d: bytes
    sk_d: bytes
    pk_f: bytes
    sk_f: bytes
    _sd: object = field(default=None, repr=False)
    _sf: object = field(default=None, repr=False)

    @property
    def key_id(self) -> bytes:
        return key_id(self.pk_d, self.pk_f)

    def signer_d(self):
        if self._sd is None:
            self._sd = oqs.Signature(SIG_D, self.sk_d)
        return self._sd

    def signer_f(self):
        if self._sf is None:
            self._sf = oqs.Signature(SIG_F, self.sk_f)
        return self._sf


def keygen() -> PQIdentity:
    sd = oqs.Signature(SIG_D)
    pk_d = sd.generate_keypair()
    sf = oqs.Signature(SIG_F)
    pk_f = sf.generate_keypair()
    return PQIdentity(pk_d, sd.export_secret_key(), pk_f, sf.export_secret_key(), sd, sf)


def key_id(pk_d: bytes, pk_f: bytes) -> bytes:
    return keccak(abi_encode(["bytes", "bytes"], [pk_d, pk_f]))


# ------------------------------------------------------------ registration
def registration_message(account: str, chain_id: int, contract: str, kid: bytes) -> bytes:
    return abi_encode(["string", "address", "uint256", "address", "bytes32"],
                      [DST_REGISTER, account, chain_id, contract, kid])


def proof_of_possession(ident: PQIdentity, account, chain_id, contract) -> dict:
    msg = registration_message(account, chain_id, contract, ident.key_id)
    return {"pk_d": ident.pk_d, "pk_f": ident.pk_f, "key_id": ident.key_id,
            "pop_d": ident.signer_d().sign(msg), "pop_f": ident.signer_f().sign(msg)}


def verify_pop(bundle: dict, account, chain_id, contract) -> bool:
    if key_id(bundle["pk_d"], bundle["pk_f"]) != bundle["key_id"]:
        return False
    msg = registration_message(account, chain_id, contract, bundle["key_id"])
    with oqs.Signature(SIG_D) as vd, oqs.Signature(SIG_F) as vf:
        return vd.verify(msg, bundle["pop_d"], bundle["pk_d"]) and vf.verify(msg, bundle["pop_f"], bundle["pk_f"])


def rotation_message(account, chain_id, contract, old_kid: bytes, new_kid: bytes) -> bytes:
    return abi_encode(["string", "address", "uint256", "address", "bytes32", "bytes32"],
                      [DST_ROTATE, account, chain_id, contract, old_kid, new_kid])


# ----------------------------------------------------------- sign & commit
def signed_payload(chain_id: int, contract: str, nonce: int, kid: bytes, m_hash: bytes) -> bytes:
    return abi_encode(["string", "uint256", "address", "uint256", "bytes32", "bytes32"],
                      [DST_SIGN, chain_id, contract, nonce, kid, m_hash])


def commitment(chain_id: int, contract: str, nonce: int, sig_d: bytes, sig_f: bytes,
               kid: bytes, m_hash: bytes) -> bytes:
    return keccak(abi_encode(
        ["string", "uint256", "address", "uint256", "bytes", "bytes", "bytes32", "bytes32"],
        [DST_ANCHOR, chain_id, contract, nonce, sig_d, sig_f, kid, m_hash]))


def dual_sign(ident: PQIdentity, payload: bytes) -> tuple[bytes, bytes]:
    return ident.signer_d().sign(payload), ident.signer_f().sign(payload)


def dual_verify(pk_d: bytes, pk_f: bytes, payload: bytes, sig_d: bytes, sig_f: bytes,
                vd=None, vf=None) -> bool:
    """AND-combiner: both component signatures must verify."""
    vd = vd or oqs.Signature(SIG_D)
    vf = vf or oqs.Signature(SIG_F)
    return bool(vd.verify(payload, sig_d, pk_d)) and bool(vf.verify(payload, sig_f, pk_f))


@dataclass
class Record:
    nonce: int
    m: bytes           # signed bytes: plaintext, or the KEM/AEAD bundle (encrypt-then-sign)
    sig_d: bytes
    sig_f: bytes
    key_id: bytes
    c: bytes

    def to_json(self) -> dict:
        return {"nonce": self.nonce, "m": self.m.hex(), "sig_d": self.sig_d.hex(),
                "sig_f": self.sig_f.hex(), "key_id": self.key_id.hex(), "c": self.c.hex()}

    @staticmethod
    def from_json(d: dict) -> "Record":
        return Record(d["nonce"], bytes.fromhex(d["m"]), bytes.fromhex(d["sig_d"]),
                      bytes.fromhex(d["sig_f"]), bytes.fromhex(d["key_id"]), bytes.fromhex(d["c"]))


def make_record(ident: PQIdentity, m: bytes, chain_id: int, contract: str, nonce: int) -> Record:
    mh = keccak(m)
    kid = ident.key_id
    payload = signed_payload(chain_id, contract, nonce, kid, mh)
    sd, sf = dual_sign(ident, payload)
    return Record(nonce, m, sd, sf, kid, commitment(chain_id, contract, nonce, sd, sf, kid, mh))


def verify_record(rec: Record, pk_d: bytes, pk_f: bytes, chain_id: int, contract: str,
                  vd=None, vf=None) -> bool:
    """Checks (a) keyId opens to (pk_D, pk_F), (b) C opens, (c) Verify_D, (d) Verify_F.
    The registry check (keyId registered for the anchoring account before the anchor
    block) and the on-chain lookup of C are done by the caller (see pipeline_bench.py)."""
    if key_id(pk_d, pk_f) != rec.key_id:
        return False
    mh = keccak(rec.m)
    if commitment(chain_id, contract, rec.nonce, rec.sig_d, rec.sig_f, rec.key_id, mh) != rec.c:
        return False
    payload = signed_payload(chain_id, contract, rec.nonce, rec.key_id, mh)
    return dual_verify(pk_d, pk_f, payload, rec.sig_d, rec.sig_f, vd, vf)


# ------------------------------------------------------------------ Merkle
def leaf_hash(c: bytes) -> bytes:
    return keccak(keccak(abi_encode(["bytes32"], [c])))


def _hash_pair(a: bytes, b: bytes) -> bytes:
    return keccak(a + b) if a < b else keccak(b + a)   # OZ commutativeKeccak256


def merkle_build(leaves: list[bytes]) -> list[list[bytes]]:
    """Binary tree, sorted-pair hashing; an odd node is promoted unchanged.
    Proof length <= ceil(log2 N); verifiable with OZ MerkleProof.verify."""
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        cur, nxt = levels[-1], []
        for i in range(0, len(cur), 2):
            nxt.append(_hash_pair(cur[i], cur[i + 1]) if i + 1 < len(cur) else cur[i])
        levels.append(nxt)
    return levels


def merkle_root(levels) -> bytes:
    return levels[-1][0]


def merkle_proof(levels, index: int) -> list[bytes]:
    proof = []
    for lvl in levels[:-1]:
        sib = index ^ 1
        if sib < len(lvl):
            proof.append(lvl[sib])
        index //= 2
    return proof


def merkle_verify(leaf: bytes, proof: list[bytes], root: bytes) -> bool:
    h = leaf
    for p in proof:
        h = _hash_pair(h, p)
    return h == root


# ------------------------------------------- optional ML-KEM confidentiality
def _derive_key(K: bytes, chain_id: int, nonce: int) -> bytes:
    info = DST_KEM + chain_id.to_bytes(32, "big") + nonce.to_bytes(32, "big")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(K)


def kem_keygen():
    k = oqs.KeyEncapsulation(KEM)
    pk = k.generate_keypair()
    return pk, k.export_secret_key()


def encrypt_for(pk_r: bytes, plaintext: bytes, chain_id: int, nonce: int, kem=None) -> bytes:
    """Encaps(pk_R) -> (ct, K); HKDF-SHA256 -> AES-256-GCM key; 96-bit nonce.
    Returns the bundle ct || iv || ciphertext||tag that is then SIGNED and COMMITTED
    (encrypt-then-sign)."""
    kem = kem or oqs.KeyEncapsulation(KEM)
    ct, K = kem.encap_secret(pk_r)
    iv = os.urandom(12)
    body = AESGCM(_derive_key(K, chain_id, nonce)).encrypt(iv, plaintext, None)
    return abi_encode(["bytes", "bytes12", "bytes"], [ct, iv, body])


def decrypt_bundle(sk_r: bytes, bundle: bytes, chain_id: int, nonce: int, kem=None) -> bytes:
    from eth_abi import decode as abi_decode
    ct, iv, body = abi_decode(["bytes", "bytes12", "bytes"], bundle)
    kem = kem or oqs.KeyEncapsulation(KEM, sk_r)
    K = kem.decap_secret(ct)
    return AESGCM(_derive_key(K, chain_id, nonce)).decrypt(iv, body, None)   # raises on bad tag
