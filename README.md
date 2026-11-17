# PQC-Ethereum anchor: reference implementation

Hybrid on-chain/off-chain anchoring of **mandatory dual post-quantum signatures**
(ML-DSA-65 **and** Falcon-512) on Ethereum, with an on-chain post-quantum key registry,
Merkle batching, and optional ML-KEM-768 payload confidentiality (encrypt-then-sign).

This repository holds the code and the raw data of the paper

> E. Houari, A. A. Harchaoui, M. Elmounaoui and A. Younes, "Hybrid On-Chain/Off-Chain
> Integration of Post-Quantum Cryptography with Ethereum: A Lattice-Based Approach Using
> ML-DSA, Falcon and ML-KEM," submitted to JASTT, 2026.

Every number in the paper comes from a file in `results/`, produced by the scripts below.

**Scope.** The design protects records and attestations anchored on Ethereum. It does not
protect Ethereum accounts or funds, because transactions are still authorised with ECDSA.

**Status.** Research prototype. The contract is unit-tested and analysed with Slither, but it
is not audited, and liboqs is intended for research and prototyping. Do not use it in production.

## Layout

| Path | Content |
|---|---|
| `contracts/PQCAnchor.sol` | registry (`registerPQKey`, `rotatePQKey`, `revokePQKey`), `anchorCommitment`, `anchorBatchRoot`, `verifyInclusion` / `verifyInclusionTx`, reference encoders |
| `pqc_lib.py` | off-chain client: keygen, keyId, proof of possession, dual sign/verify (AND), commitment C, Merkle tree, ML-KEM + HKDF + AES-GCM |
| `test/PQCAnchor.test.js` | 9 unit tests, incl. byte-for-byte Solidity/Python agreement on real ML-DSA-65/Falcon-512 vectors |
| `scripts/make_test_vectors.py` | Python self-tests (tamper, foreign key, cross-chain replay, PoP, Merkle, KEM) → `test/vectors.json` |
| `scripts/measure_gas.js` | gas from receipts and an opcode trace: Table IX, Table X, on-chain rows of Table XI, Figs. 3–4 |
| `scripts/bench_pqc.py` | per-primitive, dual-signature and ML-KEM-path latencies, 1,000 iterations (Table VII), plus the sizes in Tables III–V |
| `scripts/bench_pipeline.py` | end-to-end signer/verifier pipeline with Hardhat + IPFS, batching, negative tests (Table VIII) |
| `scripts/bench_merkle.py` | off-chain Merkle build/verify against N (off-chain rows of Table XI) |
| `scripts/compute_metrics.py` | security levels (Table I), USD sensitivity (Table XII), QARL/QSM/COE (Table XIII, Eqs. (12)–(14)), thresholds |
| `scripts/make_figures.py` | Figs. 1–5 at 600 dpi |
| `results/` | raw CSVs (per iteration), summaries, environment JSONs, Slither report, unit-test log |
| `figures/` | Figs. 1–5 of the paper |

## Environment used for the reported runs

Intel Core i7-9750H (6 cores / 12 threads, 2.6 GHz base, Turbo Boost on, laptop), 31.9 GB RAM,
Windows 11 Pro 10.0.26200. Software:

- Python 3.10.10, liboqs 0.14.0 + liboqs-python 0.14.1 (`OQS_DIST_BUILD`, MSVC)
- Node 22.9.0, Hardhat 2.29.2 (hardfork `osaka`), solc 0.8.30 (optimizer 200 runs, evm `prague`), OpenZeppelin 5.1.0
- web3.py 7.14.1, Kubo 0.32.1 (Docker), Slither 0.11.3

Benchmarks pin the process to logical core 2 with HIGH priority.

## Reproduce

```bash
# 0. dependencies
npm ci --legacy-peer-deps
```

```bash
pip install -r requirements.txt
```

`liboqs-python` needs the liboqs C library (0.14.0). If it is not found, liboqs-python tries to
download and build it on the first `import oqs`, which needs git, CMake and a C compiler.

```bash
# 1. Python self-tests and cross-language test vectors
python scripts/make_test_vectors.py
```

```bash
# 2. unit tests (9 passing)
npx hardhat test
```

```bash
# optional static analysis (pip install slither-analyzer==0.11.3)
slither . --hardhat-ignore-compile --exclude-dependencies
```

```bash
# 3. Gas: Tables IX-XI and Figs. 3-4 inputs -> results/gas_*.csv
npx hardhat run scripts/measure_gas.js
```

```bash
# 4. PQC latencies: Table VII -> results/pqc_raw.csv, pqc_summary.csv, pqc_env.json
python scripts/bench_pqc.py --iters 1000
```

```bash
# 5. End-to-end pipeline: Table VIII. Needs a local node and IPFS.
npx hardhat node
```

```bash
docker run -d --name pqc-kubo -p 127.0.0.1:5001:5001 -e IPFS_PROFILE=test ipfs/kubo:v0.32.1
```

```bash
python scripts/bench_pipeline.py --iters 1000
```

```bash
# 6. Off-chain Merkle costs: Table XI (off-chain rows)
python scripts/bench_merkle.py
```

```bash
# 7. Derived numbers: Tables I, XII, XIII -> results/metrics.json, security_levels.csv, cost_sensitivity.csv
python scripts/compute_metrics.py
```

```bash
# 8. Figures 1-5 -> figures/*.png (600 dpi)
python scripts/make_figures.py
```

Steps 1, 4, 5 and 6 use fresh random keys and timings, so their output files change at every run.
Steps 2, 3 and 7 are deterministic: the gas values and the derived numbers reproduce exactly
(in `results/gas_batch.csv` only the timing column `js_tree_build_ms` changes).

## Notes

- **Timings are machine-specific.** ML-DSA-65 and ML-KEM-768 run the portable C code in this
  Windows build; Falcon-512 uses its AVX2 code. Hardhat confirmation times (automine) do not
  reflect mainnet block times (12 s slots).
- **The proof of possession** is a pair of PQ signatures over
  `abi.encode("PQC-ETH-REGISTER-v1", account, chainId, contract, keyId)`. It is stored on IPFS with
  the public keys under `pkCID` and checked by every verifier the first time it sees a key.
- **Rotation and revocation** carry `authRef` = keccak256 of a message signed under the *current*
  PQ keys. The contract cannot check it, so verifiers must ignore any rotation or revocation whose
  authorisation does not verify.
- **The Hardhat account #0 private key** used by `bench_pipeline.py` is the publicly known
  development key. Use it on the local chain only.
- **Not run:** Echidna fuzzing and a public testnet (Sepolia) or L2 deployment. The paper
  states this.

## License

MIT, see `LICENSE`.
