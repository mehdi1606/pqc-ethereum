// Measures gasUsed from transaction receipts on the Hardhat in-process network
// (hardfork "osaka" = current mainnet gas schedule incl. EIP-2929, EIP-3529, EIP-7623)
// and decomposes one anchorCommitment transaction from its opcode trace.
// Output: results/gas_*.csv           Run: npx hardhat run scripts/measure_gas.js
const fs = require("fs");
const path = require("path");
const { ethers, network } = require("hardhat");
const V = require("../test/vectors.json");

const OUT = path.join(__dirname, "..", "results");
fs.mkdirSync(OUT, { recursive: true });
const CID = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"; // 59-char CIDv1 (length only matters)

function csv(name, header, rows) {
  fs.writeFileSync(path.join(OUT, name), [header.join(","), ...rows.map((r) => r.join(","))].join("\n") + "\n");
  console.log("wrote", name, rows.length, "rows");
}

function calldataStats(hex) {
  const b = ethers.getBytes(hex);
  let z = 0;
  for (const x of b) if (x === 0) z++;
  const nz = b.length - z;
  const standard = 21000 + 4 * z + 16 * nz;           // pre-Pectra intrinsic for a plain call
  const floor = 21000 + 10 * (z + 4 * nz);            // EIP-7623 floor
  return { len: b.length, z, nz, standard, floor };
}

// --- tiny Merkle tree identical to pqc_lib.merkle_build (sorted-pair keccak, odd node promoted)
const hp = (a, b) => (a.toLowerCase() < b.toLowerCase() ? ethers.keccak256(ethers.concat([a, b])) : ethers.keccak256(ethers.concat([b, a])));
const leafHash = (c) => ethers.keccak256(ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["bytes32"], [c])));
function build(leaves) {
  const L = [leaves];
  while (L[L.length - 1].length > 1) {
    const cur = L[L.length - 1], nx = [];
    for (let i = 0; i < cur.length; i += 2) nx.push(i + 1 < cur.length ? hp(cur[i], cur[i + 1]) : cur[i]);
    L.push(nx);
  }
  return L;
}
function proof(L, idx) {
  const p = [];
  for (const lvl of L.slice(0, -1)) { const s = idx ^ 1; if (s < lvl.length) p.push(lvl[s]); idx = Math.floor(idx / 2); }
  return p;
}

async function rcpt(txp) { const tx = await txp; return await tx.wait(); }

async function main() {
  const [owner, , , recipient] = await ethers.getSigners();
  const F = await ethers.getContractFactory("PQCAnchor");
  const c = await F.deploy();
  const dep = await c.deploymentTransaction().wait();
  const addr = await c.getAddress();
  const ops = [];
  ops.push(["deploy", dep.gasUsed.toString(), calldataStats(c.deploymentTransaction().data).len, ""]);

  const r1 = await rcpt(c.registerPQKey(V.keyId, CID));
  ops.push(["registerPQKey", r1.gasUsed.toString(), calldataStats((await c.registerPQKey.populateTransaction(V.keyId, CID)).data).len, "first registration (two cold zero->nonzero slots)"]);

  const anchorTx = [];
  for (let i = 0; i < 5; i++) {
    const C = ethers.id("commitment-" + i);
    const r = await rcpt(c.anchorCommitment(C, i, CID));
    anchorTx.push(r);
    ops.push([`anchorCommitment_${i === 0 ? "first" : "next" + i}`, r.gasUsed.toString(),
      calldataStats((await c.anchorCommitment.populateTransaction(C, i, CID)).data).len, `nonce=${i}`]);
  }
  const nk = ethers.id("rotated-key");
  const rr = await rcpt(c.rotatePQKey(nk, CID, ethers.id("auth-ref")));
  ops.push(["rotatePQKey", rr.gasUsed.toString(), "", ""]);

  // ---- batches: separate fresh account per run so the nonce slot state is comparable
  const signers = await ethers.getSigners();
  const batchRows = [], inclRows = [];
  const Ns = [1, 10, 100, 1000, 10000];
  for (let k = 0; k < Ns.length; k++) {
    const N = Ns[k];
    const s = signers[5 + k];
    await rcpt(c.connect(s).registerPQKey(ethers.id("key-" + N), CID));
    const leaves = Array.from({ length: N }, (_, i) => leafHash(ethers.id(`batch-${N}-rec-${i}`)));
    const t0 = process.hrtime.bigint();
    const L = build(leaves);
    const buildMs = Number(process.hrtime.bigint() - t0) / 1e6;
    const root = L[L.length - 1][0];
    const rb = await rcpt(c.connect(s).anchorBatchRoot(root, N, CID));
    // inclusion proofs: worst-case (longest) proof for this tree
    let worst = 0, worstLen = -1;
    for (const idx of [0, N - 1, Math.floor(N / 2)]) { const l = proof(L, idx).length; if (l > worstLen) { worstLen = l; worst = idx; } }
    const pr = proof(L, worst);
    const ok = await c.verifyInclusion(leaves[worst], pr, root);
    if (!ok) throw new Error("inclusion failed for N=" + N);
    const ri = await rcpt(c.verifyInclusionTx(leaves[worst], pr, root));
    const inclCd = calldataStats((await c.verifyInclusionTx.populateTransaction(leaves[worst], pr, root)).data);
    const viewGas = await c.verifyInclusion.estimateGas(leaves[worst], pr, root);
    batchRows.push([N, rb.gasUsed.toString(), (Number(rb.gasUsed) / N).toFixed(2), buildMs.toFixed(3)]);
    inclRows.push([N, pr.length, 32 * pr.length, ri.gasUsed.toString(), viewGas.toString(), inclCd.len]);
  }

  // ---- calldata cost of putting PQ material on-chain (plain EOA transfer carrying data)
  const sd = V.records[0].sig_d, sf = V.records[0].sig_f;
  const items = {
    "ML-DSA-65 sig": sd,
    "ML-DSA-65 sig+pk": ethers.concat([sd, V.pk_d]),
    "Falcon-512 sig": sf,
    "Falcon-512 sig+pk": ethers.concat([sf, V.pk_f]),
    "Both sigs": ethers.concat([sd, sf]),
    "Both sigs+pks": ethers.concat([sd, V.pk_d, sf, V.pk_f]),
    "Commitment only (32 B)": V.records[0].c,
  };
  const cdRows = [];
  for (const [k, data] of Object.entries(items)) {
    const r = await rcpt(owner.sendTransaction({ to: recipient.address, data, value: 0 }));
    const st = calldataStats(data);
    cdRows.push([`"${k}"`, st.len, st.z, st.nz, st.standard, st.floor, r.gasUsed.toString(), r.gasUsed.toString() === String(Math.max(st.standard, st.floor)) ? "yes" : "no"]);
  }

  // ---- opcode trace of a steady-state anchorCommitment (the 2nd one)
  const tgt = anchorTx[1];
  const trace = await network.provider.send("debug_traceTransaction", [tgt.hash, { disableStack: true, disableMemory: true, disableStorage: true }]);
  const cat = {};
  let exec = 0;
  for (const s of trace.structLogs) {
    if (s.depth !== 1) continue;
    let k;
    if (s.op === "SSTORE") k = "SSTORE";
    else if (s.op === "SLOAD") k = "SLOAD";
    else if (s.op.startsWith("LOG")) k = s.op;
    else if (s.op === "KECCAK256" || s.op === "SHA3") k = "KECCAK256";
    else k = "other opcodes (stack/memory/control/calldata)";
    cat[k] = (cat[k] || 0) + s.gasCost;
    exec += s.gasCost;
  }
  const txd = (await ethers.provider.getTransaction(tgt.hash)).data;
  const st = calldataStats(txd);
  const intrinsicCd = st.standard - 21000;
  const traceRows = [["base transaction (intrinsic 21000)", 21000], [`calldata (${st.len} B: ${st.z} zero x4 + ${st.nz} non-zero x16)`, intrinsicCd]];
  for (const [k, v] of Object.entries(cat)) traceRows.push([k, v]);
  const sum = traceRows.reduce((a, r) => a + r[1], 0);
  traceRows.push(["SUM of components", sum]);
  traceRows.push(["gasUsed (receipt)", Number(tgt.gasUsed)]);
  traceRows.push(["EIP-7623 floor for this calldata", st.floor]);
  // per-SSTORE detail
  const ss = trace.structLogs.filter((s) => s.depth === 1 && s.op === "SSTORE").map((s) => s.gasCost);
  const sl = trace.structLogs.filter((s) => s.depth === 1 && s.op === "SLOAD").map((s) => s.gasCost);

  csv("gas_operations.csv", ["operation", "gasUsed", "calldata_bytes", "note"], ops);
  csv("gas_batch.csv", ["N", "anchorBatchRoot_gasUsed", "gas_per_record", "js_tree_build_ms"], batchRows);
  csv("gas_inclusion.csv", ["N", "proof_len", "proof_bytes", "verifyInclusionTx_gasUsed", "verifyInclusion_view_estimateGas", "calldata_bytes"], inclRows);
  csv("gas_calldata.csv", ["payload", "bytes", "zero_bytes", "nonzero_bytes", "standard_cost", "eip7623_floor", "measured_gasUsed", "measured_equals_max"], cdRows);
  csv("gas_trace_anchor.csv", ["component", "gas"], traceRows.map((r) => [`"${r[0]}"`, r[1]]));
  fs.writeFileSync(path.join(OUT, "gas_trace_anchor_sstore_sload.txt"),
    `tx ${tgt.hash}\nSSTORE costs: ${ss.join(", ")}\nSLOAD costs: ${sl.join(", ")}\nrefund: ${trace.gas !== undefined ? "" : ""}\n`);
  fs.writeFileSync(path.join(OUT, "gas_env.json"), JSON.stringify({
    hardhat: require("hardhat/package.json").version, hardfork: network.config.hardfork,
    solc: "0.8.30", optimizer_runs: 200, evmVersion: "prague", openzeppelin: require("@openzeppelin/contracts/package.json").version,
    contract: addr, node: process.version, date: new Date().toISOString(),
  }, null, 1));
}

main().catch((e) => { console.error(e); process.exit(1); });
