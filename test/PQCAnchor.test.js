const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const V = require("./vectors.json");

async function deployFixture() {
  const [owner, other] = await ethers.getSigners();
  const F = await ethers.getContractFactory("PQCAnchor");
  const c = await F.deploy();
  await c.waitForDeployment();
  return { c, owner, other };
}

describe("PQCAnchor", function () {
  let c, owner, other;

  beforeEach(async () => {
    ({ c, owner, other } = await loadFixture(deployFixture));
  });

  it("deploys at the address used by the Python test vectors", async () => {
    expect(await c.getAddress()).to.equal(V.contract);
    expect(owner.address).to.equal(V.account);
  });

  it("encodes keyId and C byte-for-byte like the Python client (real ML-DSA-65/Falcon-512 data)", async () => {
    expect(await c.computeKeyId(V.pk_d, V.pk_f)).to.equal(V.keyId);
    for (const r of V.records) {
      expect(await c.computeCommitment(r.nonce, r.sig_d, r.sig_f, V.keyId, r.msgHash)).to.equal(r.c);
    }
  });

  it("verifies the Python-built Merkle proofs with OpenZeppelin MerkleProof", async () => {
    for (let i = 0; i < V.leaves.length; i++) {
      expect(await c.verifyInclusion(V.leaves[i], V.proofs[i], V.root)).to.equal(true);
    }
    expect(await c.verifyInclusion(V.leaves[0], V.proofs[1], V.root)).to.equal(false);
  });

  it("registers a PQ key once and emits KeyRegistered", async () => {
    await expect(c.registerPQKey(V.keyId, "bafy-pk")).to.emit(c, "KeyRegistered");
    const a = await c.accounts(owner.address);
    expect(a.keyId).to.equal(V.keyId);
    expect(a.registeredBlock).to.be.greaterThan(0n);
    await expect(c.registerPQKey(V.keyId, "x")).to.be.revertedWithCustomError(c, "AlreadyRegistered");
    await expect(c.registerPQKey(ethers.ZeroHash, "x")).to.be.revertedWithCustomError(c, "ZeroValue");
  });

  it("refuses to anchor before registration", async () => {
    await expect(c.anchorCommitment(V.records[0].c, 0, "cid")).to.be.revertedWithCustomError(c, "NotRegistered");
  });

  it("anchors commitments with a strict per-sender nonce and per-sender uniqueness", async () => {
    await c.registerPQKey(V.keyId, "bafy-pk");
    await expect(c.anchorCommitment(V.records[0].c, 1, "cid")).to.be.revertedWithCustomError(c, "BadNonce");
    await expect(c.anchorCommitment(V.records[0].c, 0, "cid"))
      .to.emit(c, "CommitmentAnchored").withArgs(owner.address, V.records[0].c, 0, "cid");
    await expect(c.anchorCommitment(V.records[0].c, 1, "cid")).to.be.revertedWithCustomError(c, "AlreadyAnchored");
    await c.anchorCommitment(V.records[1].c, 1, "cid");
    expect((await c.accounts(owner.address)).nonce).to.equal(2n);
    // front-running copy from another account neither blocks nor impersonates the owner
    await c.connect(other).registerPQKey(ethers.id("attacker"), "evil");
    await c.connect(other).anchorCommitment(V.records[2].c, 0, "evil");
    await c.anchorCommitment(V.records[2].c, 2, "cid");
    const packed = await c.commitments(owner.address, V.records[2].c);
    expect(packed & ((1n << 64n) - 1n)).to.equal(2n);
  });

  it("anchors batch roots and advances the nonce by n", async () => {
    await c.registerPQKey(V.keyId, "bafy-pk");
    await expect(c.anchorBatchRoot(V.root, 5, "manifest"))
      .to.emit(c, "BatchAnchored").withArgs(owner.address, V.root, 0, 5, "manifest");
    const b = await c.batches(owner.address, V.root);
    expect(b.n).to.equal(5n);
    expect((await c.accounts(owner.address)).nonce).to.equal(5n);
    await expect(c.anchorBatchRoot(V.root, 5, "m")).to.be.revertedWithCustomError(c, "AlreadyAnchored");
    await expect(c.anchorBatchRoot(V.root, 0, "m")).to.be.revertedWithCustomError(c, "ZeroValue");
  });

  it("rotates and revokes keys with an authorisation reference", async () => {
    await c.registerPQKey(V.keyId, "bafy-pk");
    const nk = ethers.id("new-key");
    await expect(c.rotatePQKey(nk, "bafy-new", ethers.ZeroHash)).to.be.revertedWithCustomError(c, "ZeroValue");
    await expect(c.rotatePQKey(nk, "bafy-new", ethers.id("auth")))
      .to.emit(c, "KeyRotated").withArgs(owner.address, V.keyId, nk, ethers.id("auth"), "bafy-new");
    await expect(c.revokePQKey(ethers.id("auth2"))).to.emit(c, "KeyRevoked");
    await expect(c.anchorCommitment(V.records[0].c, 0, "cid")).to.be.revertedWithCustomError(c, "KeyIsRevoked");
    await expect(c.rotatePQKey(nk, "x", ethers.id("a"))).to.be.revertedWithCustomError(c, "KeyIsRevoked");
  });

  it("verifyInclusionTx emits the outcome", async () => {
    await expect(c.verifyInclusionTx(V.leaves[3], V.proofs[3], V.root))
      .to.emit(c, "InclusionVerified").withArgs(V.leaves[3], V.root, true);
  });
});
