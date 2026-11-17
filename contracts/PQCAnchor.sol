// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/**
 * @title PQCAnchor
 * @notice On-chain half of the hybrid PQC/Ethereum anchoring scheme (JASTT R1).
 *
 * The contract never verifies a post-quantum signature. It is
 *   (i)  a registry binding an Ethereum account to a post-quantum key identifier
 *        keyId = keccak256(abi.encode(pk_D, pk_F)) (ML-DSA-65 || Falcon-512), and
 *   (ii) an append-only log of 32-byte commitments
 *        C = keccak256(abi.encode(DST, chainId, address(this), nonce,
 *                                 sig_D, sig_F, keyId, keccak256(m)))
 *        or of Merkle roots over batches of such commitments.
 *
 * Off-chain verifiers (liboqs) check both PQ signatures, recompute C, and
 * accept a record only if its keyId equals the keyId registered for the
 * anchoring account at a block strictly before the anchoring block, following
 * the chain of KeyRotated events whose PQ authorisation verifies.
 *
 * Rotation and revocation carry a bytes32 `authRef` = keccak256 of an
 * authorisation message signed with BOTH currently registered PQ keys; the
 * signatures themselves are published off-chain (IPFS, CID in the event).
 * The contract cannot check them, so verifiers MUST ignore any rotation or
 * revocation whose authorisation does not verify under the previous keyId.
 * After "Q-day" an attacker who forges the account's ECDSA signature can
 * therefore disturb liveness (e.g. revoke) but cannot make verifiers accept a
 * key or a record that the legitimate PQ key holder did not sign.
 */
contract PQCAnchor {
    // ------------------------------------------------------------------ types
    struct Account {
        bytes32 keyId;          // slot 0
        uint64 registeredBlock; // slot 1 (packed)
        uint64 registeredAt;    //        (unix time)
        uint64 nonce;           //        next expected record nonce
        uint64 revokedBlock;    //        0 = active
    }

    struct Batch {
        uint64 blockNumber; // packed into one slot
        uint64 firstNonce;
        uint64 n;
    }

    // ---------------------------------------------------------------- storage
    mapping(address => Account) public accounts;
    /// sender => commitment => (blockNumber, nonce) packed as blockNumber<<64 | nonce
    mapping(address => mapping(bytes32 => uint128)) public commitments;
    /// sender => Merkle root => batch metadata
    mapping(address => mapping(bytes32 => Batch)) public batches;

    // ----------------------------------------------------------------- events
    event KeyRegistered(address indexed account, bytes32 indexed keyId, string pkCID, uint64 blockNumber, uint64 timestamp);
    event KeyRotated(address indexed account, bytes32 indexed oldKeyId, bytes32 indexed newKeyId, bytes32 authRef, string pkCID);
    event KeyRevoked(address indexed account, bytes32 indexed keyId, bytes32 authRef);
    event CommitmentAnchored(address indexed sender, bytes32 indexed commitment, uint64 nonce, string cid);
    event BatchAnchored(address indexed sender, bytes32 indexed root, uint64 firstNonce, uint64 n, string manifestCID);
    event InclusionVerified(bytes32 indexed leaf, bytes32 indexed root, bool ok);

    // ----------------------------------------------------------------- errors
    error AlreadyRegistered();
    error NotRegistered();
    error KeyIsRevoked();
    error ZeroValue();
    error BadNonce(uint64 expected, uint64 given);
    error AlreadyAnchored();

    // ------------------------------------------------------------ constants
    string public constant DST = "PQC-ETH-ANCHOR-v1";

    // =============================================================== registry

    /// @notice One-off binding of msg.sender to a PQ key identifier. Authorised by
    ///         the transaction's ECDSA signature; the proof of possession (both PQ
    ///         signatures over abi.encode("PQC-ETH-REGISTER-v1", account, chainId,
    ///         address(this), keyId)) is stored with the public keys under pkCID.
    function registerPQKey(bytes32 keyId, string calldata pkCID) external {
        if (keyId == bytes32(0)) revert ZeroValue();
        Account storage a = accounts[msg.sender];
        if (a.keyId != bytes32(0)) revert AlreadyRegistered();
        a.keyId = keyId;
        a.registeredBlock = uint64(block.number);
        a.registeredAt = uint64(block.timestamp);
        emit KeyRegistered(msg.sender, keyId, pkCID, uint64(block.number), uint64(block.timestamp));
    }

    /// @notice Replace the registered keyId. `authRef` = keccak256 of the rotation
    ///         message signed under the CURRENT PQ keys (checked off-chain).
    function rotatePQKey(bytes32 newKeyId, string calldata pkCID, bytes32 authRef) external {
        if (newKeyId == bytes32(0) || authRef == bytes32(0)) revert ZeroValue();
        Account storage a = accounts[msg.sender];
        bytes32 old = a.keyId;
        if (old == bytes32(0)) revert NotRegistered();
        if (a.revokedBlock != 0) revert KeyIsRevoked();
        a.keyId = newKeyId;
        a.registeredBlock = uint64(block.number);
        a.registeredAt = uint64(block.timestamp);
        emit KeyRotated(msg.sender, old, newKeyId, authRef, pkCID);
    }

    /// @notice Mark the registered key as revoked. `authRef` as for rotation.
    function revokePQKey(bytes32 authRef) external {
        if (authRef == bytes32(0)) revert ZeroValue();
        Account storage a = accounts[msg.sender];
        if (a.keyId == bytes32(0)) revert NotRegistered();
        if (a.revokedBlock != 0) revert KeyIsRevoked();
        a.revokedBlock = uint64(block.number);
        emit KeyRevoked(msg.sender, a.keyId, authRef);
    }

    // ============================================================== anchoring

    /// @notice Anchor one commitment C whose preimage uses `nonce`, which must be
    ///         the sender's next nonce. Uniqueness is per sender, so copying
    ///         someone else's C from another account cannot block the owner.
    function anchorCommitment(bytes32 c, uint64 nonce, string calldata cid) external {
        if (c == bytes32(0)) revert ZeroValue();
        Account storage a = accounts[msg.sender];
        if (a.keyId == bytes32(0)) revert NotRegistered();
        if (a.revokedBlock != 0) revert KeyIsRevoked();
        if (nonce != a.nonce) revert BadNonce(a.nonce, nonce);
        if (commitments[msg.sender][c] != 0) revert AlreadyAnchored();
        commitments[msg.sender][c] = (uint128(block.number) << 64) | uint128(nonce);
        unchecked { a.nonce = nonce + 1; }
        emit CommitmentAnchored(msg.sender, c, nonce, cid);
    }

    /// @notice Anchor the Merkle root of n commitments whose nonces are
    ///         firstNonce .. firstNonce + n - 1 (firstNonce = sender's next nonce).
    ///         The manifest (ordered list of leaves, record CIDs) is at manifestCID.
    function anchorBatchRoot(bytes32 root, uint64 n, string calldata manifestCID) external {
        if (root == bytes32(0) || n == 0) revert ZeroValue();
        Account storage a = accounts[msg.sender];
        if (a.keyId == bytes32(0)) revert NotRegistered();
        if (a.revokedBlock != 0) revert KeyIsRevoked();
        if (batches[msg.sender][root].blockNumber != 0) revert AlreadyAnchored();
        uint64 first = a.nonce;
        batches[msg.sender][root] = Batch(uint64(block.number), first, n);
        unchecked { a.nonce = first + n; }
        emit BatchAnchored(msg.sender, root, first, n, manifestCID);
    }

    // ========================================================== verification

    /// @notice OpenZeppelin MerkleProof (sorted-pair keccak256) inclusion check.
    function verifyInclusion(bytes32 leaf, bytes32[] calldata proof, bytes32 root) public pure returns (bool) {
        return MerkleProof.verifyCalldata(proof, root, leaf);
    }

    /// @notice Same check executed in a transaction so that its gas can be
    ///         measured from the receipt; emits the outcome.
    function verifyInclusionTx(bytes32 leaf, bytes32[] calldata proof, bytes32 root) external returns (bool ok) {
        ok = MerkleProof.verifyCalldata(proof, root, leaf);
        emit InclusionVerified(leaf, root, ok);
    }

    /// @notice Reference implementation of the commitment encoding (D2), used by
    ///         the test-suite to check byte-for-byte agreement with the Python client.
    function computeCommitment(
        uint64 nonce,
        bytes calldata sigD,
        bytes calldata sigF,
        bytes32 keyId,
        bytes32 msgHash
    ) external view returns (bytes32) {
        return keccak256(abi.encode(DST, block.chainid, address(this), nonce, sigD, sigF, keyId, msgHash));
    }

    /// @notice keyId = keccak256(abi.encode(pk_D, pk_F)).
    function computeKeyId(bytes calldata pkD, bytes calldata pkF) external pure returns (bytes32) {
        return keccak256(abi.encode(pkD, pkF));
    }
}
