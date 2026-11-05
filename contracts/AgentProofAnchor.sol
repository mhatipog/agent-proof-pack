// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal Ethereum-compatible log of externally signed Merkle roots.
/// @dev This contract does NOT enforce the off-chain AI policy or prove log completeness.
///      Each publisher gets an independent stream namespace. No customer data is stored.
contract AgentProofAnchor {
    struct Head {
        uint64 epoch;
        bytes32 anchor;
    }

    mapping(bytes32 => Head) public heads;

    event CheckpointAnchored(
        address indexed publisher,
        bytes32 indexed streamKey,
        uint64 indexed epoch,
        bytes32 root,
        bytes32 predecessor,
        bytes32 anchor
    );

    error WrongEpoch();
    error WrongPredecessor();
    error EmptyRoot();

    /// @param streamId Public hash of an off-chain stream identifier (not a private name).
    /// @param epoch Monotone per-publisher/per-stream epoch starting at one.
    /// @param root SHA-256 Merkle root computed and signed by an independent witness.
    /// @param predecessor Anchor emitted by this contract for the preceding epoch.
    function anchor(bytes32 streamId, uint64 epoch, bytes32 root, bytes32 predecessor)
        external returns (bytes32 nextAnchor)
    {
        if (root == bytes32(0)) revert EmptyRoot();
        bytes32 streamKey = keccak256(abi.encode(msg.sender, streamId));
        Head storage head = heads[streamKey];
        if (uint256(epoch) != uint256(head.epoch) + 1) revert WrongEpoch();
        if (predecessor != head.anchor) revert WrongPredecessor();

        nextAnchor = keccak256(
            abi.encode(block.chainid, address(this), streamKey, epoch, root, predecessor)
        );
        head.epoch = epoch;
        head.anchor = nextAnchor;
        emit CheckpointAnchored(msg.sender, streamKey, epoch, root, predecessor, nextAnchor);
    }
}
