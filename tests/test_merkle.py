"""Tests for audit Merkle roots and inclusion proofs."""

import hashlib

import pytest

from audit.merkle import (
    build_merkle_tree,
    get_merkle_root,
    get_proof,
    verify_proof,
)


def _leaf_digest(content: str) -> str:
    """Create a SHA-256 hex leaf digest from test content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def test_changing_any_single_leaf_changes_the_root() -> None:
    """Every leaf contributes to the calculated Merkle root."""
    leaves = [_leaf_digest(f"entry-{index}") for index in range(5)]
    original_root = get_merkle_root(build_merkle_tree(leaves))

    for index in range(len(leaves)):
        changed_leaves = leaves.copy()
        changed_leaves[index] = _leaf_digest(f"changed-entry-{index}")
        assert get_merkle_root(build_merkle_tree(changed_leaves)) != original_root


@pytest.mark.parametrize("leaf_count", [1, 2, 3, 5, 8])
def test_valid_inclusion_proof_verifies_for_every_leaf(leaf_count: int) -> None:
    """Each proof reaches the same root, including odd-sized tree levels."""
    leaves = [_leaf_digest(f"entry-{index}") for index in range(leaf_count)]
    tree = build_merkle_tree(leaves)
    root = get_merkle_root(tree)

    for index, leaf in enumerate(leaves):
        proof = get_proof(tree, index)
        assert verify_proof(leaf, proof, root)


def test_invalid_leaf_proof_root_and_direction_fail() -> None:
    """A changed leaf, sibling, root, or direction cannot validate."""
    leaves = [_leaf_digest(f"entry-{index}") for index in range(4)]
    tree = build_merkle_tree(leaves)
    proof = get_proof(tree, 1)
    root = get_merkle_root(tree)
    changed_sibling = _leaf_digest("unrelated sibling")

    assert not verify_proof(_leaf_digest("different leaf"), proof, root)
    assert not verify_proof(leaves[1], [(changed_sibling, "left"), *proof[1:]], root)
    assert not verify_proof(leaves[1], proof, _leaf_digest("wrong root"))
    assert not verify_proof(leaves[1], [(proof[0][0], "up"), *proof[1:]], root)


def test_empty_tree_and_out_of_range_proof_index_are_rejected() -> None:
    """Empty trees and leaf indices outside the tree are rejected explicitly."""
    with pytest.raises(ValueError):
        build_merkle_tree([])

    tree = build_merkle_tree([_leaf_digest("only leaf")])
    with pytest.raises(IndexError):
        get_proof(tree, 1)


def test_malformed_hex_hash_is_rejected_or_fails_verification() -> None:
    """Tree construction rejects malformed digests and proof checks fail closed."""
    with pytest.raises(ValueError):
        build_merkle_tree(["not-a-sha256-digest"])

    assert not verify_proof("bad leaf", [], _leaf_digest("root"))