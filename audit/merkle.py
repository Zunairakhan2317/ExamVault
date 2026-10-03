"""Binary Merkle trees and inclusion proofs for SHA-256 audit digests."""

import hashlib
import re
from collections.abc import Sequence

_HASH_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


def _normalize_hash(value: str) -> str:
    """Validate and normalize a 32-byte hexadecimal digest."""
    if not isinstance(value, str) or _HASH_PATTERN.fullmatch(value) is None:
        raise ValueError("Merkle hashes must be 64-character SHA-256 hex strings")
    return value.lower()


def _hash_pair(left: str, right: str) -> str:
    """Hash two child digests together in left-to-right order."""
    return hashlib.sha256(bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def build_merkle_tree(leaves: list[str]) -> list[list[str]]:
    """Build leaf-to-root Merkle levels from precomputed SHA-256 hex digests."""
    if not isinstance(leaves, list) or not leaves:
        raise ValueError("At least one Merkle leaf is required")

    levels = [[_normalize_hash(leaf) for leaf in leaves]]
    while len(levels[-1]) > 1:
        current_level = levels[-1]
        parent_level = [
            _hash_pair(
                current_level[index],
                current_level[index + 1]
                if index + 1 < len(current_level)
                else current_level[index],
            )
            for index in range(0, len(current_level), 2)
        ]
        levels.append(parent_level)
    return levels


def get_merkle_root(tree: list[list[str]]) -> str:
    """Return the root digest from a non-empty leaf-to-root Merkle tree."""
    if not isinstance(tree, list) or not tree or not isinstance(tree[-1], list) or len(tree[-1]) != 1:
        raise ValueError("tree must be a non-empty Merkle tree with one root")
    return _normalize_hash(tree[-1][0])


def get_proof(tree: list[list[str]], index: int) -> list[tuple[str, str]]:
    """Return sibling digests and their positions for a leaf inclusion proof."""
    if not isinstance(tree, list) or not tree or not isinstance(tree[0], list):
        raise ValueError("tree must contain a leaf level")
    if not isinstance(index, int) or isinstance(index, bool):
        raise ValueError("index must be an integer")
    if not 0 <= index < len(tree[0]):
        raise IndexError("leaf index is outside the Merkle tree")

    proof: list[tuple[str, str]] = []
    position = index
    for level in tree[:-1]:
        if position % 2:
            sibling_index = position - 1
            direction = "left"
        else:
            sibling_index = position + 1
            direction = "right"
            if sibling_index >= len(level):
                sibling_index = position
        proof.append((_normalize_hash(level[sibling_index]), direction))
        position //= 2
    return proof


def verify_proof(
    leaf: str,
    proof: Sequence[tuple[str, str]],
    root: str,
) -> bool:
    """Verify a leaf's inclusion path against the claimed Merkle root."""
    try:
        calculated = _normalize_hash(leaf)
        expected_root = _normalize_hash(root)
        if not isinstance(proof, (list, tuple)):
            return False
        for item in proof:
            if not isinstance(item, tuple) or len(item) != 2:
                return False
            sibling, direction = item
            sibling_hash = _normalize_hash(sibling)
            if direction == "left":
                calculated = _hash_pair(sibling_hash, calculated)
            elif direction == "right":
                calculated = _hash_pair(calculated, sibling_hash)
            else:
                return False
        return calculated == expected_root
    except (TypeError, ValueError):
        return False