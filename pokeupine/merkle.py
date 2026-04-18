"""Merkle tree construction and proof verification.

Layout:
            merkle_root
           /          \\
       page_1   …   page_N
       /  \\           /  \\
   clause clause   clause clause

leaf  = sha256(b"clause:" + clause_text.encode())
node  = sha256(b"node:" + min(left, right) + max(left, right))
proof = list of ("L"|"R", sibling_hash) from leaf → root
"""

from __future__ import annotations

import hashlib
from typing import Literal


def leaf_hash(clause_text: str) -> str:
    """Hash a clause's text to create a Merkle leaf."""
    return hashlib.sha256(b"clause:" + clause_text.encode("utf-8")).hexdigest()


def node_hash(left: str, right: str) -> str:
    """Hash two children into a Merkle node (sorted for determinism)."""
    a, b = sorted([left, right])
    return hashlib.sha256(
        b"node:" + bytes.fromhex(a) + bytes.fromhex(b)
    ).hexdigest()


def build_tree(leaves: list[str]) -> tuple[str, dict[str, list[tuple[Literal["L", "R"], str]]]]:
    """Build a Merkle tree from leaf hashes.

    Returns:
        (root_hash, {leaf_hash: [(side, sibling_hash), ...]})
    """
    if not leaves:
        raise ValueError("Cannot build tree from empty leaf list")

    if len(leaves) == 1:
        return leaves[0], {leaves[0]: []}

    # Track proof paths for each leaf
    proofs: dict[str, list[tuple[Literal["L", "R"], str]]] = {lf: [] for lf in leaves}

    # Map each current hash back to which original leaves it contains
    leaf_membership: dict[str, list[str]] = {lf: [lf] for lf in leaves}

    current_level = list(leaves)

    while len(current_level) > 1:
        next_level: list[str] = []
        next_membership: dict[str, list[str]] = {}

        for i in range(0, len(current_level), 2):
            left = current_level[i]
            # If odd number of nodes, duplicate the last one
            right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]

            parent = node_hash(left, right)
            next_level.append(parent)

            # All leaves under `left` get sibling `right` on the Right
            left_members = leaf_membership[left]
            right_members = leaf_membership[right]

            for lf in left_members:
                proofs[lf].append(("R", right))
            if left != right:
                for lf in right_members:
                    proofs[lf].append(("L", left))

            next_membership[parent] = left_members + (right_members if left != right else [])

        current_level = next_level
        leaf_membership = next_membership

    root = current_level[0]
    return root, proofs


def verify_proof(
    leaf: str,
    proof: list[tuple[Literal["L", "R"] | str, str]],
    expected_root: str,
) -> bool:
    """Verify a Merkle proof from leaf to root.

    Args:
        leaf: The leaf hash to verify
        proof: List of (side, sibling_hash) pairs from leaf to root
        expected_root: The expected root hash

    Returns:
        True if the proof is valid
    """
    current = leaf
    for side, sibling in proof:
        if side == "L":
            current = node_hash(sibling, current)
        else:  # "R"
            current = node_hash(current, sibling)
    return current == expected_root
