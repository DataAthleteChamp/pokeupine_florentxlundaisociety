"""Tests for Merkle tree construction and verification."""

from pokeupine.merkle import build_tree, leaf_hash, node_hash, verify_proof


def test_leaf_hash_deterministic():
    h1 = leaf_hash("test clause text")
    h2 = leaf_hash("test clause text")
    assert h1 == h2
    assert len(h1) == 64  # sha256 hex


def test_leaf_hash_different_inputs():
    h1 = leaf_hash("clause A")
    h2 = leaf_hash("clause B")
    assert h1 != h2


def test_node_hash_sorted():
    """node_hash should produce same result regardless of argument order."""
    a = leaf_hash("A")
    b = leaf_hash("B")
    assert node_hash(a, b) == node_hash(b, a)


def test_build_tree_single_leaf():
    h = leaf_hash("only clause")
    root, proofs = build_tree([h])
    assert root == h
    assert proofs[h] == []


def test_build_tree_two_leaves():
    h1 = leaf_hash("clause 1")
    h2 = leaf_hash("clause 2")
    root, proofs = build_tree([h1, h2])

    assert root == node_hash(h1, h2)
    assert len(proofs[h1]) == 1
    assert len(proofs[h2]) == 1


def test_build_tree_multiple_leaves():
    leaves = [leaf_hash(f"clause {i}") for i in range(7)]
    root, proofs = build_tree(leaves)

    assert root is not None
    assert len(root) == 64
    assert len(proofs) == 7


def test_verify_proof_round_trip():
    """Build a tree and verify every leaf's proof."""
    clauses = [
        "Sensitive authentication data is not retained after authorization.",
        "PAN rendered unreadable anywhere it is stored.",
        "Strong cryptography for PAN in transit.",
        "Passwords must be at least 12 characters.",
        "Audit logs enabled for all components touching CHD.",
        "Custom code reviewed for injection vulnerabilities.",
    ]
    leaves = [leaf_hash(c) for c in clauses]
    root, proofs = build_tree(leaves)

    for leaf, proof in proofs.items():
        assert verify_proof(leaf, proof, root), f"Proof failed for leaf {leaf[:8]}…"


def test_verify_proof_tampered_fails():
    """Tampered clause should fail verification."""
    clauses = ["clause A", "clause B", "clause C"]
    leaves = [leaf_hash(c) for c in clauses]
    root, proofs = build_tree(leaves)

    # Tamper with a leaf
    tampered_leaf = leaf_hash("clause TAMPERED")
    original_proof = proofs[leaves[0]]

    assert not verify_proof(tampered_leaf, original_proof, root)


def test_verify_proof_wrong_root_fails():
    clauses = ["clause A", "clause B"]
    leaves = [leaf_hash(c) for c in clauses]
    root, proofs = build_tree(leaves)

    wrong_root = "f" * 64
    assert not verify_proof(leaves[0], proofs[leaves[0]], wrong_root)


def test_build_tree_large():
    """Stress test with 50 leaves."""
    leaves = [leaf_hash(f"PCI-DSS clause number {i}") for i in range(50)]
    root, proofs = build_tree(leaves)

    for leaf, proof in proofs.items():
        assert verify_proof(leaf, proof, root)
