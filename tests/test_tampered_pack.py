"""Tamper-evidence: editing clause_text must invalidate the Merkle proof."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from pokeupine.crypto import verify_signature
from pokeupine.merkle import leaf_hash, verify_proof
from pokeupine.schemas import Pack


PACK_JSON = (
    Path(__file__).parent.parent / "pokeupine-registry" / "packs" / "pci-dss" / "4.0.0" / "pack.json"
)


def test_tampered_clause_text_breaks_merkle_proof():
    pack_data = json.loads(PACK_JSON.read_text())
    pack = Pack(**pack_data)

    # Baseline: proof + signature verify on the untouched pack.
    c0 = pack.controls[0]
    assert verify_proof(
        leaf_hash(c0.clause_text), c0.provenance.merkle_proof, pack.manifest.merkle_root
    )
    assert verify_signature(pack.manifest.merkle_root_signature, pack.manifest.merkle_root)

    # Tamper: rewrite the first control's clause text.
    bad = copy.deepcopy(pack_data)
    bad["controls"][0]["clause_text"] = "TAMPERED — this clause was rewritten."
    bad_pack = Pack(**bad)

    # Signature is over the merkle_root, which we did NOT touch — still valid.
    assert verify_signature(
        bad_pack.manifest.merkle_root_signature, bad_pack.manifest.merkle_root,
    )
    # But the leaf no longer hashes into the signed root, so the proof must fail.
    bad_c0 = bad_pack.controls[0]
    assert not verify_proof(
        leaf_hash(bad_c0.clause_text),
        bad_c0.provenance.merkle_proof,
        bad_pack.manifest.merkle_root,
    )
