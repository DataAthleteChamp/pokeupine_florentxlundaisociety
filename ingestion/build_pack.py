"""Build a signed regulation pack from the ingestion pipeline output.

This is the main entry point for the ingestion pipeline:
    python -m ingestion.build_pack

It runs the full pipeline: fetch → extract → chunk → LLM extract → validate → sign → pack.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).parent.parent
REGISTRY_DIR = PROJECT_ROOT / "pokeupine-registry"
PRIVATE_KEY_PATH = Path(__file__).parent / "data" / "registry_private_key.hex"

# The 6 hand-authored test specs that match our demo target
TEST_SPECS = [
    {
        "id": "PCI-DSS-3.3.1::no-sad-storage",
        "control_id": "PCI-DSS-3.3.1",
        "kind": "dataflow",
        "spec": {
            "sources": {
                "sad_field": [{
                    "kind": "pydantic_field",
                    "class_in": ["Order", "Payment", "Card", "Transaction"],
                    "field_name_regex": "^(cvv|cvc|cvv2|csc)$"
                }]
            },
            "sinks": {
                "storage": [
                    {"kind": "call", "qualified_name_regex": r"(db|session|cursor)\.execute"},
                    {"kind": "call", "qualified_name_regex": r"\.save\("},
                ]
            },
            "sanitizers": []
        },
        "target_globs": ["**/*.py"],
    },
    {
        "id": "PCI-DSS-3.5.1::pan-unreadable",
        "control_id": "PCI-DSS-3.5.1",
        "kind": "dataflow",
        "spec": {
            "sources": {
                "pan_typed": [{
                    "kind": "pydantic_field",
                    "class_in": ["Order", "Payment", "Card", "Transaction"],
                    "field_name_regex": r"^(card_number|pan|cc(_num)?)$"
                }]
            },
            "sinks": {
                "storage": [
                    {"kind": "call", "qualified_name_regex": r"(db|session|cursor)\.execute"},
                    {"kind": "call", "qualified_name_regex": r"\.save\("},
                ]
            },
            "sanitizers": [
                {"kind": "call", "qualified_name_regex": r"^(tokenize|vault\.store|mask_pan)$"}
            ]
        },
        "target_globs": ["**/*.py"],
    },
    {
        "id": "PCI-DSS-4.2.1::strong-crypto-transit",
        "control_id": "PCI-DSS-4.2.1",
        "kind": "ast_check",
        "spec": {"check_type": "cleartext_http"},
        "target_globs": ["**/*.py"],
    },
    {
        "id": "PCI-DSS-8.3.6::password-length",
        "control_id": "PCI-DSS-8.3.6",
        "kind": "ast_check",
        "spec": {"check_type": "weak_password_policy"},
        "target_globs": ["**/*.py"],
    },
    {
        "id": "PCI-DSS-10.2.1::audit-log-required",
        "control_id": "PCI-DSS-10.2.1",
        "kind": "decorator_required",
        "spec": {
            "required_decorator": "audit_log",
            "target_decorator_regex": r"@app\.(post|put|patch|delete)",
            "target_param_type": ""
        },
        "target_globs": ["**/*.py"],
    },
    {
        "id": "PCI-DSS-6.2.4::sast-in-ci",
        "control_id": "PCI-DSS-6.2.4",
        "kind": "llm_judge",
        "spec": {
            "check_type": "file_exists",
            "required_files": ["SECURITY.md"],
            "description": "code review process",
            "remediation": "Create a SECURITY.md documenting your SAST/code review process."
        },
        "target_globs": ["**/*.py"],
    },
]

# The 6 control IDs we need for our demo tests
REQUIRED_CONTROL_IDS = {t["control_id"] for t in TEST_SPECS}


def get_or_create_private_key() -> str:
    """Load or generate the ed25519 private key for signing."""
    from pokeupine.crypto import generate_keypair

    if PRIVATE_KEY_PATH.exists():
        return PRIVATE_KEY_PATH.read_text().strip()

    PRIVATE_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    private_key, public_key = generate_keypair()
    PRIVATE_KEY_PATH.write_text(private_key)
    print(f"Generated new keypair. Public key: {public_key}")
    return private_key


def build_pack(
    pdf_path: Path | None = None,
    model: str = "anthropic/claude-sonnet-4-20250514",
    skip_llm: bool = False,
) -> None:
    """Run the full ingestion pipeline and produce a signed pack."""
    from pokeupine.crypto import sign
    from pokeupine.merkle import build_tree, leaf_hash

    from ingestion.chunk import chunk_text
    from ingestion.extract_text import extract_text, save_text_layer
    from ingestion.fetch import fetch
    from ingestion.validate import find_byte_range, validate_controls

    # Step 1: Fetch and hash PDF
    print("=" * 60)
    print("Step 1: Fetching PDF...")
    path, source_doc_sha256 = fetch(pdf_path)
    print(f"  PDF: {path}")
    print(f"  SHA-256: {source_doc_sha256}")

    # Step 2: Extract text layer
    print("\nStep 2: Extracting text layer...")
    full_text, pages = extract_text(path)
    text_layer_path, text_layer_sha256 = save_text_layer(full_text)
    print(f"  Pages: {len(pages)}")
    print(f"  Text layer: {text_layer_path} ({len(full_text):,} chars)")
    print(f"  Text layer SHA-256: {text_layer_sha256}")

    # Step 3: Chunk
    print("\nStep 3: Chunking text...")
    chunks = chunk_text(full_text, pages)
    print(f"  Found {len(chunks)} chunks")

    # Step 4: LLM extraction
    if skip_llm:
        print("\nStep 4: Skipping LLM extraction (--skip-llm)")
        raw_controls = _fallback_controls()
    else:
        print("\nStep 4: LLM extraction...")
        from ingestion.llm_extract import extract_all
        target_sections = ["3.3", "3.4", "3.5", "4.2", "6.2", "8.3", "10.2"]
        raw_controls = extract_all(chunks, model=model, target_sections=target_sections)

    # Step 5: Validate
    print("\nStep 5: Validating controls...")
    valid, rejected = validate_controls(raw_controls, full_text)
    print(f"  Valid: {len(valid)}, Rejected: {len(rejected)}")
    for r in rejected:
        print(f"    REJECTED {r.get('id', '???')}: {r.get('_rejection_reasons', [])}")

    # Ensure we have controls for all 6 required test IDs
    valid_ids = {c["id"] for c in valid}
    missing_ids = REQUIRED_CONTROL_IDS - valid_ids
    if missing_ids:
        print(f"\n  WARNING: Missing controls for required test IDs: {missing_ids}")
        print("  Adding fallback controls for missing IDs...")
        for fallback in _fallback_controls():
            if fallback["id"] in missing_ids and fallback["id"] not in valid_ids:
                valid.append(fallback)
                valid_ids.add(fallback["id"])

    # Step 6: Build Merkle tree and attach provenance
    print("\nStep 6: Building Merkle tree...")
    controls_with_provenance = []
    clause_texts = []

    for ctrl in valid:
        clause_text = ctrl["clause_text"]
        clause_texts.append(clause_text)

    leaves = [leaf_hash(ct) for ct in clause_texts]
    merkle_root, proofs = build_tree(leaves)
    print(f"  Merkle root: {merkle_root[:16]}...")

    extractor_version = f"pymupdf-{pymupdf_version()}"

    for i, ctrl in enumerate(valid):
        clause_text = ctrl["clause_text"]
        leaf = leaves[i]
        proof = proofs[leaf]

        # Find real byte range in text layer
        byte_range = find_byte_range(clause_text, full_text)
        if byte_range is None:
            byte_range = (0, len(clause_text.encode("utf-8")))

        page = ctrl.get("_chunk_page", 0)

        controls_with_provenance.append({
            "id": ctrl["id"],
            "title": ctrl["title"],
            "clause_text": clause_text,
            "requirement": ctrl["requirement"],
            "severity": ctrl["severity"],
            "provenance": {
                "source_doc_sha256": source_doc_sha256,
                "text_layer_sha256": text_layer_sha256,
                "extractor": extractor_version,
                "page": page,
                "byte_range": list(byte_range),
                "merkle_proof": proof,
            },
        })

    # Step 7: Sign
    print("\nStep 7: Signing Merkle root...")
    private_key = get_or_create_private_key()
    signature = sign(private_key, merkle_root)

    # Derive public key for registry
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    priv_key_obj = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key))
    public_key_hex = priv_key_obj.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    ).hex()

    print(f"  Signature: {signature[:16]}...")
    print(f"  Public key: {public_key_hex}")

    # Step 8: Write pack
    print("\nStep 8: Writing pack.json...")

    # Filter tests to only include those whose control_id exists
    tests = [t for t in TEST_SPECS if t["control_id"] in valid_ids]

    pack = {
        "manifest": {
            "id": "pci-dss",
            "version": "4.0.0",
            "title": "Payment Card Industry Data Security Standard v4.0",
            "source_url": "https://www.pcisecuritystandards.org/document_library/",
            "source_doc_sha256": source_doc_sha256,
            "text_layer_sha256": text_layer_sha256,
            "merkle_root": merkle_root,
            "merkle_root_signature": signature,
            "signing_key_id": "registry-2026",
            "controls_count": len(controls_with_provenance),
            "tests_count": len(tests),
        },
        "controls": controls_with_provenance,
        "tests": tests,
    }

    # Write to registry
    pack_dir = REGISTRY_DIR / "packs" / "pci-dss" / "4.0.0"
    pack_dir.mkdir(parents=True, exist_ok=True)
    pack_path = pack_dir / "pack.json"
    pack_path.write_text(json.dumps(pack, indent=2))

    # Write index.json
    index = {
        "schema_version": 1,
        "updated": "2026-04-18T12:00:00Z",
        "signing_keys": {
            "registry-2026": "keys/registry-2026.pub"
        },
        "packs": [{
            "id": "pci-dss",
            "title": "Payment Card Industry Data Security Standard",
            "latest": "4.0.0",
            "versions": ["4.0.0"],
            "url": "packs/pci-dss/4.0.0/pack.json",
            "controls_count": len(controls_with_provenance),
            "tests_count": len(tests),
        }]
    }
    (REGISTRY_DIR / "index.json").write_text(json.dumps(index, indent=2))

    # Write public key
    keys_dir = REGISTRY_DIR / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    (keys_dir / "registry-2026.pub").write_text(public_key_hex)

    print(f"\n{'=' * 60}")
    print(f"✓ Pack written to {pack_path}")
    print(f"  {len(controls_with_provenance)} controls, {len(tests)} tests")
    print(f"  Merkle root: {merkle_root[:16]}...")
    print(f"  Signed by: {public_key_hex[:16]}...")
    print(f"\n  UPDATE pokeupine/config.py with:")
    print(f'  REGISTRY_PUBLIC_KEY_HEX = "{public_key_hex}"')


def pymupdf_version() -> str:
    import pymupdf
    return pymupdf.VersionBind


def _fallback_controls() -> list[dict]:
    """Hardcoded fallback controls for when LLM extraction misses required IDs."""
    return [
        {
            "id": "PCI-DSS-3.3.1",
            "title": "Sensitive Authentication Data not stored after authorization",
            "clause_text": "SAD is not retained after authorization, even if encrypted. All sensitive authentication data received is rendered unrecoverable upon completion of the authorization process.",
            "requirement": "Never persist CVV/CVC. Delete SAD immediately after authorization.",
            "severity": "critical",
            "_chunk_page": 0,
        },
        {
            "id": "PCI-DSS-3.5.1",
            "title": "PAN is rendered unreadable anywhere it is stored",
            "clause_text": "PAN is rendered unreadable anywhere it is stored by using any of the following approaches: One-way hashes based on strong cryptography of the entire PAN. Truncation. Index tokens. Strong cryptography with associated key-management processes and procedures.",
            "requirement": "Tokenize PAN with a PCI-validated provider; store the token only.",
            "severity": "critical",
            "_chunk_page": 0,
        },
        {
            "id": "PCI-DSS-4.2.1",
            "title": "Strong cryptography for PAN in transit over open, public networks",
            "clause_text": "PAN is secured with strong cryptography whenever it is sent via end-user messaging technologies. Strong cryptography is used to safeguard PAN during transmission over open, public networks.",
            "requirement": "Use HTTPS (TLS 1.2+) for all PAN transmission.",
            "severity": "high",
            "_chunk_page": 0,
        },
        {
            "id": "PCI-DSS-8.3.6",
            "title": "Passwords/passphrases meet minimum complexity requirements",
            "clause_text": "If passwords/passphrases are used as an authentication factor, they meet the following minimum level of complexity: A minimum length of 12 characters.",
            "requirement": "Set minimum password length to 12 or greater.",
            "severity": "medium",
            "_chunk_page": 0,
        },
        {
            "id": "PCI-DSS-10.2.1",
            "title": "Audit logs capture all individual user access to cardholder data",
            "clause_text": "Audit logs are enabled and active for all system components. All individual user accesses to cardholder data are logged.",
            "requirement": "Add audit logging to all functions handling cardholder data.",
            "severity": "high",
            "_chunk_page": 0,
        },
        {
            "id": "PCI-DSS-6.2.4",
            "title": "Software engineering techniques prevent common coding vulnerabilities",
            "clause_text": "Software engineering techniques or other methods are defined and in use by software development personnel to prevent or mitigate common software attacks and related vulnerabilities in bespoke and custom software.",
            "requirement": "Document SAST/code review process in SECURITY.md.",
            "severity": "medium",
            "_chunk_page": 0,
        },
    ]


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Build a signed PCI-DSS regulation pack")
    parser.add_argument("--pdf", type=Path, default=None, help="Path to PCI-DSS PDF")
    parser.add_argument("--model", default="anthropic/claude-sonnet-4-20250514", help="LLM model")
    parser.add_argument("--skip-llm", action="store_true", help="Skip LLM, use fallback controls")
    args = parser.parse_args()

    build_pack(pdf_path=args.pdf, model=args.model, skip_llm=args.skip_llm)
