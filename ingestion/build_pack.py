"""Build a signed regulation pack from a RegulationProfile.

Usage:
    python -m ingestion.build_pack --profile pci-dss
    python -m ingestion.build_pack --profile gdpr --skip-llm
    python -m ingestion.build_pack --profile path/to/custom.json --pdf override.pdf

The same pipeline (fetch -> extract -> chunk -> LLM extract -> validate -> sign -> pack)
serves any regulation. Regulation-specific knowledge lives only in the profile JSON.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from ingestion.profile import RegulationProfile

load_dotenv()

PROJECT_ROOT = Path(__file__).parent.parent
REGISTRY_DIR = PROJECT_ROOT / "pokeupine-registry"
PRIVATE_KEY_PATH = Path(__file__).parent / "data" / "registry_private_key.hex"


def get_or_create_private_key() -> str:
    from pokeupine.crypto import generate_keypair

    if PRIVATE_KEY_PATH.exists():
        return PRIVATE_KEY_PATH.read_text().strip()

    PRIVATE_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    private_key, public_key = generate_keypair()
    PRIVATE_KEY_PATH.write_text(private_key)
    print(f"Generated new keypair. Public key: {public_key}")
    return private_key


def pymupdf_version() -> str:
    import pymupdf
    return pymupdf.VersionBind


def _update_index(
    profile: RegulationProfile,
    controls_count: int,
    tests_count: int,
) -> None:
    index_path = REGISTRY_DIR / "index.json"

    if index_path.exists():
        index = json.loads(index_path.read_text())
    else:
        index = {
            "schema_version": 1,
            "updated": "",
            "signing_keys": {},
            "packs": [],
        }

    index["updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    index.setdefault("signing_keys", {})["registry-2026"] = "keys/registry-2026.pub"

    packs: list[dict] = index.setdefault("packs", [])
    new_entry = {
        "id": profile.pack_id,
        "title": profile.pack_title,
        "latest": profile.pack_version,
        "versions": [profile.pack_version],
        "url": f"{profile.registry_path}/pack.json",
        "controls_count": controls_count,
        "tests_count": tests_count,
    }

    replaced = False
    for i, p in enumerate(packs):
        if p.get("id") == profile.pack_id:
            existing_versions = set(p.get("versions", []))
            existing_versions.add(profile.pack_version)
            new_entry["versions"] = sorted(existing_versions)
            packs[i] = new_entry
            replaced = True
            break
    if not replaced:
        packs.append(new_entry)

    packs.sort(key=lambda p: p.get("id", ""))
    index_path.write_text(json.dumps(index, indent=2))


def build_pack(
    profile: RegulationProfile,
    model: str = "anthropic/claude-sonnet-4-20250514",
    skip_llm: bool = False,
) -> None:
    from pokeupine.crypto import sign
    from pokeupine.merkle import build_tree, leaf_hash

    from ingestion.chunk import chunk_text
    from ingestion.extract_text import extract_text, save_text_layer
    from ingestion.fetch import fetch
    from ingestion.llm_extract import extract_all
    from ingestion.validate import find_byte_range, validate_controls

    print("=" * 60)
    print(f"Building pack for: {profile.pack_id} {profile.pack_version}")
    print(f"Profile PDF:       {profile.pdf_path}")
    print("=" * 60)
    print("\nStep 1: Fetching PDF...")
    path, source_doc_sha256 = fetch(profile.pdf_path)
    print(f"  PDF: {path}")
    print(f"  SHA-256: {source_doc_sha256}")

    print("\nStep 2: Extracting text layer...")
    full_text, pages = extract_text(path)
    text_layer_path, text_layer_sha256 = save_text_layer(full_text)
    print(f"  Pages: {len(pages)}")
    print(f"  Text layer: {text_layer_path} ({len(full_text):,} chars)")
    print(f"  Text layer SHA-256: {text_layer_sha256}")

    print("\nStep 3: Chunking text...")
    chunks = chunk_text(full_text, pages, profile.compile_heading_re())
    print(f"  Found {len(chunks)} chunks")

    if skip_llm:
        print("\nStep 4: Skipping LLM extraction (--skip-llm)")
        # Replace each fallback's clause_text with verbatim text from the
        # matching chunk in the PDF. Maps article/section number -> chunk.
        # The id_template tells us how to derive a heading token from an id:
        # e.g. "GDPR-ART-32" -> "32", "PCI-DSS-3.5.1" -> "3.5.1".
        id_prefix = profile.id_template.split("{heading}")[0]
        chunk_by_heading = {c.heading: c for c in chunks}
        raw_controls = []
        for fb in profile.fallback_controls:
            ctrl = dict(fb)
            heading_token = ctrl["id"].removeprefix(id_prefix)
            chunk = chunk_by_heading.get(heading_token)
            if chunk is not None:
                # Take a self-contained slice of the chunk as clause_text.
                # Use first ~600 chars or up to first sub-paragraph break.
                slice_text = chunk.text[:600].rstrip()
                ctrl["clause_text"] = slice_text
                ctrl["_chunk_page"] = chunk.page
                print(f"  {ctrl['id']}: extracted {len(slice_text)} chars from chunk on page {chunk.page}")
            else:
                print(f"  {ctrl['id']}: WARNING - no chunk found for heading '{heading_token}', keeping hand-authored clause")
            raw_controls.append(ctrl)
    else:
        print("\nStep 4: LLM extraction...")
        raw_controls = extract_all(chunks, profile=profile, model=model)

    print("\nStep 5: Validating controls...")
    valid, rejected = validate_controls(
        raw_controls, full_text, id_pattern=profile.compile_id_re()
    )
    print(f"  Valid: {len(valid)}, Rejected: {len(rejected)}")
    for r in rejected:
        print(f"    REJECTED {r.get('id', '???')}: {r.get('_rejection_reasons', [])}")

    valid_ids = {c["id"] for c in valid}
    required_ids = profile.required_control_ids()
    missing_ids = required_ids - valid_ids
    if missing_ids:
        print(f"\n  WARNING: Missing controls for required test IDs: {missing_ids}")
        print("  Adding fallback controls for missing IDs...")
        for fallback in profile.fallback_controls:
            if fallback["id"] in missing_ids and fallback["id"] not in valid_ids:
                valid.append(dict(fallback))
                valid_ids.add(fallback["id"])

    print("\nStep 6: Building Merkle tree...")
    clause_texts = [ctrl["clause_text"] for ctrl in valid]
    leaves = [leaf_hash(ct) for ct in clause_texts]
    merkle_root, proofs = build_tree(leaves)
    print(f"  Merkle root: {merkle_root[:16]}...")

    extractor_version = f"pymupdf-{pymupdf_version()}"

    controls_with_provenance = []
    for i, ctrl in enumerate(valid):
        clause_text = ctrl["clause_text"]
        leaf = leaves[i]
        proof = proofs[leaf]

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

    print("\nStep 7: Signing Merkle root...")
    private_key = get_or_create_private_key()
    signature = sign(private_key, merkle_root)

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    priv_key_obj = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key))
    public_key_hex = priv_key_obj.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    ).hex()

    print(f"  Signature: {signature[:16]}...")
    print(f"  Public key: {public_key_hex}")

    print("\nStep 8: Writing pack.json...")
    tests = [t for t in profile.tests if t.get("control_id") in valid_ids]

    pack = {
        "manifest": {
            "id": profile.pack_id,
            "version": profile.pack_version,
            "title": profile.pack_title,
            "source_url": profile.source_url,
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

    pack_dir = REGISTRY_DIR / profile.registry_path
    pack_dir.mkdir(parents=True, exist_ok=True)
    pack_path = pack_dir / "pack.json"
    pack_path.write_text(json.dumps(pack, indent=2))

    _update_index(profile, len(controls_with_provenance), len(tests))

    keys_dir = REGISTRY_DIR / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    (keys_dir / "registry-2026.pub").write_text(public_key_hex)

    print(f"\n{'=' * 60}")
    print(f"Pack written to {pack_path}")
    print(f"  {len(controls_with_provenance)} controls, {len(tests)} tests")
    print(f"  Merkle root: {merkle_root[:16]}...")
    print(f"  Signed by: {public_key_hex[:16]}...")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Build a signed regulation pack from a profile"
    )
    parser.add_argument(
        "--profile",
        required=True,
        help="Profile name (e.g. 'pci-dss', 'gdpr') or path to a profile JSON file",
    )
    parser.add_argument(
        "--pdf",
        type=Path,
        default=None,
        help="Override the PDF path declared in the profile",
    )
    parser.add_argument(
        "--model",
        default="anthropic/claude-sonnet-4-20250514",
        help="LLM model used for extraction",
    )
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        help="Skip LLM extraction; use the profile's fallback_controls instead",
    )
    args = parser.parse_args()

    profile = RegulationProfile.load(args.profile)
    if args.pdf is not None:
        profile.pdf_path = args.pdf.resolve()

    build_pack(profile=profile, model=args.model, skip_llm=args.skip_llm)
"""Build a signed regulation pack from a RegulationProfile.

Usage:
    python -m ingestion.build_pack --profile pci-dss
    python -m ingestion.build_pack --profile gdpr --skip-llm
    python -m ingestion.build_pack --profile path/to/custom.json --pdf override.pdf

The same pipeline (fetch → extract → chunk → LLM extract → validate → sign → pack)
serves any regulation. Regulation-specific knowledge lives only in the profile JSON.
"""

