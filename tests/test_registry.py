"""Registry client: HTTP and file:// resolution + signature enforcement."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from pokeupine import registry
from pokeupine.schemas import Pack


REPO_ROOT = Path(__file__).parent.parent
REGISTRY_DIR = REPO_ROOT / "pokeupine-registry"
PACK_JSON = REGISTRY_DIR / "packs" / "pci-dss" / "4.0.0" / "pack.json"
INDEX_JSON = REGISTRY_DIR / "index.json"


@pytest.fixture
def isolated_packs_dir(tmp_path, monkeypatch):
    """Redirect PACKS_DIR so tests don't touch ~/.pokeupine."""
    monkeypatch.setattr(registry, "PACKS_DIR", tmp_path / "packs")
    return tmp_path / "packs"


def test_pull_pack_via_file_url(isolated_packs_dir, monkeypatch):
    """file:// scheme must resolve without touching the network."""
    monkeypatch.setattr(registry, "REGISTRY_BASE_URL", f"file://{REGISTRY_DIR}")

    pack = registry.pull_pack("pci-dss")
    assert isinstance(pack, Pack)
    assert pack.manifest.id == "pci-dss"
    cached = isolated_packs_dir / "pci-dss" / "4.0.0" / "pack.json"
    assert cached.exists()


def test_pull_pack_via_bare_path(isolated_packs_dir, monkeypatch):
    """A bare local path must work as the registry source."""
    monkeypatch.setattr(registry, "REGISTRY_BASE_URL", str(REGISTRY_DIR))
    pack = registry.pull_pack("pci-dss")
    assert pack.manifest.controls_count == len(pack.controls)


def test_pull_unknown_pack_errors(isolated_packs_dir, monkeypatch):
    monkeypatch.setattr(registry, "REGISTRY_BASE_URL", f"file://{REGISTRY_DIR}")
    with pytest.raises(SystemExit):
        registry.pull_pack("nonexistent-pack")


def test_pull_rejects_tampered_signature(isolated_packs_dir, monkeypatch, tmp_path):
    """A pack with a flipped Merkle root must fail signature verification."""
    fake_registry = tmp_path / "fake-registry"
    (fake_registry / "packs" / "pci-dss" / "4.0.0").mkdir(parents=True)

    pack_data = json.loads(PACK_JSON.read_text())
    bad = copy.deepcopy(pack_data)
    # Flip the Merkle root — signature was issued over the original root only.
    bad["manifest"]["merkle_root"] = "0" * 64
    (fake_registry / "packs" / "pci-dss" / "4.0.0" / "pack.json").write_text(
        json.dumps(bad)
    )
    (fake_registry / "index.json").write_text(INDEX_JSON.read_text())

    monkeypatch.setattr(registry, "REGISTRY_BASE_URL", f"file://{fake_registry}")
    with pytest.raises(SystemExit):
        registry.pull_pack("pci-dss")


def test_pull_pack_via_http_mock(isolated_packs_dir, monkeypatch):
    """Happy path through the http(s) branch with mocked requests.get."""
    monkeypatch.setattr(registry, "REGISTRY_BASE_URL", "https://example.test/registry")

    index_payload = json.loads(INDEX_JSON.read_text())
    pack_payload = json.loads(PACK_JSON.read_text())

    class FakeResp:
        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    def fake_get(url, timeout=None):
        if url.endswith("index.json"):
            return FakeResp(index_payload)
        return FakeResp(pack_payload)

    with patch.object(registry.requests, "get", fake_get):
        pack = registry.pull_pack("pci-dss")
    assert pack.manifest.id == "pci-dss"
