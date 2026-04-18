# Pokeupine — Technical Design

> Compliance-as-Code CLI with a curated, vector-indexed Regulation Registry.
> Status: Hackathon spec (M0). Production hardening deferred.

---

## 0. TL;DR

**Pokeupine** turns regulations (EU AI Act, HIPAA, GDPR…) into executable code-level test suites.
The differentiator is not the CLI — it is the **Registry**: an automatically-watched, LLM-extracted, human-curated, vector-indexed corpus of regulation → control → test mappings, distributed as signed packs.

```
┌──────────────┐      ┌────────────────────────┐      ┌───────────────┐
│ Reg Watcher  │ ───► │  Ingestion Pipeline    │ ───► │  Registry     │
│ (RSS/scrape) │      │  parse→extract→embed   │      │  (packs+API)  │
└──────────────┘      └────────────────────────┘      └───────┬───────┘
                                                              │
                                          pokeupine list/pull │
                                                              ▼
                                                      ┌───────────────┐
                                                      │  CLI scanner  │
                                                      │ AST+semgrep+  │
                                                      │ LLM judge     │
                                                      └───────────────┘
```

---

## 1. Component Map

| # | Component | Tech | Status M0 |
|---|---|---|---|
| 1 | CLI | `typer` + `rich` | ✅ build |
| 2 | Schemas | `pydantic` v2 | ✅ build |
| 3 | LLM gateway | `litellm` + `instructor` + `diskcache` | ✅ build |
| 4 | Ingestion: parser | `pymupdf`, `docling` fallback | ✅ build |
| 5 | Ingestion: extractor | LLM + structured output | ✅ build |
| 6 | Ingestion: watcher | `feedparser` + scheduled GH Action | ✅ minimal |
| 7 | Embedder | `text-embedding-3-large` or `bge-large` (local) | ✅ build |
| 8 | Vector DB | `qdrant` (embedded mode) | ✅ build |
| 9 | Registry storage | GitHub repo `pokeupine/registry` + R2/Pages | ✅ fake-it |
| 10 | Pack format | `tar.gz` + `manifest.json` + `cosign` sig | ✅ build |
| 11 | Scan engines | `ast`, `tree-sitter`, `semgrep`, regex, LLM-judge | ✅ build |
| 12 | Reporters | rich terminal, JSON, SARIF 2.1.0 | ✅ build |
| 13 | Review UI | `streamlit` (offline only, you run it) | ✅ minimal |

---

## 2. Data Model

```python
# pokeupine/schemas.py

from pydantic import BaseModel, Field
from typing import Literal
from datetime import date

TestKind = Literal[
    "route_exists", "decorator_required", "taint_flow",
    "weak_crypto", "audit_coverage", "model_field_required",
    "iac_check", "consent_gate", "llm_judge",
]

class Control(BaseModel):
    id: str                         # "EUAIA-Art-12"
    title: str
    clause_text: str                # verbatim, validated as substring of source
    source: str                     # "eu-ai-act-2024-1689.pdf p.42"
    source_url: str | None = None
    category: str
    requirement: str                # plain-English summary (LLM, may drift)
    evidence_types: list[Literal["code","config","docs","runtime"]]
    embedding_id: str | None = None # FK into vector DB

class TestCase(BaseModel):
    id: str
    control_id: str
    kind: TestKind
    target_globs: list[str]
    spec: dict                      # kind-specific payload
    severity: Literal["high","medium","low"]
    rationale: str
    reviewed: bool = False

class CrossMap(BaseModel):
    """Equivalence mapping between controls across regulations."""
    from_control: str               # "HIPAA-164.312-b"
    to_control: str                 # "SOC2-CC7.2"
    similarity: float               # 0..1, cosine on embeddings
    confidence: Literal["auto","reviewed","authoritative"]

class Finding(BaseModel):
    test_id: str
    control_id: str
    status: Literal["pass","fail","uncertain"]
    file: str | None = None
    line: int | None = None
    evidence: str
    remediation: str
    confidence: float = 1.0

class PackManifest(BaseModel):
    id: str                         # "eu-ai-act"
    version: str                    # "2026.03" (CalVer)
    title: str
    jurisdiction: str               # "EU"
    source_url: str
    source_hash: str                # sha256 of upstream PDF
    published: date
    controls_count: int
    tests_count: int
    languages: list[str]            # ["python","typescript"]
    embedding_model: str
    embedding_dim: int
    pokeupine_min: str              # "0.3.0"
    signature: str                  # cosign sig over the tarball
```

---

## 3. Pack Format

A regulation pack is a signed `tar.gz` distributed via the registry.

```
eu-ai-act-2026.03.tar.gz
├── manifest.json          # PackManifest
├── controls.json          # list[Control]
├── tests.yaml             # list[TestCase]
├── crossmap.json          # list[CrossMap] to other packs
├── embeddings.parquet     # control_id, vector[float32]
├── source/
│   └── eu-ai-act.pdf      # original (optional, for audit trail)
└── CHANGELOG.md           # diff vs previous version
```

Versioning: **CalVer `YYYY.MM`** for regulation snapshots (matches how legal texts evolve).
Signing: **sigstore/cosign keyless** with GitHub OIDC — anyone can verify the pack came from the official registry repo.

---

## 4. Registry API (M0: GitHub-as-CDN; M1: real API)

### M0 implementation
A public GitHub repo `pokeupine/registry` serving static JSON over `raw.githubusercontent.com` (or GitHub Pages):

```
registry/
├── index.json                                # catalog
├── packs/
│   ├── eu-ai-act/
│   │   ├── 2026.03/
│   │   │   ├── pack.tar.gz
│   │   │   ├── pack.tar.gz.sig
│   │   │   └── manifest.json
│   │   └── 2025.09/...
│   ├── hipaa-164/...
│   └── gdpr/...
└── feeds/
    └── updates.atom                          # consumed by `pokeupine update`
```

`index.json`:
```json
{
  "schema_version": 1,
  "updated": "2026-04-18T10:00:00Z",
  "packs": [
    {
      "id": "eu-ai-act",
      "title": "EU Artificial Intelligence Act",
      "jurisdiction": "EU",
      "latest": "2026.03",
      "versions": ["2026.03", "2025.09", "2024.12"],
      "controls_count": 147,
      "languages": ["python","typescript"],
      "url": "packs/eu-ai-act/2026.03/pack.tar.gz",
      "manifest": "packs/eu-ai-act/2026.03/manifest.json"
    }
  ]
}
```

### CLI ↔ Registry contract
| Command | HTTP equivalent | Cache |
|---|---|---|
| `pokeupine list` | `GET /index.json` | 1h TTL |
| `pokeupine search <q>` | local — uses pulled embeddings | — |
| `pokeupine pull <id>[@ver]` | `GET /packs/<id>/<ver>/pack.tar.gz` + `.sig` | permanent, content-addressed |
| `pokeupine update` | reads `feeds/updates.atom` | 1h |
| `pokeupine verify <pack>` | local — cosign verify | — |

### M1 upgrade path (post-hackathon)
Swap raw GitHub for FastAPI on Cloudflare Workers + Postgres + R2. Same URL shape, no client changes.

---

## 5. Ingestion Pipeline (the moat)

This is what we will **actually run** during the hackathon to demonstrate technical novelty. Lives in `ingestion/` directory and runs as a scheduled GitHub Action in the registry repo.

### 5.1 Watcher
```python
# ingestion/watch.py
SOURCES = [
    {"id": "eu-ai-act",  "url": "https://eur-lex.europa.eu/...rss",  "kind": "rss"},
    {"id": "nist-ai-rmf","url": "https://www.nist.gov/.../updates", "kind": "html"},
    {"id": "hhs-hipaa",  "url": "https://www.hhs.gov/.../rss",      "kind": "rss"},
    {"id": "ico-gdpr",   "url": "https://ico.org.uk/.../rss",       "kind": "rss"},
]

def poll() -> list[NewDoc]:
    """Returns docs whose sha256 differs from registry index.json."""
```

Runs **every 6 hours** via `.github/workflows/watch.yml`. New docs open a draft PR with the parsed output.

### 5.2 Parser
- Primary: `pymupdf` (fast, plain text + page numbers).
- Fallback: `docling` (IBM, handles scanned/structured legal docs).
- Output: `list[Page(number, text)]`.

### 5.3 Chunker
Heuristic regex per regulation family:
- EU instruments: split on `^Article\s+\d+`
- US CFR: split on `§\s*\d+\.\d+`
- Fallback: 1500-char windows with 200-char overlap.

### 5.4 Extractor
```python
# ingestion/extract.py
@cached
def extract_controls(chunk: str, source_meta: dict) -> list[Control]:
    return llm.structured(
        prompt=EXTRACT_PROMPT,
        context=chunk,
        schema=list[Control],
        model="claude-sonnet-4-5",
        temperature=0,
    )
```

Validation gates (auto-reject on fail):
1. `clause_text` must be a verbatim substring of the chunk.
2. `id` matches regex `^[A-Z]+(-[A-Za-z0-9.]+)+$`.
3. `evidence_types` non-empty.
4. Cosine similarity vs existing controls > 0.95 → flag as duplicate.

### 5.5 Embedder
```python
embeddings = embed_batch(
    [c.clause_text for c in controls],
    model="text-embedding-3-large",  # or bge-large-en-v1.5 local
    dim=1024,
)
qdrant.upsert("controls", points=zip(ids, embeddings, payloads))
```

### 5.6 Cross-mapper
For each new control, query the vector DB for top-5 neighbors across other regulations. Pairs with cosine > 0.85 become candidate `CrossMap` entries (confidence=`auto`); humans promote to `reviewed` in the review UI.

This is the killer feature: **automatic discovery that HIPAA §164.312(b) ≈ SOC2 CC7.2 ≈ ISO 27001 A.12.4** without anyone writing the mapping by hand.

### 5.7 Review queue
Streamlit app reads pending controls from a SQLite DB, shows side-by-side: source clause | extracted control | suggested tests | candidate crossmaps. Reviewer clicks ✅ or edits inline. On approve → commits to `registry/` repo via PR.

### 5.8 Pack builder
```bash
make pack ID=eu-ai-act VERSION=2026.03
# → tarballs controls.json + tests.yaml + embeddings.parquet + manifest.json
# → cosign sign --keyless pack.tar.gz
# → updates registry/index.json
# → opens release PR
```

---

## 6. CLI Surface

```
pokeupine init                         scaffold .pokeupine/ in cwd
pokeupine list [--json]                show all available packs
pokeupine search "<query>" [--top N]   semantic search over all installed packs
pokeupine pull <id>[@version]          download + verify pack
pokeupine update                       check feeds, pull newer versions
pokeupine verify <pack>                cosign-verify a local pack
pokeupine ingest <pdf|url>             one-off local extraction (no registry)
pokeupine generate [--id ID]           synthesize tests from controls
pokeupine scan <path> [--pack ID,...]  run scan
pokeupine explain <control-id>         verbatim clause + remediation + RAG
pokeupine map --from CTRL --to REG     show crossmaps
pokeupine version
```

---

## 7. Scan Engine

```
                    ┌─────────────────────┐
                    │  TestCase dispatch  │
                    └──────────┬──────────┘
        ┌──────────┬───────────┼────────────┬──────────┐
        ▼          ▼           ▼            ▼          ▼
   ┌────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────────┐
   │  AST   │ │ semgrep │ │  regex  │ │  IaC    │ │ LLM-judge│
   │ engine │ │ engine  │ │ engine  │ │ engine  │ │ ReAct    │
   └────────┘ └─────────┘ └─────────┘ └─────────┘ └──────────┘
        │          │           │            │          │
        └──────────┴───────────┼────────────┴──────────┘
                               ▼
                          ┌─────────┐
                          │Findings │ → terminal | json | sarif
                          └─────────┘
```

### Engine contract
```python
class Engine(Protocol):
    kinds: set[TestKind]
    def run(self, test: TestCase, files: list[Path]) -> list[Finding]: ...
```

### Determinism order
1. Deterministic engines first (AST, semgrep, regex). Cheap, fast, citeable.
2. LLM-judge only for tests where deterministic engines returned no result and the control's `evidence_types` contains `"docs"` or the `kind == "llm_judge"`.
3. LLM-judge findings always carry `confidence < 1.0` and default to `status="uncertain"` unless the agent provides a file:line citation.

### LLM-judge agent
ReAct loop, max 8 iterations, tools:
- `grep(pattern: str, glob: str = "**/*") -> list[Match]`
- `read_file(path: str, start: int = 1, end: int = 200) -> str`
- `list_dir(path: str) -> list[str]`

System prompt forbids speculation; requires either a `file:line` citation or `status="uncertain"`.

---

## 8. Storage Layout (client-side)

```
~/.pokeupine/
├── config.toml
├── cache/
│   └── llm/                       # diskcache of LLM responses
└── packs/
    ├── eu-ai-act/
    │   └── 2026.03/
    │       ├── manifest.json
    │       ├── controls.json
    │       ├── tests.yaml
    │       ├── embeddings.parquet
    │       └── crossmap.json
    └── hipaa-164/...

./.pokeupine/                      # per-project, committed to git
├── pokeupine.yaml                 # which packs, which overrides
├── findings.lock.json             # baseline (suppresses known findings)
└── reports/
    └── 2026-04-18T10-30.sarif
```

---

## 9. Vector Search — Local Mode

To keep `pokeupine search` zero-server, embeddings ship inside each pack as a Parquet file. The CLI loads them into an in-memory Qdrant (embedded) or falls back to numpy cosine.

```python
# pokeupine/search.py
def search(query: str, top_k: int = 10) -> list[ControlHit]:
    q_vec = embed_query(query)        # uses same model as packs declare
    hits = []
    for pack in installed_packs():
        emb = pack.load_embeddings()  # parquet → np.ndarray
        sims = emb @ q_vec
        top = np.argsort(-sims)[:top_k]
        hits.extend(pack.controls[i] for i in top)
    return rerank(hits, top_k)
```

Embedding model is **pinned per pack** (recorded in manifest). The CLI lazily downloads the matching model on first search (or uses OpenAI API if configured).

---

## 10. Security & Trust

| Concern | Mitigation |
|---|---|
| Pack tampering | Cosign keyless signing tied to registry repo's GitHub OIDC; CLI verifies on `pull` |
| Malicious test specs (e.g., RCE via semgrep rule) | Semgrep rules sandboxed; LLM-judge tools are read-only; no `eval` of pack content |
| LLM data exfiltration | `--offline` flag disables LLM-judge; deterministic engines only |
| Private code in prompts | LLM-judge sends snippets only when explicitly enabled; local model option via `litellm` → Ollama |
| Hallucinated regulations | `clause_text` must be verbatim substring of source PDF (validated at ingestion); `pokeupine explain` always shows the source |

---

## 11. Hackathon Build Plan (Mapped to 50% Moat Score)

We will demo **all four moat elements** as working code, even if minimal:

| Moat element | Demo artifact | Effort |
|---|---|---|
| Watcher pipeline | GitHub Action on `pokeupine/registry` polling 2 RSS feeds, opening PRs with extracted controls | 3h |
| Vector index | Qdrant embedded; `pokeupine search "audit log"` returns hits across 3 packs | 2h |
| Cross-reg mapping | `pokeupine map --from HIPAA-164.312-b` shows auto-discovered SOC2/ISO neighbors | 2h |
| Signed packs | Cosign signature verified on `pokeupine pull`; tampered pack rejected on stage | 1h |

These four together = the "technical novelty" judges score. The CLI scan is the "product works" demo.

---

## 12. Out of Scope (M0)

- Hosted registry API (use GitHub-as-CDN)
- Web dashboard / SaaS
- Multi-tenant auth
- Real-time scan (only batch CLI)
- Languages beyond Python (JS/TS scaffolding only)
- Auto-fix / patch generation
- Runtime/dynamic analysis

---

## 13. Repository Layout

```
pokeupine/                          # this repo (CLI + ingestion)
├── pyproject.toml
├── pokeupine/
│   ├── cli.py
│   ├── schemas.py
│   ├── llm.py
│   ├── registry/                   # client: list/pull/verify
│   ├── search/                     # local vector search
│   ├── ingest/                     # PDF → Control[]
│   ├── generate/                   # Control → TestCase[]
│   ├── scan/
│   │   ├── walker.py
│   │   ├── runner.py
│   │   ├── adapters/
│   │   └── engines/
│   └── report/
├── ingestion/                      # offline pipeline (we run)
│   ├── watch.py
│   ├── extract.py
│   ├── embed.py
│   ├── crossmap.py
│   ├── pack.py
│   └── review_ui.py                # streamlit
├── examples/
│   ├── vulnerable-clinic/
│   └── compliant-clinic/
└── tests/

pokeupine/registry/                 # SEPARATE repo; the moat
├── index.json
├── packs/
│   └── <id>/<version>/
├── feeds/updates.atom
├── .github/workflows/
│   ├── watch.yml                   # 6h schedule
│   └── publish.yml                 # on PR merge → sign + release
└── ingestion-state/                # sqlite of what's been seen
```

---

## 14. Definition of Done (Hackathon)

- [ ] `pip install pokeupine` works
- [ ] `pokeupine list` returns ≥ 3 packs from the registry
- [ ] `pokeupine pull eu-ai-act` downloads + cosign-verifies
- [ ] `pokeupine search "audit log"` returns cross-regulation hits
- [ ] `pokeupine map --from HIPAA-164.312-b` shows ≥ 2 crossmaps
- [ ] `pokeupine scan examples/vulnerable-clinic` finds ≥ 6/8 seeded violations
- [ ] Registry GitHub Action visibly opens a PR after a simulated upstream change
- [ ] SARIF uploads to GitHub Code Scanning
- [ ] README with 60-second asciinema demo

---

## 15. Pitch Sentence

> Pokeupine is an open-source CLI that scans your codebase for violations of regulations like the EU AI Act and HIPAA — backed by a community-curated, vector-indexed registry that auto-watches official sources, cross-maps controls across frameworks, and ships signed packs you verify locally.
