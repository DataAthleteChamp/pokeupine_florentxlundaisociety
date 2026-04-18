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

## 11. Hackathon Build Plan — Honest Moat Analysis

### 11.1 What is NOT a moat (table-stakes, vibe-codeable in a weekend)

| Claimed moat | Reality | Why it fails as a moat |
|---|---|---|
| RSS watcher → PR | `feedparser` + cron Action | Anyone copies the YAML in 30 min |
| LLM extraction with verbatim substring check | Standard `instructor` / structured output | Default pattern in every RAG tutorial |
| Embeddings + Qdrant | OpenAI + qdrant quickstart | Commodity infra |
| Crossmap = cosine ≥ 0.85 over embeddings | 5 lines of numpy | Naive kNN, 70%+ false positives in practice — useless without a curated ontology |
| Cosign keyless signing | One CLI invocation | Sigstore docs page |
| LLM-judge with grep/read tools | ReAct from any 2024 demo | No statistical guarantees → unusable in audit |
| SARIF emit | `pip install sarif-om` | Format conversion |

Build these — they're necessary plumbing — but **do not pitch them as the moat**. A judge who has used Cursor for 10 minutes will see through it.

### 11.2 What IS a moat (engineering novelty that resists replication)

Pick **two** of the following five and execute them deeply. That's the difference between "neat hack" and "I cannot rebuild this in a week."

#### M-1. Proof-Carrying Extraction (provenance you can take to court)
Every `Control` carries a verifiable provenance object, not just a substring check:

```python
class Provenance(BaseModel):
    source_doc_sha256: str        # the upstream PDF
    page: int
    byte_range: tuple[int, int]   # exact span in the extracted text layer
    text_layer_sha256: str        # hash of the extracted text (pinned extractor version)
    extractor_version: str        # pymupdf X.Y.Z + chunker rev
    merkle_proof: list[str]       # path from clause → page → doc root
    doc_root_signature: str       # cosign sig over the doc root
```

The pack ships a Merkle tree over `(doc → page → clause)`. A verifier can prove a single clause is in the original PDF *without* downloading the PDF. This is what makes a pack **audit-grade** rather than "AI-generated text we trust." Nobody else will build this in a weekend because Merkle proofs over chunked legal text + a stable text-extraction hash is fiddly.

**Demo line:** `pokeupine prove EUAIA-Art-12` → prints clause, page, byte range, and verifies the Merkle path against the signed doc root in 50 ms, with the PDF *not* on disk.

#### M-2. Semantic Regulation Diff + Test-Impact Analysis
When a regulation gets amended (this happens — AI Act delegated acts, HIPAA NPRM 2024, GDPR §2 carve-outs), the moat is answering: **"which of my codebase findings just changed?"**

Pipeline:
1. **Cross-version alignment**: legal texts renumber and reorder. Use embeddings + LCS over article headers to align v_old ↔ v_new controls (this is non-trivial; structural diff alone fails).
2. **Change classification**: editorial / clarifying / substantive / new-obligation / removed. Trained as a few-shot classifier with a held-out eval set you build from EUR-Lex consolidated versions (free labeled data).
3. **Test impact graph**: each `TestCase` records which clause tokens it depends on. A substantive change to those tokens flips the test's status to `needs-review`.
4. **Codebase impact**: re-run only the affected tests, diff against `findings.lock.json`.

**Demo line:** `pokeupine diff eu-ai-act@2025.09 eu-ai-act@2026.03 --against ./` → "3 substantive changes; 7 new findings in your repo; 2 prior findings now resolved."

This is an actual product feature compliance teams pay for and is genuinely hard.

#### M-3. Regulation-Aware Dataflow / Taint Analysis
Replace `grep for @audit_log` with real interprocedural analysis. Sources, sinks, and sanitizers are **derived from the control**, not hand-written:

- Sources: PHI / PII / model-output / cardholder-data / biometric — typed at the schema/model layer (Pydantic, SQLAlchemy, Prisma) or annotated.
- Sinks: log writers, network egress, third-party SDK calls, LLM prompt assembly, file writes.
- Sanitizers: redactors, consent gates, role-checks.

Use `tree-sitter` + a lightweight Datalog (e.g., [Soufflé](https://souffle-lang.github.io/) or pure Python on small graphs) to evaluate predicates like:
> "No path exists from a `PHI`-typed source to a `network_egress` sink that does not pass through a `consent_gate` sanitizer."

This is the same pattern as CodeQL, but the queries are **generated from controls**, not hand-written by humans. That generator (control → Datalog query) is the moat.

**Demo line:** `pokeupine scan --explain HIPAA-164.312-e` → shows the dataflow path from `Patient.ssn` through `logger.info(...)` with no redactor in between, with the actual call stack.

#### M-4. Calibrated LLM-Judge with Conformal Abstention
Currently `confidence < 1.0` is a vibe. Make it a **statistical guarantee**:

1. Build a calibration set of ~300 hand-labeled (control, code-snippet) → {pass, fail} pairs (you produce this; it becomes proprietary training data).
2. Run an ensemble of N LLM judges with diverse prompts.
3. Apply **split conformal prediction** to convert raw judge scores into prediction sets with a guaranteed coverage rate (e.g., "when we say PASS we are right 95% of the time"). Abstain otherwise → routes to human review.
4. Report coverage and abstention rate per pack version.

This turns the LLM-judge from "another agent" into a **measurable instrument**. It is also a non-trivial ML engineering exercise that does not exist as a copy-pasteable repo. References: Angelopoulos & Bates, *A Gentle Introduction to Conformal Prediction*, 2022.

**Demo line:** `pokeupine scan --judge-coverage 0.95` → "Coverage 95.2%, abstention 18.4%. 7 findings high-confidence, 2 routed to review."

#### M-5. The Control Ontology (the data moat)
Cosine ≥ 0.85 is candidate generation. The actual moat is a **canonical control ontology** — like SNOMED for compliance — where:

- Each canonical concept (e.g., `audit.access.read`) has a formal predicate (the dataflow query from M-3).
- Each regulation clause maps to one or more canonical concepts.
- The mapping is human-reviewed once, then reused across every codebase forever.

Embeddings + LLM are how you *propose* mappings; the ontology is what you *ship*. After 6 months of curation, no one can catch up because the labels compound. Hackathon-feasible slice: ship the ontology with 30 concepts and ~120 reviewed mappings across HIPAA / SOC2 / ISO 27001 / EU AI Act / GDPR. Make the schema public so others can contribute, but *you* hold the curation pipeline.

### 11.3 Recommended hackathon picks

| If you have | Pick | Why |
|---|---|---|
| 1 strong systems eng | **M-1 + M-5** | Both are mostly "build it carefully", no ML risk |
| 1 strong ML eng | **M-4 + M-2** | Conformal + diff are differentiating and demoable |
| 2 devs, mixed | **M-3 + M-5** | Dataflow demo is *visually* impressive on stage; ontology gives the long-term story |

Whatever you pick, your pitch sentence becomes the answer to: *"Why can't I rebuild this with Claude Code?"* — and the answer must be a specific engineering artifact, not a workflow.

---

## 11A. Per-Industry Context — what flags actually matter

Compliance is not one universe. Each industry has its own controls, its own evidence model, and its own *kind* of test that's worth running. Pick **2 industries to go deep** for the demo; "we support everything" is a red flag to judges.

### Healthcare (US: HIPAA, HITECH, 21 CFR Part 11, FDA SaMD; EU: MDR/IVDR, EHDS)
- **Core flags:** PHI access logging (§164.312(b)), encryption at rest/transit (§164.312(a)(2)(iv)), minimum necessary access, BAA presence for sub-processors, breach notification flow (§164.404), de-identification method (Safe Harbor 18 identifiers vs. Expert Determination), audit retention 6 years.
- **What to scan for:** ORM models with un-redacted PHI fields written to logs; missing `@require_role` decorators on routes touching `Patient`/`Encounter`; S3/GCS buckets without SSE-KMS; `print()` / `console.log` in PHI code paths; missing HMAC on webhook receivers.
- **Industry-specific moat:** wire the dataflow analyzer (M-3) to recognize **FHIR resources** (`Patient`, `Observation`, `MedicationRequest`) as PHI sources automatically. No competitor does this.

### Finance (SOX, PCI-DSS v4.0, GLBA, MiFID II, SR 11-7 model risk, NYDFS Part 500, EU DORA)
- **Core flags:** PAN tokenization (PCI 3.4), key rotation cadence (PCI 3.6), segregation of duties (SOX ITGC), transaction immutability / WORM, model governance docs (SR 11-7), customer-facing AI disclosures (NYDFS §500.16), operational-resilience testing (DORA Art. 25), trade surveillance hooks (MiFID II Art. 17).
- **What to scan for:** PAN-shaped strings (Luhn check) in logs/DB columns; KMS keys without rotation policy in IaC; merge-without-review on prod branches (SoX SoD); model artifacts deployed without signed model card.
- **Industry-specific moat:** **Differential testing for model risk** — replay a held-out adversarial dataset against the deployed model endpoint and check drift / fairness deltas, emitting them as findings tied to SR 11-7 §V.

### AI / ML (EU AI Act, NIST AI RMF 1.0, ISO/IEC 42001, Colorado AI Act, NYC LL144, UK AISI evals)
- **Core flags:** Risk classification (AI Act Art. 6 + Annex III), data governance (Art. 10), technical documentation (Art. 11 + Annex IV), record-keeping (Art. 12), transparency to users (Art. 13 + 50), human oversight hooks (Art. 14), accuracy/robustness/cybersecurity (Art. 15), post-market monitoring (Art. 72), GPAI obligations (Art. 53–55).
- **What to scan for:** ML training code without dataset lineage (no `mlflow.log_input` / DVC); inference endpoints without rate-limit + abuse logging; absence of `system_card.md`; LLM prompts that lack a `[user]` / `[system]` separation (prompt-injection surface); no `human_review_required=True` path on high-risk decisions.
- **Industry-specific moat:** ship a **"GPAI evidence collector"** that walks a HuggingFace-style training repo and emits Annex IV §2 documentation as a draft markdown, scoring each section's completeness.

### Privacy (GDPR, CCPA/CPRA, LGPD, India DPDP 2023, China PIPL, Quebec Law 25)
- **Core flags:** Lawful basis recorded per processing activity (Art. 6); DSAR endpoints (access/erasure/portability) reachable and < 30-day SLA; consent string format (TCF v2.2 for ad-tech); cross-border transfer (SCCs / adequacy / DPF); data minimization in API responses; retention schedules per data category; breach reporting < 72h plumbing.
- **What to scan for:** API responses that include fields beyond the documented schema (over-collection); consent checks missing on tracking SDK init; DSAR routes that don't actually delete from analytics warehouses; `region != "EU"` logic missing on egress to US sub-processors.
- **Industry-specific moat:** **"DSAR completeness graph"** — crawl every datastore reference in the repo (Postgres, S3, Snowflake, Segment, Mixpanel) and prove the deletion path covers all of them; missing nodes become findings.

### Security / SaaS (SOC 2 Type II, ISO 27001:2022, FedRAMP Moderate/High, CMMC 2.0, EU NIS2, EU CRA)
- **Core flags:** MFA enforced (SOC2 CC6.1), least-privilege IAM, vulnerability mgmt SLA (CC7.1), incident response runbook tested annually (CC7.3), change mgmt review (CC8.1), vendor due-diligence (CC9.2), CRA Art. 13 SBOM + vuln-disclosure, NIS2 Art. 21 incident reporting.
- **What to scan for:** IaC with `*` IAM principals; secrets in env files; Dependabot/Renovate disabled; missing `SECURITY.md`; CI without required reviewers; container images without provenance attestation.
- **Industry-specific moat:** **SBOM-aware compliance** — read CycloneDX/SPDX from the repo, map each dep to known CVEs, and emit findings tied to *specific* SOC2/CRA controls (not just "you have a CVE").

### Critical infra & public sector (NERC CIP, TSA SD pipeline, FISMA / FedRAMP, IRS Pub 1075, CJIS, FIPS 140-3)
- **Core flags:** crypto modules FIPS-validated; boundary identification; ICS network segmentation evidence; supply-chain attestation (SLSA level); FedRAMP control inheritance from CSP.
- **What to scan for:** `cryptography` lib in non-FIPS mode; TLS configs allowing < 1.2; hard-coded IPs into OT segments; missing SLSA provenance on releases.
- **Industry-specific moat:** **Inheritance graph** — express which controls are inherited from AWS GovCloud / Azure Gov vs. owned by the customer, and only scan for the *owned* set. This is the #1 pain in FedRAMP authorization packages.

### How to use this in the pitch
> "Pokeupine ships an open registry, but the moat is two things: a **proof-carrying extraction pipeline** that makes packs audit-admissible, and a **regulation-aware dataflow analyzer** with industry-specific source/sink recognizers — today for FHIR (healthcare) and for CycloneDX SBOMs (SaaS security). Everything else in the demo is open infrastructure anyone is welcome to copy."

That sentence is what defeats the "Claude Code in 3 days" objection.

### Mapping of moat picks to demo Definition of Done

| Replace this old DoD line | With this stronger one |
|---|---|
| `pokeupine search` returns cross-reg hits | `pokeupine prove <control-id>` verifies a Merkle proof against the signed doc root **without** the PDF on disk (M-1) |
| `pokeupine map --from ...` shows ≥ 2 crossmaps | `pokeupine diff eu-ai-act@v1 @v2 --against ./` lists *new findings caused by the amendment* (M-2) |
| `pokeupine scan` finds ≥ 6/8 seeded violations | `pokeupine scan --explain HIPAA-164.312-e` prints the *dataflow path* from a FHIR `Patient.ssn` source to a `logger.info` sink (M-3) |
| LLM-judge marked "uncertain" sometimes | `pokeupine scan --judge-coverage 0.95` reports calibrated coverage + abstention rate on a held-out set (M-4) |

---

## 11B. The 5-Hour Hackathon Plan (what we actually build today)

**One story, one industry, one language, two artifacts.**

> "We scan a healthcare codebase against HIPAA. Every finding is backed by a **Merkle proof** to the exact byte range in the official PDF, and the dangerous ones come from a **dataflow analyzer** that knows FHIR `Patient.ssn` is PHI."

Industry: **Healthcare / HIPAA §164.312 only**. Language: **Python only**. Moats demoed: **M-1 (proof-carrying extraction)** + a thin slice of **M-3 (FHIR-typed dataflow)**. Everything else from §§4–10 is deferred.

### 11B.1 Demo surface (the only commands that exist on stage)

```
pokeupine scan <path>            # finds 3 seeded violations
pokeupine explain <control-id>   # verbatim clause + ✓ Merkle proof
pokeupine prove <control-id>     # verifies proof WITHOUT the PDF on disk
```

No `list`, `pull`, `update`, `search`, `map`, `diff`, `verify`, `generate`, `ingest`, `init` today. They're in §6 for the post-hackathon roadmap.

### 11B.2 Hour-by-hour

**H0  (0:00–0:30) — Skeleton & demo target**
- `pip install typer rich pydantic pymupdf tree-sitter tree-sitter-python instructor litellm diskcache cryptography`
- Build `examples/vulnerable-clinic/` — ~60-line FastAPI app with:
  - `class Patient(BaseModel): ssn: str; name: str`
  - one route doing `logger.info(f"patient {p}")` ← the money finding
  - one route missing `@require_role("clinician")`
  - no `SECURITY.md` (LLM-judge fallback finding)
  - one *clean* control route
- Lock the three commands above. Nothing else exists.

**H1  (0:30–1:30) — Ingest HIPAA §164.312 + Merkle tree (M-1)**
- Download HIPAA Security Rule §164.312 (one PDF, ~10 pages).
- `pymupdf`: extract per-page text, record `(page, byte_start, byte_end)` for each clause split on `\(\w\)\s` headers.
- LLM extract → `Control` objects; reject any whose `clause_text` is not a verbatim substring (loud fail).
- Merkle build: `leaf = sha256(clause_text)` → `page_node = sha256(sorted leaves)` → `doc_root = sha256(sorted page_nodes)`. Store proof path per clause.
- Sign `doc_root` with a local **ed25519** key (skip cosign — too much yak-shaving for 5h).
- Emit `pack.json` with controls + proofs + `doc_root_signature`. **No tarball, no registry, no GitHub Action.**
- Commit `pack.json` to the repo. Never re-extract during the demo.

**Checkpoint @ H1:30** — `pokeupine prove HIPAA-164.312-b` prints clause + verifies Merkle path in <100 ms with the PDF off disk. **If this fails, cut M-1 and pivot all remaining time to dataflow.**

**H2  (1:30–3:00) — FHIR-typed dataflow (M-3 slice)**
- Parse the example app with `tree-sitter-python`.
- **Sources** (kept tiny):
  - any class inheriting `BaseModel` with name in `{"Patient","Observation","MedicationRequest"}` → all fields are PHI-tainted, **or**
  - fields explicitly typed `Annotated[str, PHI]`.
- **Sinks**: call exprs matching `logger.{info,debug,warning,error}`, `print`, `requests.{get,post}`, `httpx.*`.
- **Sanitizers**: call to `redact(...)` or `@phi_safe` decorator on enclosing function.
- **Analysis**: intra-procedural def-use walk. A var is tainted if assigned from a tainted expr; if a tainted var reaches a sink without crossing a sanitizer → finding.
- Each finding cites: source loc, sink loc, control id (`HIPAA-164.312-b`), and links to the proof.

**Demo target** — `pokeupine scan examples/vulnerable-clinic` prints **1 red dataflow finding** with the path `Patient.ssn → p → logger.info` rendered as an arrow.

**H3  (3:00–4:00) — `scan` / `explain` / `prove` polish + 1 LLM-judge fallback**
- Wire Typer commands; `rich` panels with the dataflow arrow and proof verification check-mark.
- `pokeupine explain HIPAA-164.312-b` → verbatim clause + page + Merkle ✓ + remediation snippet.
- Add **one** `kind="docs_present"` LLM-judge test that checks for a `SECURITY.md` mentioning audit logging. `diskcache` it. Don't go further with the judge.
- Add **one** trivial AST check: routes touching `Patient` must carry `@require_role`.
- Total: **3 findings** seeded, **3 findings** detected.

**H4  (4:00–4:45) — Demo dress rehearsal**
- Sequence:
  1. `pokeupine scan examples/vulnerable-clinic` → 3 findings (1 dataflow red, 1 AST yellow, 1 docs yellow)
  2. `pokeupine explain HIPAA-164.312-b` → clause + ✓ proof
  3. `pokeupine prove HIPAA-164.312-b --no-pdf` → proof verifies, PDF deleted from disk
- Run end-to-end **3×** back-to-back. Fix any flakiness.
- **Pre-warm the LLM cache.** No live LLM calls during the demo.
- 6-line README with install + the 3 commands.

**H4:45–5:00 — Pitch slide + buffer**
- One slide: moat sentence + screenshot of proof verification + screenshot of dataflow finding.
- Buffer for last-minute breakage.

### 11B.3 Hard cuts (do NOT build today)
- ❌ Registry, `index.json`, network `pull`/`update`/`list` — pack lives on disk
- ❌ Cosign / sigstore — local ed25519
- ❌ Qdrant, embeddings, semantic search, crossmap (M-5 deferred)
- ❌ Streamlit review UI
- ❌ RSS watcher / GitHub Actions
- ❌ SARIF, JSON reporter (rich-only)
- ❌ Conformal prediction (M-4) — needs a calibration set we don't have
- ❌ Regulation diff (M-2) — needs two versions
- ❌ Multiple regulations / multiple industries — HIPAA only
- ❌ TypeScript, IaC, semgrep adapters

### 11B.4 Risk triage
| Rank | Risk | Mitigation |
|---|---|---|
| 1 | Merkle-proof flakiness from text-extraction offset drift | Pin one `pymupdf` version; freeze the extracted text layer to disk; hash *that file*, not the live extraction |
| 2 | Tree-sitter taint walker has too many false negatives | Hand-pick the vulnerable example so it triggers the simplest possible path; intra-procedural only |
| 3 | LLM extraction time / rate limits | Extract once at H1, commit `pack.json`, never re-run during demo |
| 4 | Live-coded demo crashes | All three commands run from cached state; no network calls live |

### 11B.5 Answers to the obvious judge questions
1. *"Why can't I rebuild this with Claude Code in a weekend?"* — Point at `prove`: the Merkle tree over PDF byte ranges is the audit-grade artifact; vibes-coded scanners don't have it. Then point at the dataflow finding: source typing comes from a **typed FHIR resource**, not a regex.
2. *"What about the registry / signed packs / crossmaps you mentioned?"* — "Open infrastructure on the roadmap (§§4, 5, 9). The defensible artifact is the **proof format** and the **control ontology**, not the CDN."
3. *"Only one regulation?"* — "By design for the demo. The pack format is regulation-agnostic; a second pack is a few hours of ingestion, not engineering."

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

## 14. Definition of Done (5-Hour Hackathon)

- [ ] `pokeupine scan examples/vulnerable-clinic` prints **3 findings** (1 dataflow, 1 AST, 1 docs)
- [ ] The dataflow finding renders the path `Patient.ssn → p → logger.info` with file:line for source and sink
- [ ] `pokeupine explain HIPAA-164.312-b` prints verbatim clause + page + ✓ Merkle proof verification
- [ ] `pokeupine prove HIPAA-164.312-b --no-pdf` verifies the proof in <100 ms with the source PDF deleted from disk
- [ ] `pack.json` commits to the repo and is regenerable via `make pack` (but not regenerated live)
- [ ] All three commands run end-to-end from cache, **no network calls during the demo**
- [ ] One-page README: install + the three commands + the moat sentence
- [ ] Demo rehearsed 3× back-to-back without flake

**Deferred to post-hackathon (do not block on these):** `pip install pokeupine` from PyPI, registry `list`/`pull`/`update`, cosign keyless, SARIF, asciinema, second pack.

---

## 15. Pitch Sentence

> Pokeupine scans your codebase against regulations like HIPAA — and unlike every vibe-coded scanner, every finding is backed by a **Merkle proof to the exact byte range in the official PDF**, and the dangerous ones come from a **dataflow analyzer that understands typed FHIR resources as PHI sources**. The registry, the watcher, and the cross-mapping are open infrastructure on the roadmap; the proof format and the control ontology are the moat.
