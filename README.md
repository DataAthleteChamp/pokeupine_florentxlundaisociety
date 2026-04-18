# Pokeupine

Compliance-as-Code CLI with proof-carrying regulation packs.

## Problem Statement

Modern teams can ship business software into regulated workflows faster
than they can reason about compliance. That gap is growing as more code
is written or assembled with AI assistance: features ship quickly, but
the caveats hidden inside standards like PCI-DSS or GDPR are still hard
to interpret at the code level.

The hard part is not just reading the regulation. The hard part is
translating legal and audit language into concrete engineering
questions:

1. **What exactly counts as a violation in code?** For example, when is
    PAN considered stored, what data must never persist after
    authorization, and which endpoints or code paths must carry audit
    controls?
2. **How do you prove the finding maps to the real regulation?** Even
    when a scanner flags a problem, auditors still need to know which
    exact clause it maps to and whether that rule can be trusted.

Existing tooling only partially closes that gap. Rule-based tools often
lose the original legal provenance, while shallow source scanning misses
the data flows and structural context that matter in real applications.

The result is that compliance issues are often discovered late — during
audit prep, customer security reviews, or incident response — when they
are much more expensive to fix.

## Solution

Pokeupine is a CLI that ships **signed regulation packs** and runs them
against a target codebase. Every control inside a pack carries:

- the verbatim clause text extracted from the official PDF,
- the SHA-256 of the source PDF and of the deterministic text layer,
- a Merkle proof from the clause leaf to a signed root, and
- an Ed25519 signature over that root using a hard-coded trust anchor.

`pokeupine prove <control-id>` verifies the full chain **without
needing the source PDF on disk**. `pokeupine explain <control-id>`
prints the verbatim clause alongside the same verification.

For code analysis, Pokeupine combines five engines (regex, AST,
required-decorator, intra-procedural taint dataflow, and an optional
LLM judge for policy-heavy checks). The dataflow engine recognises
Luhn-valid PAN literals as
regulated sources, follows them through aliasing into sinks such as
`cursor.execute`, and respects sanitiser calls (`tokenize`, `mask_pan`,
…) to suppress false positives.

The architecture is regulation-agnostic. The repository ships two packs
out of the box (`pci-dss` v4.0.0 and `gdpr` v2016.679); adding a new
regulation is a matter of writing an ingestion profile and running
`python -m ingestion.build_pack`.

## Technical Approach

```
PDF --extract--> text_layer.txt --chunk--> LLM extract --validate--+
                                                                   |
                                       Merkle tree over clauses    |
                                                                   v
                                  ed25519 sign root --------> pack.json
                                                                |
                            pokeupine pull <pack> <-- registry +
                                  |
                                  +-- pokeupine scan    -> engines -> findings
                                  +-- pokeupine explain -> clause + Merkle proof
                                  +-- pokeupine prove   -> verify proof, no PDF
```

### Pack ingestion (`ingestion/`)

1. **`extract_text.py`** uses PyMuPDF to produce a frozen text layer
   from the source PDF, with deterministic page separators. The byte
   offsets recorded in every `Provenance` reference this file, not the
   PDF itself.
2. **`chunk.py`** splits the text layer into heading-anchored chunks.
3. **`llm_extract.py`** runs an LLM extraction pass per chunk, guided
   by a regulation profile (`ingestion/profiles/*.json`) that supplies
   the ID regex, heading rules, and extraction guidance.
4. **`validate.py`** rejects extracted controls whose `clause_text` is
   not a verbatim substring of the text layer (with a small amount of
   PDF-noise normalisation).
5. **`build_pack.py`** ties everything together, builds a Merkle tree
   over the validated clause leaves, signs the root with Ed25519, and
   writes `pack.json` plus a copy of the text layer.

### Pack distribution (`pokeupine-registry/`)

A pack is published by committing it under
`pokeupine-registry/packs/<id>/<version>/pack.json` and updating
`pokeupine-registry/index.json`. The CLI resolves the registry from the
`POKEUPINE_REGISTRY_URL` environment variable and falls back to the
in-repo registry served via raw GitHub. Both `https://`, `file://`, and
bare local paths are accepted, which makes fully offline runs trivial.

### Scan engines (`pokeupine/scan/engines/`)

| Engine | Responsibility |
| ------ | -------------- |
| `regex` | Line-level regex matches against source text. |
| `ast_check` | Tree-sitter AST checks (cleartext HTTP, weak password thresholds, generic patterns). All thresholds and remediation strings are spec-driven. |
| `decorator` | Asserts that every function matching a target pattern carries a required decorator (e.g. `@audit_log` on routes). |
| `dataflow` | Intra-procedural def-use graph over Python ASTs. Pydantic fields and Luhn-valid PAN literals flow through aliasing into call sinks; sanitiser calls clear taint. |
| `llm_judge` | Document and policy check with optional LLM assistance via `POKEUPINE_LLM=1`; degrades to an `uncertain` finding instead of failing the scan when no key is configured. |

Each engine consumes the same `TestCase` schema from
`pokeupine/schemas.py`, so adding a sixth engine requires no changes
elsewhere in the runner.

### Verification (`pokeupine/crypto.py`, `pokeupine/merkle.py`)

`pokeupine prove` recomputes the leaf hash from the stored
`clause_text`, walks the recorded Merkle siblings to reconstruct the
root, and verifies the Ed25519 signature against
`REGISTRY_PUBLIC_KEY_HEX` baked into `pokeupine/config.py`. Verification
is signature-only: the source PDF is never read, which makes
self-contained, air-gapped audit checks possible.

## How to Run the Project

### Prerequisites

- Python 3.11+
- `pip` and a virtual environment (recommended)

### Install

```bash
git clone <this-repo>
cd pokeupine_florentxlundaisociety
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Pull a regulation pack

```bash
pokeupine pull pci-dss        # fetches and verifies the signed pack
pokeupine pull gdpr           # second pack ships in the same registry
```

To run fully offline, point at the bundled registry:

```bash
export POKEUPINE_REGISTRY_URL="file://$PWD/pokeupine-registry"
pokeupine pull pci-dss
```

### Scan a codebase

```bash
pokeupine scan ./vulnerable-checkout                  # default pack: pci-dss
pokeupine scan ./vulnerable-checkout --pack gdpr      # any installed pack
pokeupine scan ./vulnerable-checkout --output json    # machine-readable output
pokeupine scan ./vulnerable-checkout --exit-code      # non-zero on failure
```

Example output against the bundled `vulnerable-checkout/` demo:

```
Scanning vulnerable-checkout  (1 pack: pci-dss@4.0.0)

  x PCI-DSS-3.3.1     Sensitive Authentication Data Not Stored After Authorization
      app.py:49   order.cvv  ->  order  ->  db.execute(...)
  x PCI-DSS-3.5.1     PAN is rendered unreadable anywhere it is stored
      app.py:49   order.card_number  ->  order  ->  db.execute(...)
  x PCI-DSS-4.2.1     Strong cryptography for PAN in transit over open networks
      app.py:53   requests call using cleartext HTTP: "http://internal-fraud-check/score"
  x PCI-DSS-10.2.1    Audit Logs Enabled for All System Components
      app.py:47   checkout route /checkout missing @audit_log decorator
  ? PCI-DSS-6.2.4     Software Engineering Techniques for Attack Prevention  (LLM-judge)
      SECURITY.md   LLM judge could not confirm SECURITY.md satisfies the control
  x PCI-DSS-8.3.6     Passwords/passphrases meet minimum complexity requirements
      app.py:43   min_length=8 in password validator (PCI-DSS-8.3.6 requires >=12)

  6 findings (5 failed, 1 uncertain)
```

### Inspect a control with proof

```bash
pokeupine explain PCI-DSS-3.3.1 --pack pci-dss
```

Prints the verbatim clause text together with Merkle proof and
signature verification marks.

### Verify a proof without the PDF

```bash
pokeupine prove PCI-DSS-3.3.1 --pack pci-dss --no-pdf
```

Recomputes the Merkle path and verifies the signed root in single-digit
milliseconds. The `--no-pdf` flag is a display hint that the source PDF
is not required for verification.

### Optional: enable the LLM judge

Set `POKEUPINE_LLM=1` and the appropriate `*_API_KEY` for your
[litellm](https://github.com/BerriAI/litellm) provider. Without these
the `llm_judge` engine emits an `uncertain` finding rather than
crashing.

### Build a new regulation pack

```bash
python -m ingestion.build_pack \
    --profile ingestion/profiles/<regulation>.json \
    --pdf path/to/regulation.pdf
```

The signed pack and updated `pokeupine-registry/index.json` are written
in place under `pokeupine-registry/packs/<id>/<version>/`. The output
location is taken from the profile's `registry_path`. Pass `--skip-llm`
to run the deterministic ingestion path from profile-defined control
entries when you want to avoid network calls.

### Run the test suite

```bash
.venv/bin/pytest -q
```

The suite is hermetic; it exercises every engine, the Merkle and
signature paths, and end-to-end scans against `vulnerable-checkout/`.

## License

Apache-2.0
