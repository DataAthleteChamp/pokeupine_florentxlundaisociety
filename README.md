# 🦔 Pokeupine

> Compliance-as-Code CLI with proof-carrying regulation packs.

**Pokeupine** scans your codebase against PCI-DSS — and unlike every vibe-coded scanner, every finding is backed by a **Merkle proof to the exact byte range in the official PDF**, and the dangerous ones come from a **dataflow analyzer that recognises Luhn-valid PANs as regulated sources**.

## Quick Start

```bash
pip install .
pokeupine pull pci-dss                   # fetches + verifies the signed pack
pokeupine scan ./your-project            # 5 deterministic + 1 LLM-judged finding
pokeupine explain PCI-DSS-3.3.1          # verbatim clause + ✓ Merkle proof
pokeupine prove   PCI-DSS-3.3.1 --no-pdf # verifies the chain WITHOUT the PDF
```

The `pull` command resolves the pack from the in-repo `pokeupine-registry/`
served via raw GitHub. Override the source with `POKEUPINE_REGISTRY_URL`
(supports `https://`, `file://`, and bare local paths) to run fully offline:

```bash
POKEUPINE_REGISTRY_URL="file:///path/to/pokeupine-registry" pokeupine pull pci-dss
```

## What It Does

```
$ pokeupine scan vulnerable-checkout/
Scanning vulnerable-checkout  (1 pack: pci-dss@4.0.0)

  ✗ PCI-DSS-3.3.1    Sensitive Authentication Data Not Stored After Authorization
      app.py:49   order.customer_email  →  order  →  db.execute(...)
  ✗ PCI-DSS-3.5.1    PAN is rendered unreadable anywhere it is stored
      app.py:49   order.customer_email  →  order  →  db.execute(...)
  ✗ PCI-DSS-4.2.1    Strong cryptography for PAN in transit over open, public networks
      app.py:53   requests call using cleartext HTTP: "http://internal-fraud-check/score"
  ✗ PCI-DSS-10.2.1   Audit Logs Enabled for All System Components
      app.py:47   checkout route /checkout missing @audit_log decorator
  ? PCI-DSS-6.2.4    Software Engineering Techniques for Attack Prevention  (LLM-judge, 50% confidence)
      SECURITY.md   LLM judge could not confirm SECURITY.md satisfies the control
  ✗ PCI-DSS-8.3.6    Passwords/passphrases meet minimum complexity requirements
      app.py:43   min_length=8 in password validator (PCI requires ≥12)

  6 findings (5 failed, 1 uncertain)
  Run pokeupine explain <id> for proof-backed evidence.
```

The dataflow engine also catches **Luhn-valid PAN literals** when they
flow into a storage sink, even with no Pydantic model in sight:

```
$ pokeupine scan ./has-pan-leak/
  ✗ PCI-DSS-3.5.1    PAN is rendered unreadable anywhere it is stored
      store.py:4   Luhn-valid PAN literal '411111...1111' → db.execute(...)
```

Set `POKEUPINE_LLM=1` (and the appropriate `*_API_KEY` for your litellm
provider) to make the LLM judge actually call out to a model. Without it
the engine degrades gracefully and emits an `uncertain` finding so the
demo never crashes.

## How It Works

### 1. Proof-Carrying Extraction (Moat M-1)
Every control in a regulation pack carries a `Provenance` object with:
- **SHA-256** of the source PDF and extracted text layer
- **Byte range** of the exact clause text in the extracted text
- **Merkle proof** from the clause leaf to a signed root hash
- **Ed25519 signature** over the Merkle root (hard-coded trust anchor)

`pokeupine prove` verifies this chain **without the PDF on disk**.

### 2. PAN-Typed Dataflow Analysis (Moat M-3 slice)
The dataflow engine uses **tree-sitter** to build intra-procedural def-use graphs:
- **Sources**: Pydantic fields matching regulated data patterns (PAN, CVV)
- **Sinks**: Database writes (`cursor.execute`), network calls (`requests.post`)
- **Sanitizers**: Tokenization functions (`tokenize()`, `mask_pan()`)

If tainted data reaches a sink without a sanitizer → **finding with the full path**.

## Architecture

```
PCI-DSS PDF → parse → chunk → LLM extract → Merkle tree → ed25519 sign → pack.json
                                                                              │
                                              pokeupine pull ← registry ──────┘
                                                    │
                                              pokeupine scan → engines → findings
                                                    │
                                              pokeupine explain → clause + ✓ proof
                                              pokeupine prove  → Merkle verification
```

## License

Apache-2.0
