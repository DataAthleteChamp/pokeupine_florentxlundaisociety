# 🦔 Pokeupine

> Compliance-as-Code CLI with proof-carrying regulation packs.

**Pokeupine** scans your codebase against PCI-DSS — and unlike every vibe-coded scanner, every finding is backed by a **Merkle proof to the exact byte range in the official PDF**, and the dangerous ones come from a **dataflow analyzer that recognises Luhn-valid PANs as regulated sources**.

## Quick Start

```bash
pip install .
pokeupine pull pci-dss
pokeupine scan ./your-project
pokeupine explain PCI-DSS-3.3.1
pokeupine prove PCI-DSS-3.3.1 --no-pdf
```

## What It Does

```
$ pokeupine scan vulnerable-checkout/
Scanning vulnerable-checkout/  (1 pack: pci-dss@4.0.0)

  ✗ PCI-DSS-3.3.1 [critical]   Sensitive Authentication Data must not be stored
      app.py:51   Order.cvv  →  order  →  db.execute(...)
  ✗ PCI-DSS-3.5.1 [critical]   PAN must be rendered unreadable at rest
      app.py:51   Order.card_number  →  order  →  db.execute(...)
  ✗ PCI-DSS-4.2.1 [high]       Strong cryptography for PAN in transit
      app.py:54   requests.post("http://internal-fraud-check/...")
  ✗ PCI-DSS-10.2.1 [high]      Audit logs required for components touching CHD
      app.py:48   checkout /checkout missing @audit_log decorator
  ✗ PCI-DSS-8.3.6 [medium]     Passwords ≥ 12 characters
      app.py:45   min_length=8 in password validator
  ? PCI-DSS-6.2.4 [medium]     SAST in CI for custom code  (LLM-judge, 60% confidence)
      no SECURITY.md found describing code review process

6 findings.  Run `pokeupine explain <id>` for proof-backed evidence.
```

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
