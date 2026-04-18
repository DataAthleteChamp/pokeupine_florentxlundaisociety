# vulnerable-checkout

A deliberately vulnerable FastAPI checkout app with **6 seeded PCI-DSS v4.0 violations**.

This is the demo target for [Pokeupine](../README.md) — a compliance-as-code CLI.

## Seeded Violations

| # | PCI-DSS Clause | What's Wrong | Line |
|---|----------------|-------------|------|
| 1 | 3.3.1 | `Order.cvv` stored in DB — SAD must never be retained | 51 |
| 2 | 3.5.1 | `Order.card_number` stored without tokenization | 51 |
| 3 | 4.2.1 | `requests.post("http://...")` — cleartext HTTP for PAN | 54 |
| 4 | 8.3.6 | `min_length=8` — passwords must be ≥12 chars | 45 |
| 5 | 10.2.1 | `/checkout` missing `@audit_log` decorator | 48 |
| 6 | 6.2.4 | No `SECURITY.md` describing code review process | — |

## Usage

```bash
pokeupine scan vulnerable-checkout/
```

**DO NOT FIX** these violations — they are intentional for the demo.
