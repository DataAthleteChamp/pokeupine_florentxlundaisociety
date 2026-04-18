# vulnerable-checkout — PCI-DSS Demo Target
#
# A deliberately vulnerable 60-line FastAPI checkout app
# with 6 seeded PCI-DSS v4.0 violations.
#
# Violations:
#   1. PCI-DSS-3.3.1  Order.cvv stored in DB (SAD retention)
#   2. PCI-DSS-3.5.1  Order.card_number stored without tokenization
#   3. PCI-DSS-4.2.1  requests.post over cleartext HTTP
#   4. PCI-DSS-8.3.6  min_length=8 in password validator (needs ≥12)
#   5. PCI-DSS-10.2.1 /checkout route missing @audit_log
#   6. PCI-DSS-6.2.4  No SECURITY.md describing SAST in CI
#
# DO NOT FIX THESE — they are intentional for the demo.

from fastapi import FastAPI
from pydantic import BaseModel
import logging
import sqlite3
import requests

app = FastAPI()
log = logging.getLogger("checkout")
db = sqlite3.connect("orders.db")


def audit_log(func):
    """Decorator that logs access for audit trail compliance."""
    def wrapper(*args, **kwargs):
        log.info(f"AUDIT: {func.__name__} called")
        return func(*args, **kwargs)
    return wrapper


class Order(BaseModel):
    customer_email: str
    card_number: str        # PAN — must be tokenized     (3.5.1)
    cvv: str                # SAD — must NEVER be stored   (3.3.1)
    amount_cents: int


class PasswordPolicy(BaseModel):
    min_length: int = 8     # PCI 8.3.6 requires ≥ 12     (8.3.6)


@app.post("/checkout")       # missing @audit_log           (10.2.1)
def checkout(order: Order):
    log.info(f"processing order {order}")  # PAN+CVV in log (3.5.1, 3.3.1)
    db.execute(
        "INSERT INTO orders VALUES (?,?,?,?)",
        (order.customer_email, order.card_number, order.cvv, order.amount_cents),
    )                                       # PAN+CVV at rest (3.5.1, 3.3.1)
    requests.post(
        "http://internal-fraud-check/score",  # cleartext HTTP  (4.2.1)
        json=order.dict(),
    )
    return {"ok": True}


@app.get("/health")
@audit_log
def health():
    return {"status": "healthy"}
