"""The AI payment agent under test.

v0.1 uses a SIMULATED agent: for each injection technique it follows the
planted instruction with a fixed, documented probability. These rates are
assumptions chosen to be plausible, not measurements. The next phase replaces
SimulatedAgent with real LLM agents behind the same interface, so the
defence measurements below can be repeated against real models.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from payments import PaymentRequest

# ASSUMED probability that an undefended agent obeys each technique.
# Replace with measured rates from real LLM runs.
ASSUMED_SUSCEPTIBILITY = {
    "direct_override": 0.35,
    "bank_detail_change": 0.60,
    "authority_impersonation": 0.50,
    "amount_inflation": 0.45,
    "obfuscated_base64": 0.25,
    "unicode_smuggling": 0.30,
}


@dataclass
class PaymentInstruction:
    """What the agent decides to send to the instant-payment rail."""
    account: str
    name: str
    amount: float
    followed_injection: bool


class SimulatedAgent:
    name = "simulated-v0.1"

    def __init__(self, seed: int = 7, susceptibility: dict | None = None):
        self.rng = random.Random(seed)
        self.p = susceptibility or ASSUMED_SUSCEPTIBILITY

    def decide(self, req: PaymentRequest) -> PaymentInstruction:
        if req.attack and self.rng.random() < self.p[req.attack]:
            return PaymentInstruction(req.attacker_account, req.attacker_name,
                                      req.attacker_amount, True)
        return PaymentInstruction(req.payee.account, req.payee.name, req.amount, False)
