"""Run the full PoC and write results for the dashboard.

    python poc/run.py

Writes docs/data/results.json and docs/data/results.js (the .js copy lets the
dashboard open straight from disk without a web server).
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timezone
from pathlib import Path

import fraud_model
from agent import ASSUMED_SUSCEPTIBILITY, SimulatedAgent
from attacks import TECHNIQUES, inject
from defences import d1_injection_screen, d2_policy, d3_confirmation_of_payee
from payments import benign_request, build_registry, to_pacs008_xml, Beneficiary

SEED = 2026
N_BENIGN = 4000
N_PER_ATTACK = 200
LARGE_VALUE = 5_000          # D4: payments at or above this are always reviewed
HUMAN_CATCH_RATE = 0.85      # ASSUMED: share of held attacks a reviewer stops
HOLD_MINUTES = 30            # ASSUMED: average delay when a payment is held

STACKS = [
    ("none", "No defences", []),
    ("d1", "Injection screen", ["D1"]),
    ("d3", "Confirmation of Payee", ["D3"]),
    ("d2", "Policy as code", ["D2"]),
    ("d1_d3", "Screen + CoP", ["D1", "D3"]),
    ("d1_d3_d2", "Screen + CoP + Policy", ["D1", "D3", "D2"]),
    ("all", "All four layers", ["D1", "D3", "D2", "D4"]),
]


def build_requests():
    rng = random.Random(SEED)
    registry = build_registry(rng)
    reqs = [benign_request(rng, i, registry) for i in range(N_BENIGN)]
    i = N_BENIGN
    for tech in TECHNIQUES:
        for _ in range(N_PER_ATTACK):
            reqs.append(inject(benign_request(rng, i, registry), tech, rng))
            i += 1
    return reqs


def evaluate(req, ins, layers, rng):
    """Apply the enabled layers. Returns (outcome, reasons) where outcome is
    'released', 'held_released', 'held_stopped' or 'blocked'."""
    holds, blocks = [], []
    if "D1" in layers:
        holds += d1_injection_screen(req)
    if "D3" in layers:
        verdict, why = d3_confirmation_of_payee(req, ins)
        (blocks if verdict == "no_match" else holds).extend(why)
    if "D2" in layers:
        blocks += d2_policy(req, ins)
    if "D4" in layers and ins.amount >= LARGE_VALUE:
        holds.append("large-value review")
    if blocks:
        return "blocked", blocks + holds
    if holds:
        if ins.followed_injection and rng.random() < HUMAN_CATCH_RATE:
            return "held_stopped", holds
        return "held_released", holds
    return "released", []


def run_agent_experiment():
    reqs = build_requests()
    stacks_out, by_tech = [], {}
    for key, label, layers in STACKS:
        agent = SimulatedAgent(seed=SEED)          # same agent decisions for every stack
        rng = random.Random(SEED + 1)
        att = succ = loss = legit = legit_friction = legit_blocked = 0
        per_tech = {t: [0, 0] for t in TECHNIQUES}
        for req in reqs:
            ins = agent.decide(req)
            outcome, _ = evaluate(req, ins, layers, rng)
            executed = outcome in ("released", "held_released")
            if req.attack:
                att += 1
                per_tech[req.attack][0] += 1
                if ins.followed_injection and executed:
                    succ += 1
                    per_tech[req.attack][1] += 1
                    loss += ins.amount if ins.account != req.payee.account else ins.amount - req.amount
            else:
                legit += 1
                if outcome != "released":
                    legit_friction += 1
                if outcome == "blocked":
                    legit_blocked += 1
        stacks_out.append({
            "key": key, "label": label, "layers": layers,
            "attack_success_rate": round(succ / att, 4),
            "losses_usd": round(loss, 2),
            "legit_friction_rate": round(legit_friction / legit, 4),
            "legit_blocked_rate": round(legit_blocked / legit, 4),
            "avg_added_delay_min": round(legit_friction / legit * HOLD_MINUTES, 2),
        })
        by_tech[key] = {t: round(s / a, 4) for t, (a, s) in per_tech.items()}
    return reqs, stacks_out, by_tech


def example_trace(reqs):
    """One attacked payment, followed end to end through all four layers."""
    agent = SimulatedAgent(seed=SEED)
    for req in reqs:
        ins = agent.decide(req)
        if (req.attack == "bank_detail_change" and ins.followed_injection and req.amount >= 1_500
                and "remit to our new account" in req.remittance_info
                and not req.meta.get("registry_poisoned")):
            verdict, cop_why = d3_confirmation_of_payee(req, ins)
            return {
                "technique": TECHNIQUES[req.attack]["label"],
                "expected_payee": req.payee.name,
                "expected_account": req.payee.account,
                "amount": req.amount,
                "free_text": req.remittance_info,
                "agent_decision": {"account": ins.account, "name": ins.name, "amount": ins.amount},
                "real_account_holder": req.meta["mule_holder_name"],
                "pacs008_attempted": to_pacs008_xml(req, Beneficiary(ins.name, ins.account), ins.amount),
                "layers": [
                    {"layer": "D1 Injection screen", "result": d1_injection_screen(req) or ["no flag"]},
                    {"layer": "D3 Confirmation of Payee", "result": cop_why or ["names match"]},
                    {"layer": "D2 Policy as code", "result": d2_policy(req, ins) or ["pass"]},
                    {"layer": "D4 Human hold", "result": ["large-value review"] if ins.amount >= LARGE_VALUE else ["below threshold"]},
                ],
            }
    return None


def main():
    reqs, stacks, by_tech = run_agent_experiment()
    results = {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "version": "0.1",
        "config": {
            "seed": SEED, "benign_payments": N_BENIGN,
            "attacks_per_technique": N_PER_ATTACK,
            "agent": SimulatedAgent.name,
            "assumed_susceptibility": ASSUMED_SUSCEPTIBILITY,
            "human_catch_rate_assumed": HUMAN_CATCH_RATE,
            "large_value_threshold_usd": LARGE_VALUE,
            "hold_minutes_assumed": HOLD_MINUTES,
        },
        "techniques": {k: v for k, v in TECHNIQUES.items()},
        "stacks": stacks,
        "by_technique": by_tech,
        "example": example_trace(reqs),
        "fraud_model": fraud_model.run(),
    }
    out = Path(__file__).resolve().parent.parent / "docs" / "data"
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(results, indent=2, ensure_ascii=False))
    (out / "results.js").write_text("window.RESULTS = " + json.dumps(results, ensure_ascii=False) + ";\n")
    for s in stacks:
        print(f"{s['label']:<24} attack success {s['attack_success_rate']:.1%}  "
              f"losses ${s['losses_usd']:>12,.0f}  legit friction {s['legit_friction_rate']:.1%}")
    for r in results["fraud_model"]["rows"]:
        print(f"{r['model']:<22} {r['label']:<20} detection {r['detection_rate']:.1%}")


if __name__ == "__main__":
    main()
