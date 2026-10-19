"""Real-time fraud model for instant payments, and how attackers evade it.

Trains a gradient-boosted classifier on synthetic transactions containing
authorised push payment (APP) scams and mule-account activity, then measures
how much detection drops when fraudsters change behaviour to look normal,
and how much adversarial training recovers.
"""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import roc_curve

FEATURES = [
    "log_amount",            # size of the payment
    "amount_vs_median",      # amount relative to this payer's usual payment
    "hour",                  # local hour sent
    "payee_age_days",        # how long the payer has paid this payee
    "payer_txn_24h",         # payer's payments in the last 24h
    "payee_inbound_24h",     # payments received by the payee account in 24h (mule fan-in)
    "new_device",            # sent from a device not seen before
    "payee_account_age_days" # how long the receiving account has existed
]


def _legit(rng, n):
    amt = rng.lognormal(5.0, 1.0, n)
    new_payee = rng.random(n) < 0.15          # customers pay new people all the time
    busy_payee = rng.random(n) < 0.10         # merchants and landlords receive many payments
    young_acct = rng.random(n) < 0.06         # some genuine accounts are new too
    return np.column_stack([
        np.log1p(amt),
        rng.lognormal(0, 0.6, n),
        np.clip(rng.normal(13, 4, n), 0, 23).round(),
        np.where(new_payee, rng.uniform(0, 10, n), rng.exponential(300, n)),
        rng.poisson(1.5, n),
        np.where(busy_payee, rng.poisson(15, n), rng.poisson(2, n)),
        rng.random(n) < 0.08,
        np.where(young_acct, rng.exponential(60, n) + 1, rng.exponential(1500, n) + 30),
    ])


def _fraud(rng, n):
    amt = rng.lognormal(6.2, 1.0, n)
    return np.column_stack([
        np.log1p(amt),
        rng.lognormal(0.9, 0.7, n),
        np.where(rng.random(n) < 0.4, rng.integers(0, 6, n), rng.integers(8, 22, n)),
        rng.exponential(3, n),            # usually a brand-new payee
        rng.poisson(2.5, n),
        rng.poisson(7, n),                # mule account receiving from many victims
        rng.random(n) < 0.35,
        rng.exponential(60, n) + 1,       # usually a recently opened account
    ])


def make_data(seed=11, n_legit=40_000, n_fraud=800):
    rng = np.random.default_rng(seed)
    X = np.vstack([_legit(rng, n_legit), _fraud(rng, n_fraud)]).astype(float)
    y = np.r_[np.zeros(n_legit), np.ones(n_fraud)]
    idx = rng.permutation(len(y))
    return X[idx], y[idx]


# ---- Evasion strategies: what a fraudster changes to look like a normal customer ----

def evade(X, strategy, rng):
    X = X.copy()
    if strategy == "split_amounts":         # break one large payment into several small ones
        k = rng.integers(3, 6, len(X))
        X[:, 0] = np.log1p(np.expm1(X[:, 0]) / k)
        X[:, 1] = X[:, 1] / k
        X[:, 4] = X[:, 4] + k               # but velocity goes up
    elif strategy == "business_hours":      # send during normal hours
        X[:, 2] = rng.integers(9, 17, len(X))
    elif strategy == "aged_mule_accounts":  # buy older accounts and spread victims across more mules
        X[:, 7] = rng.exponential(900, len(X)) + 200
        X[:, 5] = rng.poisson(2.5, len(X))
    elif strategy == "warm_up_payee":       # small test payments first so the payee isn't new
        X[:, 3] = rng.exponential(60, len(X)) + 14
        X[:, 6] = rng.random(len(X)) < 0.08
    elif strategy == "combined":
        for s in ("split_amounts", "business_hours", "aged_mule_accounts", "warm_up_payee"):
            X = evade(X, s, rng)
    return X


STRATEGIES = {
    "none": "No evasion",
    "split_amounts": "Split amounts",
    "business_hours": "Business hours",
    "warm_up_payee": "Warm up payee",
    "aged_mule_accounts": "Aged mule accounts",
    "combined": "All combined",
}


def _threshold_at_fpr(model, X, y, fpr_target=0.01):
    fpr, _, thr = roc_curve(y, model.predict_proba(X)[:, 1])
    return thr[np.searchsorted(fpr, fpr_target, side="right") - 1]


def run(seed=11):
    rng = np.random.default_rng(seed + 1)
    X, y = make_data(seed)
    cut = int(0.7 * len(y))
    Xtr, ytr, Xte, yte = X[:cut], y[:cut], X[cut:], y[cut:]

    def fit(Xa, ya):
        return HistGradientBoostingClassifier(max_iter=200, learning_rate=0.08, random_state=seed).fit(Xa, ya)

    base = fit(Xtr, ytr)
    # Adversarial training: add evaded copies of the training fraud (half the strategies only,
    # so we can see whether it generalises to tactics it never saw).
    fr = Xtr[ytr == 1]
    seen = ["split_amounts", "aged_mule_accounts"]
    aug = np.vstack([evade(fr, s, rng) for s in seen])
    hard = fit(np.vstack([Xtr, aug]), np.r_[ytr, np.ones(len(aug))])

    legit_te = Xte[yte == 0]
    fraud_te = Xte[yte == 1]
    out = {"operating_point": "1% of legitimate payments flagged",
           "n_test_legit": int(len(legit_te)), "n_test_fraud": int(len(fraud_te)),
           "adversarial_training_seen": [STRATEGIES[s] for s in seen], "rows": []}
    for name, model in (("baseline", base), ("adversarially_trained", hard)):
        thr = _threshold_at_fpr(model, Xte, yte)
        out[f"{name}_threshold"] = float(thr)
        for s, label in STRATEGIES.items():
            Xf = evade(fraud_te, s, np.random.default_rng(seed + 99)) if s != "none" else fraud_te
            recall = float((model.predict_proba(Xf)[:, 1] >= thr).mean())
            out["rows"].append({"model": name, "strategy": s, "label": label,
                                "detection_rate": round(recall, 4),
                                "seen_in_training": s in seen})
        out[f"{name}_false_positive_rate"] = round(float((model.predict_proba(legit_te)[:, 1] >= thr).mean()), 4)
    return out
