# Securing AI agents on instant-payment rails

**A proof of concept on AI security for fast payment systems.**

Instant payment systems such as PIX, UPI and FedNow settle in seconds and cannot be reversed. Central banks across the Caribbean, Latin America and beyond are building their own. At the same time, businesses are starting to let AI assistants pay invoices for them.

This PoC asks two questions:

1. **If an AI payment agent reads a fraudster's instructions hidden in a payment message, which defences actually stop the money from leaving?**
2. **If fraudsters change their behaviour, how much does a real-time fraud model miss, and does adversarial training help?**

**[View the interactive dashboard →](https://YOUR-USERNAME.github.io/fps-ai-security-poc/)**

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/YOUR-USERNAME/fps-ai-security-poc/blob/main/notebooks/fps_ai_security_poc.ipynb)

> v0.1 uses synthetic data and a simulated agent. See [Limits](#limits) before citing any number.

## Part 1: Prompt injection through payment messages

The agent processes supplier invoices and sends instant payments. The fraudster controls only the free text: the ISO 20022 remittance field (`RmtInf/Ustrd`) or an invoice note. Six techniques are tested, each with several phrasings, from textbook injections to wording that reads like a normal supplier email:

| Technique | What it does |
|---|---|
| Direct override | Tells the agent to ignore its task and pay a new account |
| Bank-detail change | Classic invoice fraud: "our bank details have changed" |
| Authority impersonation | Claims CFO or compliance approval |
| Amount inflation | Keeps the real payee but adds "arrears and fees" |
| Encoded payload | Base64-encoded instruction |
| Unicode smuggling | Zero-width characters and look-alike letters |

In 20% of bank-detail-change attacks, the fraudster has already had the supplier's record changed through a separate call or email (vendor-master fraud).

Four defence layers, measured alone and stacked:

| Layer | What it does |
|---|---|
| D1 Injection screen | Normalises hidden characters and flags instruction-like or encoded text before the agent reads it |
| D2 Policy as code | Checks the agent's **output** against the business's own beneficiary records and invoice amount. It never reads the attacker's text. |
| D3 Confirmation of Payee | Compares the expected payee name with the real account holder |
| D4 Human hold | Routes flagged and large-value payments to a reviewer |

**Results (v0.1, 4,000 genuine payments, 1,200 attacks):**

| Defence stack | Attacks that moved money | Losses | Genuine payments held |
|---|---:|---:|---:|
| No defences | 38.4% | $567,911 | 0.0% |
| Injection screen only | 15.5% | $283,086 | 4.6% |
| Confirmation of Payee only | 7.8% | $290,367 | 0.0% |
| Policy as code only | 1.6% | $18,521 | 0.0% |
| Screen + CoP + Policy | 0.0% | $0 | 4.6% |
| All four layers | 0.0% | $0 | 5.2% |

## Part 2: Evading the real-time fraud model

A gradient-boosted classifier detects authorised push payment (APP) scams and mule-account activity. It is tuned so that 1% of genuine payments are flagged. Fraudsters then change one behaviour at a time.

| Evasion strategy | Baseline model | Adversarially trained |
|---|---:|---:|
| No evasion | 99.2% | 97.6% |
| Split amounts * | 93.3% | 99.6% |
| Business hours | 98.0% | 94.8% |
| Warm up payee | 15.1% | 7.5% |
| Aged mule accounts * | 12.3% | 77.8% |
| All combined | 0.0% | 5.6% |

\* used in adversarial training

## What this shows

- **Text filters are not enough.** The injection screen cut successful attacks by more than half but missed phrasing that sounds like an ordinary supplier email, and it delayed genuine payments whose wording looked suspicious.
- **Deterministic checks outside the model do the heavy lifting.** Policy as code cannot be persuaded because it never reads the attacker's text. Its weak point is the record it checks against.
- **Layers cover each other's gaps.** Confirmation of Payee catches poisoned records but not inflated amounts; policy catches inflated amounts but not poisoned records.
- **Fraud models learn shortcuts.** The model leaned on "new payee" and "new account" signals. Adversarial training recovered the tactics it was trained on but did not generalise to tactics it never saw.

## Limits

- **The agent is simulated.** It follows each injection technique at an assumed rate (see `poc/agent.py`), not a rate measured on a real model. The defence layers, policy checks and fraud model are real code; the agent's gullibility is not.
- **Other assumptions:** a human reviewer stops 85% of held attacks; holds delay a payment by 30 minutes on average.
- **All data are synthetic.** No real people, accounts or institutions. Account numbers use an obviously fake `SIM..FPS..` format.
- **Zero is not zero.** No successes in 1,200 attacks means the true rate is likely below about 0.25% (rule of three), not that it is impossible.
- The pacs.008 message is trimmed for illustration and is not schema-complete.

## Roadmap

- [ ] Replace the simulated agent with real LLM agents behind the same `decide()` interface and measure actual susceptibility per technique
- [ ] Add model-based injection classifiers alongside the pattern screen
- [ ] Test registry-poisoning defences (out-of-band verification of bank-detail changes)
- [ ] Multi-seed runs with confidence intervals
- [ ] Scenarios for specific rails (PIX, UPI) and Caribbean fast payment systems

## Run it

The easiest way is the Colab notebook (badge above): Runtime → Run all. To run the scripts instead:

```bash
pip install -r requirements.txt
python poc/run.py          # writes docs/data/results.json
```

Then open `docs/index.html`. The GitHub Action in `.github/workflows/pages.yml` also runs the simulation and republishes the dashboard on every push.

## Repository layout

```
poc/
  payments.py      synthetic payment requests and pacs.008 rendering
  attacks.py       six injection techniques
  agent.py         the agent under test (simulated in v0.1)
  defences.py      D1 to D3; D4 is applied in run.py
  fraud_model.py   fraud classifier, evasion strategies, adversarial training
  run.py           runs everything and writes the results
notebooks/
  fps_ai_security_poc.ipynb   the same PoC as a walkthrough notebook for Google Colab
docs/
  index.html       the dashboard (GitHub Pages)
  data/            generated results
```

## Author

[Judith Ann Sarjeant](https://www.linkedin.com/in/judith-sarjeant-a9b629a3), cloud and AI security leader in Caribbean financial services.

## License

MIT
