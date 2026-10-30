# ScamOrNot

**Paste it. Check it. Before you pay, send, or click.**

Live: https://scamornot-app.netlify.app

ScamOrNot is a free, privacy-first scam checker. Paste any suspicious **message, link, or wallet address** and get a risk score (0–100) with every red flag explained in plain English, plus what to do next.

## Why it exists

Global scam losses exceed $1 trillion a year. The scripts — advance-fee prizes, pig-butchering "mentors," fake parcels, task-job scams, phishing links wearing real brands' names — all depend on one thing: the victim acting inside the moment of doubt. ScamOrNot is built for that exact moment. One job, done well.

## How it works

- 100% client-side: `engine.js` runs entirely in the browser. Nothing pasted is uploaded or stored.
- 15 fraud-pattern families (seed/credential theft, advance fee, giveaway doubling, pig-butchering, job scams, prize/lottery, parcel/customs, payment red flags, authority impersonation, urgency, secrecy, free-email impersonation, verify bait, romance) with weighted scoring.
- Structural URL analysis: brand impersonation domains, punycode, IP hosts, @-trick, shorteners, abused TLDs, http login pages.
- Wallet-address format checks with honest guidance (a valid format never proves a deal is real).
- Protective-framing guard so security-education text ("never share your seed phrase") is not flagged as theft.

Calibration (launch tests): real scam scripts score 45–70; legitimate messages, real brand domains, genuine bank SMS and security articles score 0.

## Pricing

Free: 3 checks/day, no sign-up. Pro: $9/month (unlimited) — USDC on Base. Teams: $29/month.

## Honest limits

Pattern-based and educational — not a guarantee, and not a substitute for your bank, exchange, or law enforcement. A clean result means no strong patterns were detected, not that something is certainly safe.

## Files

- `index.html` — the app (UI + free-tier counter + Pro unlock)
- `engine.js` — the analysis engine (also loadable in Node for testing)

Built by [NenzyBrown](https://nenzybrown.netlify.app) (Dubai), founder of [ProofReceipt](https://proofreceipt.netlify.app).
