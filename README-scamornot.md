# ScamOrNot

**Paste it. Check it. Before you pay, send, or click.**

**Live app: https://scamornot-app.netlify.app**

Got a message, job offer, investment pitch, delivery text or link that feels off? Paste it into ScamOrNot and get a risk score (0–100) with every red flag explained in plain English — in seconds, with no sign-up. Nothing you paste ever leaves your browser.

---

## What it does

- **Three ways in:** check a **message** (WhatsApp chat, email, SMS, job offer, pitch), a **link** (the full URL), or a **wallet address** (the one you were asked to send money to).
- **A score you can act on:** a 0–100 risk dial with a plain verdict — from "no strong patterns found" up to "multiple heavy fraud patterns, do not send money, codes or documents."
- **Receipts, not vibes:** every flag names the pattern, explains *why* it's a warning sign in normal words, and shows the exact snippet from your paste that triggered it. You also get a short "what to do" list and, when they exist, the reassuring signs.
- **One-tap examples:** built-in samples (a "friendly trading mentor," a prize-with-a-fee, a held-parcel text, a fake bank link, and an ordinary message) so you can watch it think before trusting it with anything real.
- **Copyable summary:** one click copies the result, so you can warn the group chat or family member who forwarded the thing to you.

## How it works

ScamOrNot is a pattern checker, not an AI oracle and not a database lookup. The engine (`engine.js`) runs a weighted rule library against your text, URL or address:

- **15 fraud-pattern families** for messages — seed-phrase / credential theft, advance fees, giveaway doubling ("send 0.1, get 0.2 back"), pig-butchering scripts, fake-job and task scams, prize/lottery lures, parcel and customs fees, payment-method red flags, authority impersonation, urgency and secrecy pressure, free-email impersonation, "verify your wallet" bait, romance openers, and more.
- **Structural URL analysis** — lookalike brand domains (the real brand list covers PayPal, Binance, Coinbase, Apple, Amazon, major banks, Aramex, DHL and others), punycode, IP-address hosts, the `@` trick, known shorteners, abused TLDs, and login pages served over plain HTTP.
- **Wallet-address checks** — format validation for common address types, with honest guidance: a correctly formatted address proves nothing about the deal behind it.
- **A protective-framing guard** — security education ("never share your seed phrase") is not flagged as seed theft. Context matters; the engine reads for it.

Scoring is calibrated so real scam scripts land roughly in the 45–70 band while legitimate messages, real brand domains, genuine bank texts and security articles score 0. Weights are visible in the engine source — read them, argue with them, open an issue.

**Privacy is architectural, not a policy page.** The app is a static page. The analysis runs 100% client-side, nothing is uploaded or logged, and the free-tier counter lives in your own browser's local storage. There is no server to breach because there is no server.

## Pricing

| Tier | Price | What you get |
|---|---|---|
| Free | $0 | 3 checks every day · full red-flag breakdown · message, link & address checks · no account, no tracking |
| Pro | $9/month | Unlimited checks · priority pattern updates as new scams spread · for people who screen offers, gigs and deals daily |
| Teams & Communities | $29/month | Everything in Pro · access codes for up to 10 members · built for trading groups, freelancer communities and family chats |

Pro and Teams are paid in **USDC on Base**. You send payment, then send your transaction hash to the Telegram assistant **@NenzyBrownAssistantBot** (`/order`) or by email, and your access code (format `SON-PRO-XXXX`) arrives within 24 hours. The code unlocks Pro on your device — no account is created.

## Tech

- Static, in-browser app: one `index.html` (UI, free-tier counter, Pro unlock) plus a dependency-free `engine.js` that also loads in Node for testing.
- No backend, no database, no analytics on what you paste, no build step. Deployable to any static host (the live app runs on Netlify).
- Pattern library and scoring weights live entirely in `engine.js` — small enough to audit in one sitting, which is deliberate.

```
index.html   the app
engine.js    the analysis engine (browser + Node)
logo-480.png brand asset
```

## Honest limits

ScamOrNot is an educational pattern-checking tool. It is not a guarantee, not a financial, legal or security authority, and not a substitute for your bank, your exchange or law enforcement. Scammers change tactics constantly; a message can be dangerous without matching a known pattern, and a clean result means *no strong patterns were detected* — not that something is certainly safe. If money is involved and anything feels wrong, pause and verify through the official app or the number on your card. That pause is the real protection; this tool just makes it easier to take.

## Status

Live and early. ScamOrNot is **pre-revenue with $0 in sales so far** — Pro exists and works, and nobody has bought it yet. It was built in Dubai by [NenzyBrown](https://nenzybrown.netlify.app), founder of [ProofReceipt](https://proofreceipt.netlify.app), out of forensic casework on scam wallet files that had been sold to hopeful buyers. Missed-pattern reports are the most valuable feedback there is: if a scam scores low, that is a bug report worth filing.

Sister tool: [SignSafe](https://signsafe-app.netlify.app) — the same idea for the signature layer. ScamOrNot checks the message; SignSafe checks what you're about to sign.

---

*MIT-style footer placeholder — replace with the final licence text before publishing this README to a public repo. Suggested interim line: "Released under the MIT License — © 2026 Nenzy Brown. The live service at scamornot-app.netlify.app is operated by the author; this licence covers the code in this repository only."*
