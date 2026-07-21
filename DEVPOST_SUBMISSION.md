# ControlX — Devpost submission packet

> Copy-ready draft. Replace every `TODO` before submitting.

## Submission fields

- **Project name:** ControlX
- **Track:** Developer Tools
- **Tagline:** Find the delta. Prove the impact.
- **Repository:** `https://github.com/sftwrstef/ctrl-x`
- **Public YouTube demo:** https://youtu.be/VzguBCxDU9o
- **Codex `/feedback` session ID:** `TODO: run /feedback in the primary build task`
- **Feature commit:** `TODO: commit the ControlX rebrand; preserve 603e785696ff75733f86e8c1df91674787045e4d as the authenticated-replay feature commit`

## What it does

ControlX is a local-first proof console for authorized Web security research.
It turns an object-level authorization hunch into a bounded, inspectable test:
paste two DevTools **Copy as cURL** captures from isolated accounts you control,
preview the redacted request shape, and run a deterministic B→B, A→A, B→A
control matrix. The engine stops as soon as exposure is proved, repeats only a
denial, and writes a secret-free integrity-hashed receipt.

The result is deliberately narrow: **VERIFIED** only when Account B's isolated
session receives Account A's unique marker; **INVALID** only after both controls
pass and denial is stable; otherwise **INCONCLUSIVE**. Raw cookies, tokens,
URLs, object IDs, markers, and bodies stay ephemeral. An optional,
model-configurable AI reviewer can challenge the sanitized evidence, but it
cannot override the deterministic verdict or mark a live result ready for submission.

## Why it matters

Bug hunters lose time between seeing suspicious behavior and producing proof a
program can trust. Naive replay tools also make it easy to mix sessions, follow
redirects, over-test a target, or mistake a status code for impact. ControlX
builds the control experiment, safety boundary, and evidence receipt into one
workflow. It is designed for local labs, systems the researcher owns, and
explicitly authorized in-scope HackerOne, Bugcrowd, or Intigriti programs—not
for indiscriminate scanning.

## How Codex and GPT-5.6 were used

The pre-Dev-Week project was a local console with a disconnected Web engine.
Working in the primary Codex task with GPT-5.6 Sol, I chose the smallest
victim-centered extension and turned a hard-coded localhost IDOR proof into a
reusable authenticated capture-and-replay engine. Codex helped:

- design the structural cURL parser and ephemeral secret boundary;
- define the B→B, A→A, B→A counterfactual and stop conditions;
- implement exact-host validation, DNS pinning, redirect blocking, request and
  response limits, per-host pacing, and server-authoritative verdict gates;
- build the React proof workbench, vulnerable and secure fixtures, and
  write-once sanitized receipt; and
- challenge the implementation with false-positive, privacy, tamper, fixture,
  browser, build, and clean-install tests.

I made the product decision that AI may critique saved evidence but may never
manufacture proof. GPT-5.6 Sol accelerated the architecture, implementation,
security review, debugging, test design, interface, documentation, and demo
workflow. Runtime AI review is optional and model-configurable; it is never the
proof oracle.

## What changed during Dev Week

The eligible extension includes the live bounded Web engine, reviewed program
profiles, optional AI evidence review, persistent evidence/report workflow, verified
localhost proof, and the reusable authenticated replay engine. The exact
pre-existing boundary and dated work ledger are documented in
`PREEXISTING.md` and `DEV_WEEK_WORK.md`.

## Judge quick test

Tested on macOS Apple silicon with Node.js 25.9.0, npm 11.12.1, Python 3.14.4,
and a Chromium browser. The application runtime does not require an OpenAI API
key. AI review is optional and accepts any model available through the
operator's authenticated OpenCode setup.

```bash
git clone https://github.com/sftwrstef/ctrl-x.git controlx
cd controlx
npm ci
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
npm run dev
```

Open `http://127.0.0.1:5173`, then in another terminal run:

```bash
npm run fixture:replay:vulnerable
```

Choose **Local / owned target → Authenticated replay** and follow the printed
synthetic captures. No account, API key, or third-party target is needed. The
full click path and secure denial fixture are documented in `README.md`.

Verification commands:

```bash
npm run test:proof
npm run test:web
npm run build
npm audit --omit=dev
```

Final local verification receipt:

- Browser run: `b2784892-6cde-4bfd-a95d-33a30361327e`
- Replay receipt integrity: `1d8fc9daa17241f14aab0bcb6c3e7e70ef9c132bd325860d587db6dce1857bff`
- Recorded optional-AI test session: `ses_07a422d7effeOrvAhxlSlRA9B8`
- Narrated MP4: 79.23 seconds, H.264/AAC, SHA-256
  `e6c3ab62f9032ee34b0a674d127bd896f893aab51c79080147d95a5360ed1c5a`
- Clean-source verification: 32/32 proof tests, 6/6 Web-engine tests,
  production build pass, and zero production dependency vulnerabilities.

## Final submission gate

- [x] Commit and push the tested checkout; feature commit recorded above.
- [x] Publish the repository under the MIT License.
- [x] Verify the public feature commit from a clean clone: fresh dependencies,
      32/32 proof tests, 6/6 Web tests, and production build all pass.
- [x] Upload the narrated MP4 as a public YouTube video and paste the URL.
- [ ] Run `/feedback` in the primary build task and paste its session ID.
- [ ] Confirm public playback, repository access, README setup, and all Devpost
      fields before submitting.
