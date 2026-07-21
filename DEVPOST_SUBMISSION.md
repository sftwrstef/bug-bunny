# Bug Bunny — Devpost submission packet

> Copy-ready draft. Replace every `TODO` before submitting.

## Submission fields

- **Project name:** Bug Bunny
- **Track:** Developer Tools
- **Tagline:** Capture the request. Replay the claim. Preserve the proof.
- **Repository:** `https://github.com/sftwrstef/bug-bunny`
- **Public YouTube demo:** `TODO: upload output/demo/bug-bunny-authenticated-replay-demo.mp4`
- **Codex `/feedback` session ID:** `TODO: run /feedback in the primary build task`
- **Feature commit:** `TODO: final pushed commit SHA`

## What it does

Bug Bunny is a local-first proof console for authorized Web security research.
It turns an object-level authorization hunch into a bounded, inspectable test:
paste two DevTools **Copy as cURL** captures from isolated accounts you control,
preview the redacted request shape, and run a deterministic B→B, A→A, B→A
control matrix. The engine stops as soon as exposure is proved, repeats only a
denial, and writes a secret-free integrity-hashed receipt.

The result is deliberately narrow: **VERIFIED** only when Account B's isolated
session receives Account A's unique marker; **INVALID** only after both controls
pass and denial is stable; otherwise **INCONCLUSIVE**. Raw cookies, tokens,
URLs, object IDs, markers, and bodies stay ephemeral. A separate Kimi K3 stage
can challenge the sanitized evidence, but it cannot override the deterministic
verdict or mark a live result ready for submission.

## Why it matters

Bug hunters lose time between seeing suspicious behavior and producing proof a
program can trust. Naive replay tools also make it easy to mix sessions, follow
redirects, over-test a target, or mistake a status code for impact. Bug Bunny
builds the control experiment, safety boundary, and evidence receipt into one
workflow. It is designed for researchers using reviewed HackerOne, Bugcrowd,
or Intigriti programs—not for indiscriminate scanning.

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
workflow. Kimi K3 is an optional runtime evidence challenger, not the proof
oracle.

## What changed during Dev Week

The eligible extension includes the live bounded Web engine, reviewed program
profiles, Kimi evidence triage, persistent evidence/report workflow, verified
localhost proof, and the reusable authenticated replay engine. The exact
pre-existing boundary and dated work ledger are documented in
`PREEXISTING.md` and `DEV_WEEK_WORK.md`.

## Judge quick test

Tested on macOS Apple silicon with Node.js 25.9.0, npm 11.12.1, Python 3.14.4,
and a Chromium browser. The application runtime does not require an OpenAI API
key. Kimi analysis is optional and requires an authenticated OpenCode Go setup.

```bash
git clone TODO_FINAL_REPOSITORY_URL
cd bug-bunny
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
- Kimi challenge session: `ses_07a422d7effeOrvAhxlSlRA9B8`
- Narrated MP4: 78.68 seconds, H.264/AAC, SHA-256
  `10c02c5777e03f9f9457fd910d80b8c86570cbaca52592400d25292b301ed99b`
- Clean-source verification: 32/32 proof tests, 6/6 Web-engine tests,
  production build pass, and zero production dependency vulnerabilities.

## Final submission gate

- [ ] Commit and push the tested checkout; paste the SHA above.
- [ ] Make the repository public with an appropriate license, or share the
      private repository with both required judging addresses.
- [ ] Verify the pushed repository from a clean clone.
- [ ] Upload the narrated MP4 as a public YouTube video and paste the URL.
- [ ] Run `/feedback` in the primary build task and paste its session ID.
- [ ] Confirm public playback, repository access, README setup, and all Devpost
      fields before submitting.
