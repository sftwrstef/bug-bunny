# Dev Week evidence

```text
evidence is the product surface
secrets are not evidence
```

These files document Bug Bunny's post-baseline Dev Week work.

- `kimi-runtime-receipt.json` records a real OpenCode Go / Kimi K3 evidence
  analysis: model, session, cost, tokens, latency, request ledger, redacted-input
  hash, advisory verdict, and server-side submission gate. The AI analyzed saved
  evidence and did not make another request to the target.
- `intigriti-live-access-receipt.json` records the first attributed bounded run
  against Intigriti's PWN environment. Three requests remained inside the exact
  host and returned CloudFront `403`; the mapper stopped without bypass attempts
  because the required Intigriti VPN was not active.
- `verified-idor-proof.json` is the machine-readable output of the executable
  same-state IDOR proof on July 19, 2026.
- `dev-week-verified-idor.png` shows the verified control/exploit matrix after
  the browser exercised `POST /api/proofs/idor/run`.
- `controlled-proof-closed.png` shows the first real two-account PWN proof
  receipt: owner access succeeded, the isolated peer was denied twice, the
  tested draft-flow hypothesis was `INVALID`, and the submission gate remained
  closed. The separate JSON receipt includes Kimi's agreeing verdict and
  provenance. The underlying run stores no raw object ID, URL,
  response body, headers, credentials, cookies, tokens, or email addresses.
- `controlled-proof-receipt.json` is the public-safe machine-readable receipt
  for that run, including the controlled actors, two denial outcomes, locator
  hash, server classification, and Kimi provenance.
- `authenticated-replay-verified.png` shows the reusable engine's truthful
  A→A and B→B controls, derived B→A exposure, `3 / 4` stop condition, and
  immutable receipt hash for final hardened run
  `b2784892-6cde-4bfd-a95d-33a30361327e`.
- `authenticated-replay-receipt.json` is an exact public-safe copy of that
  run's secret-free, write-once receipt. Its internal integrity SHA-256 is
  `1d8fc9daa17241f14aab0bcb6c3e7e70ef9c132bd325860d587db6dce1857bff`.
- `authenticated-replay-kimi-receipt.json` preserves the Kimi K3 challenge of
  that exact final hardened receipt: OpenCode session
  `ses_07a422d7effeOrvAhxlSlRA9B8`, redacted input hash, tokens, cost,
  deterministic/model verdicts, and the fail-closed submission gate.
- `authenticated-replay-demo.webm`,
  `authenticated-replay-demo-narration.txt`, and
  `authenticated-replay-demo-subtitles.srt` are the current 78.68-second
  browser recording, voiceover source, and timed captions. The upload-ready
  H.264/AAC file is local at
  `output/demo/bug-bunny-authenticated-replay-demo.mp4`.
- `bug-bunny-demo-narration.txt` and `bug-bunny-demo-subtitles.srt` are the
  voiceover and captions for the short real-product demo. The local,
  upload-ready MP4 is `output/demo/bug-bunny-demo.mp4`; generated media is
  deliberately kept out of Git. That 36.5-second recording predates the reusable
  authenticated capture-and-replay engine and must not be presented as a demo
  of the new workflow.

## July 21: reusable authenticated replay

The current Dev Week vertical slice accepts two ephemeral DevTools **Copy as
cURL** captures from isolated accounts and equivalent harmless objects owned by
the researcher. It supports a reviewed HackerOne, Bugcrowd, or Intigriti
program through an exact-host policy receipt, plus a localhost-only judge
fixture.

The engine permits only `GET`; requires distinct primary sessions and one
changed object locator; rejects ambiguous account-binding headers; requires
high-entropy non-overlapping markers with negative controls; runs the B→B, A→A,
and B→A authorization matrix behind a process-wide exact-origin pace lock;
repeats only a denial once; stops immediately on exposure; and never exceeds
four requests. It emits
`VERIFIED`, `INVALID`, or `INCONCLUSIVE` for only the tested branch.

Raw cURLs, credentials, URLs, object locators, markers, headers, and
request/response bodies are never persisted. The expected public artifact is a
sanitized copy of the write-once, file-mode `0600` receipt containing only derived
shape metadata, outcome booleans, request/response hashes, request count,
redaction assertions, DNS-pin metadata, and its integrity SHA-256.

**Codex with GPT-5.6 Sol built the project. Kimi K3 is the runtime evidence
challenger.** Kimi receives the sanitized receipt after replay; it does not
hold credentials, send replay traffic, or control the deterministic verdict.

## Submission evidence checklist

- [x] Pre-existing baseline is separated in `PREEXISTING.md`.
- [x] Eligible work is dated and described in `DEV_WEEK_WORK.md`.
- [x] Reusable engine and API tests pass: `npm run test:proof` — 32/32.
- [x] Bounded Web-engine tests pass: `npm run test:web` — 6/6.
- [x] Production client builds: `npm run build` with Vite 7.3.6.
- [x] Production dependency audit is clean: `npm audit --omit=dev` — zero
  known vulnerabilities.
- [x] Kimi runtime provenance is preserved in
  `kimi-runtime-receipt.json`, including its OpenCode session ID.
- [x] Run the vulnerable localhost fixture through the final browser UI and add
  `authenticated-replay-verified.png`.
- [x] Export the fixture run's secret-free receipt as
  `authenticated-replay-receipt.json`; verify the integrity SHA-256 and confirm
  no cURL, credential, URL, marker, locator, header, or body is present.
- [x] Repeat final browser smoke with zero console errors and record the exact
  run ID in this file: `b2784892-6cde-4bfd-a95d-33a30361327e`.
- [x] Record a new under-three-minute video that visibly shows a fresh scoped
  run loading, secret paste zones, redaction preview, the request budget, A/B matrix,
  deterministic verdict, receipt hash, and the separate Kimi handoff button.
  The current narrated
  H.264/AAC export is 78.68 seconds; audio was explicitly checked at 27, 70, and 75
  seconds to prevent the earlier mute regression.
- [ ] Add the final public video URL and verify it plays without authentication.
- [ ] Preserve the feature commit hash and confirm the public repository matches
  the tested checkout.
- [ ] Run `/feedback` in the Codex task and use its returned Codex session ID in
  the Devpost form.
- [x] Verify the README setup from a clean source checkout: fresh `npm ci`,
  fresh Python virtual environment, 32/32 proof tests, 6/6 Web tests, and the
  production build all pass.

Codex Desktop primary session:
`019f7376-015c-78b3-a2ea-7b43e4b03b40`

The task's recorded model is `gpt-5.6-sol`. Run `/feedback` in that task before
submission and use the returned session ID in the Devpost form.

Controlled-proof OpenCode session:
`ses_07c30eea3ffeqIZj3sx2p1cwx7`
