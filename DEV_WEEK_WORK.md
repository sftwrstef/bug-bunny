# Dev Week work ledger

Submission period: July 13, 2026 at 9:00 AM PT through July 21, 2026 at
5:00 PM PT.

## Administrative baseline work

- July 19: Imported the untouched May Bug Bunny source into the Dev Week
  workspace so subsequent work can be tracked in Git.
- July 19: Added baseline disclosure, source hashes, and pre-existing QA
  screenshots.

Administrative baseline work is not claimed as new product functionality.

## Eligible product work

### July 19: Authorized Safe Web Hunter

- Connected the pre-existing Node Web audit engine to the persistent FastAPI and
  SQLite product path; the dashboard no longer uses mock findings for normal runs.
- Added live DNS, homepage, same-origin route, header, cookie, CORS, robots.txt,
  link, form, and dotfile observations behind an explicit authorization gate.
- Added same-origin redirect enforcement, HTTP(S)-only requests, a four-redirect
  ceiling, per-request timeouts, and a 512 KiB response limit.
- Persisted the raw engine evidence, normalized findings, generated repro commands,
  agent timeline, duplicate-search leads, and final Markdown report per run.
- Tightened severity discipline so hardening gaps remain observations and wildcard
  credentialed CORS is not incorrectly treated as a browser-readable exploit.
- Added a deterministic localhost Web fixture test and verified the complete flow in
  Chromium with zero console errors.
- Reframed the product as a dark, evidence-first Signal Console with a responsive
  investigator workflow, making the authorization gate, live signal, and report
  handoff legible in a short demo.

### July 19: Verified IDOR Replay

- Added an ephemeral localhost profile API with deterministic attacker and
  victim records.
- Added a same-state truthful control and attacker replay over real HTTP.
- Added a negative control proving unauthenticated access is rejected.
- Added assertions for legitimate attacker access and unauthorized exposure of
  the victim's private record.
- Added redacted, hashed, machine-readable proof artifacts.
- Added `POST /api/proofs/idor/run` to execute and persist the proof.
- Added the Verified IDOR Replay control/exploit matrix to the React UI.
- Added a focused standard-library test and one-command CLI reproduction.
- Restored clean dependencies and updated the imported lockfile until
  `npm audit` reported zero known vulnerabilities.
- Removed Uvicorn reload mode from the judge/demo command after clean setup
  showed it repeatedly watching and restarting on `.venv` files.

This is the first product functionality claimed as Dev Week work. It was built
in Codex Desktop with GPT-5.6 Sol in primary session
`019f7376-015c-78b3-a2ea-7b43e4b03b40`.

### July 20: External Program passive guardrail

- Added a separately enforced HackerOne/Bugcrowd **External Program (passive)**
  mode instead of treating an authorization checkbox as sufficient permission.
- Requires a stored policy receipt: platform, program name, current policy URL,
  exact in-scope HTTPS URL, policy acknowledgement for the read-only check, and
  manual-validation acknowledgement.
- Enforces exactly one public-target `GET` request at no more than one HTTP
  request per second. Localhost/IP targets, redirect following, route guessing,
  link following, robots/sitemap requests, dotfile checks, CORS manipulation,
  authentication, payload mutation, active exploitation, and repro traffic are
  unavailable in this mode.
- Stores an observations-only ledger with the policy receipt and explicit
  non-submission gate. It never claims severity, a duplicate verdict, a PoC, or
  bounty eligibility from a passive response.
- Added deterministic engine tests for the exact-URL policy receipt, HTTPS and
  public-host rejection, no-path-discovery constraints, and the one-request-per-
  second pacer.

### July 21: OpenCode Go / Kimi evidence triage

- Replaced the decorative multi-agent UI with four truthful pipeline stages:
  scope gate, evidence collector, Kimi reasoner, and report builder.
- Added a project-scoped OpenCode agent pinned to `opencode-go/kimi-k3` with all
  tools denied. It receives saved evidence only and cannot browse, mutate the
  workspace, or send traffic to a target.
- Added a server-side redaction boundary before model invocation: query strings,
  credentials, cookie values, tokens, and sensitive header values are removed;
  only header names and derived cookie-attribute booleans are retained.
- Added a validated JSON evidence-review contract covering observed facts,
  unsupported claims, attacker, victim, asset or authority at risk, strongest
  likely dismissal, proof requirements, safest manual step, and submission gate.
- Added fail-closed server enforcement: model output is advisory; external runs
  remain non-submission-ready, and a model `VERIFIED` verdict is downgraded
  unless a separate deterministic proof artifact is supplied.
- Persisted provider, model, OpenCode session ID, cost, token counts, latency,
  redacted input, and input SHA-256 in each run and in the generated report.
- Made the visible UI workflow real and prerequisite-gated: **Collect bounded
  evidence → Analyze current run with Kimi → Generate evidence report**.
- Removed or renamed decorative controls, made provider status refreshable, and
  split Hunts, Scope, Findings, Proof Lab, Reports, and Settings into working
  views. Loading a saved run restores its evidence and mode safely.
- Kept IDOR in Proof Lab as the first deterministic proof template while making
  clear that Web collection and AI triage are not limited to IDOR.

The final runtime receipt used saved evidence from a prior single-request
PortSwigger observation run. Kimi made no target request. It returned
`OBSERVATION`, identified no attacker, victim, or asset at risk, and kept
`submission_ready` false.

- OpenCode session: `ses_07d26df27ffe0u4VZLYAhwPThD`.
- Model: `opencode-go/kimi-k3`.
- Cost: `$0.026421`; latency: `57,253 ms`.
- Tokens: `2,615` total (`1,067` input, `694` output, `854` reasoning).
- Redacted input SHA-256:
  `d4b790ca78c2d8336601fbea092927089fa2019d0ccd0d8ad3802bb3f512d7a7`.
- Receipt: `evidence/dev-week/kimi-runtime-receipt.json`.

### July 21: Policy-matched live target profile

- Added Intigriti as a first-class platform and selected Intigriti's own paid
  `*.pwn.intigriti.rocks` research environment as the first reviewed live target.
- Pinned the profile to the official program URL and current July 21 policy
  snapshot, including safe harbor, a published 10 requests/second automation
  limit, required researcher attribution, and explicit scope boundaries.
- Replaced the one-response fallback for this profile with a hard-limited live
  surface mapper: 24 `GET`/`HEAD` requests at no more than 2 requests/second.
- Requires the operator's real Intigriti username and sends both the required
  `X-Intigriti-Username` header and an attributed Bug Bunny user agent.
- Enforces the exact `*.pwn.intigriti.rocks` host suffix, public DNS resolution,
  same-origin redirects, response-size limits, request timeouts, and the request
  budget in the engine—not only in UI copy.
- Maps only the root, standard policy files, and same-origin public links/assets
  present in retrieved pages. A bounded set of public JavaScript assets can be
  parsed for API/auth route strings, but extracted candidates are not probed.
- Blocks cross-origin and subdomain discovery, form submission, credential
  attacks, state-changing methods, payload mutation, denial of service, and
  access to other users' data.
- Added fail-closed backend and engine tests for the target allowlist, pinned
  policy URL, researcher identity format, attribution receipt, published versus
  operational rate, and hard request-budget enforcement.
- Verified the live-target form in the in-app browser. The run button remains
  disabled until the real researcher identity and all policy acknowledgements
  are present.
- Ran the first real attributed profile as Intigriti researcher `sftwr` on July
  21. The exact target, `app.pwn.intigriti.rocks`, returned CloudFront `403` for
  the root, `robots.txt`, and `.well-known/security.txt`, consistent with the
  program's required VPN not being active. Bug Bunny stopped after three of the
  24 allowed requests, did not bypass the access gate, and asserted no finding.
- Preserved the public-safe execution receipt at
  `evidence/dev-week/intigriti-live-access-receipt.json`; the full local raw
  artifact remains under run `9bf14443-062d-40ea-a9fe-3ab9ca1592ee`.

### July 21: Controlled two-account authorization proof

- Added a separate Intigriti PWN proof profile for one known-object A↔B
  authorization hypothesis. It requires two researcher-controlled accounts,
  explicit PWN hosts, isolated sessions, `GET`-only replay, and a two-attempt
  stop condition; automatic login and target traffic remain disabled.
- Added a run-scoped `controlled-proof.json` receipt that is write-once through
  the API. Its strict
  import schema accepts only account aliases, object type, a locator SHA-256,
  marker-present booleans, two denial outcomes, and session isolation.
- Prohibited and omitted raw object IDs/URLs, request and response bodies,
  headers, credentials, cookies, tokens, email addresses, and free-form page
  text. The artifact is mode `0600` and a repeat import returns `409`.
- Kept controlled proof separate from Web-scanner evidence and from findings.
  A denied replay closes one hypothesis; it does not create an informational
  pseudo-finding or claim that the target is globally free of IDOR.
- Completed the first real PWN run with controlled Account A `bugbunny` and
  Account B `sftwr_bugbunny_b_0721`: A's owner control succeeded, B was denied
  twice, no A marker or third-party data appeared, and testing stopped.
- Derived `INVALID`, `NO_IDOR`, `tested_draft_only`, and
  `submission_ready=false` server-side. Kimi independently reviewed the
  sanitized receipt and agreed; OpenCode session
  `ses_07c30eea3ffeqIZj3sx2p1cwx7`.
- Added the data-driven Proof Lab closed state and preserved its browser-checked
  capture at `evidence/dev-week/controlled-proof-closed.png`.

### July 21: Reusable authenticated capture-and-replay engine

- Replaced the manual-only A↔B handoff for new work with a reusable engine that
  accepts two ephemeral DevTools **Copy as cURL** captures from isolated,
  researcher-controlled accounts and two equivalent controlled objects.
- Added a generic reviewed-program profile for HackerOne, Bugcrowd, and
  Intigriti. It records the current program and policy, one exact HTTPS target,
  explicit hostnames with no wildcards, one victim-centered hypothesis, the
  four-request maximum, and the operator's scope and ownership attestations.
- Added a localhost authenticated-replay workflow and vulnerable/secure
  fixtures so judges can reproduce both verdict branches without an account or
  any third-party traffic.
- Parses cURL syntax structurally with `shlex` and never invokes a shell. It
  rejects non-`GET` methods, bodies, uploads, proxies, redirects, TLS bypasses,
  host overrides, unsupported flags, sensitive query parameters, unsafe
  headers, oversized captures, and captures without distinct session material.
- Requires both captures to share one exact origin and endpoint shape while
  differing by exactly one object locator. External runs require HTTPS on port
  443 and the exact hostname in the stored allowlist.
- Resolves and validates DNS before replay, pins each connection to the checked
  address, permits only a public external address or the exact loopback fixture,
  uses a fresh connection per attempt, blocks redirects, caps each response at
  256 KiB, and enforces connect/read timeouts.
- Runs the minimum deterministic matrix: B→B and A→A same-account controls,
  followed by B→A. Exposure stops immediately after three requests; only a
  denial is repeated once, for an absolute maximum of four requests.
- Derives exactly three tested-branch verdicts server-side:
  `VERIFIED / CROSS_ACCOUNT_OBJECT_EXPOSURE`,
  `INVALID / NO_CROSS_ACCOUNT_EXPOSURE`, or
  `INCONCLUSIVE / CONTROL_FAILED|UNSTABLE_REPLAY`.
- Keeps raw cURLs, credential values, URLs, object locators, response markers,
  headers, and request/response bodies out of SQLite, logs, UI state, and disk.
  Secret fields are cleared after every execution attempt.
- Writes one file-mode `0600`, sanitized, integrity-checked
  `authenticated-replay.json` receipt per run. The receipt retains only derived
  request shape, fingerprints and hashes, control/replay outcomes, request
  budget, DNS-pin metadata, redaction assertions, and a receipt SHA-256.
- Added compare-and-swap run locking to prevent concurrent duplicate replay,
  preview/execute intent headers, a 64 KiB request-body ceiling, and safe
  validation responses that omit submitted secret input.
- Hardened the false-positive boundary after an independent security pass:
  primary authentication must differ independently of CSRF rotation;
  ambiguous account-binding/signature headers are rejected; markers must be
  high-entropy and non-overlapping; both controls prove the other marker is
  absent; and a process-wide exact-origin lock plus scheduler prevents parallel
  runs from bypassing the stored request pace.
- Added the capture, redaction preview, acknowledgements, control matrix,
  verdict, receipt hash, timeline, and Kimi handoff to Proof Lab. Kimi remains
  an evidence challenger: it receives only the sanitized receipt and cannot
  override the deterministic verdict or mark a live result submission-ready.
- Added focused engine/API tests for vulnerable, secure, control-failure and
  rejected plans, redirect behavior, secret absence, artifact
  tamper detection, write-once/file-mode `0600` persistence, and SQLite/run-response
  redaction.
- Completed final browser run `b2784892-6cde-4bfd-a95d-33a30361327e` with zero
  console or API errors. Both truthful controls passed, the derived B→A branch
  exposed A's marker, and the engine stopped at `3 / 4` requests.
- Challenged that exact hardened receipt with real Kimi K3 session
  `ses_07a422d7effeOrvAhxlSlRA9B8`. Kimi agreed the tested fixture branch was
  deterministic while correctly keeping `submission_ready=false`; the report
  records the redacted input hash, costs, tokens, dismissal, and proof gates.
- Recorded a 78.68-second browser demo and produced a narrated H.264/AAC export.
  The audio stream was measured as non-silent at 26–30 seconds and throughout
  the final seven seconds.

This is a material Dev Week extension of the original fixed localhost IDOR
template: the request shape, origin, locator, credentials, controls, and result
now come from a policy-gated capture rather than a hard-coded endpoint.

## Verification receipts

- `npm run test:proof`: **32 tests pass**, including structural capture parsing,
  unsafe cURL rejection, primary-session and ambiguous-header enforcement,
  marker entropy/negative controls, origin locking/pacing, vulnerable and secure
  stop conditions, control failure, redirect blocking, secret absence,
  authenticated-replay API persistence and artifact integrity, secret/cookie
  redaction, structured Kimi output, program-profile allowlists,
  controlled-proof strictness, and the original local IDOR proof.
- Two independent proof executions were identical after removing only the
  generated timestamp.
- `npm run build`: pass with Vite 7.3.6; 1,578 modules transformed.
- `npm audit --omit=dev`: zero known vulnerabilities.
- Browser flow: opened the app, selected **Run real proof**, observed the
  verified control/exploit matrix, and recorded no browser console errors.
- Controlled-proof browser smoke: loaded the real PWN run, verified the closed
  Proof Lab matrix plus controlled-specific Findings and Reports copy, rejected
  stale plan/passive text, and recorded zero browser console errors.
- Safe Web browser flow: created an authorized localhost hunt, observed three
  evidence-backed hardening observations, generated the final report, and recorded no
  browser console errors.
- `npm run test:web`: six engine tests pass against deterministic localhost
  fixtures, covering the safe Web audit, redirect and size boundaries, passive profile,
  Intigriti bounded-profile policy, pacing, and hard request-budget exhaustion
  without contacting a third-party target.
- Safe Web UI capture: `evidence/dev-week/safe-web-hunter.png`.
- JSON proof: `evidence/dev-week/verified-idor-proof.json`.
- UI capture: `evidence/dev-week/dev-week-verified-idor.png`.
- Controlled live-proof capture: `evidence/dev-week/controlled-proof-closed.png`.
- Kimi runtime receipt: `evidence/dev-week/kimi-runtime-receipt.json`.
- Live Kimi report:
  `runs/a43dcf88-9b95-463f-bede-071159f04767/reports/observation-ledger.md`.
- Narrated demo source: `evidence/dev-week/bug-bunny-demo-narration.txt` and
  `evidence/dev-week/bug-bunny-demo-subtitles.srt`; the generated H.264/AAC
  upload file is `output/demo/bug-bunny-demo.mp4` (36.5 seconds, local-only).
- Reusable authenticated-replay browser capture:
  `evidence/dev-week/authenticated-replay-verified.png`.
- Public-safe authenticated-replay receipt:
  `evidence/dev-week/authenticated-replay-receipt.json`.
- Current replay/Kimi provenance:
  `evidence/dev-week/authenticated-replay-kimi-receipt.json`.
- Updated browser recording: `evidence/dev-week/authenticated-replay-demo.webm`;
  narrated upload file: `output/demo/bug-bunny-authenticated-replay-demo.mp4`
  (78.68 seconds, H.264/AAC, local-only until upload).
