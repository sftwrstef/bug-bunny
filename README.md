<div align="center">

\`\`\`text
██████╗ ██╗   ██╗ ██████╗     ██████╗ ██╗   ██╗███╗   ██╗███╗   ██╗██╗   ██╗
██╔══██╗██║   ██║██╔════╝     ██╔══██╗██║   ██║████╗  ██║████╗  ██║╚██╗ ██╔╝
██████╔╝██║   ██║██║  ███╗    ██████╔╝██║   ██║██╔██╗ ██║██╔██╗ ██║ ╚████╔╝
██╔══██╗██║   ██║██║   ██║    ██╔══██╗██║   ██║██║╚██╗██║██║╚██╗██║  ╚██╔╝
██████╔╝╚██████╔╝╚██████╔╝    ██████╔╝╚██████╔╝██║ ╚████║██║ ╚████║   ██║
╚═════╝  ╚═════╝  ╚═════╝     ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝   ╚═╝
\`\`\`

**Local security proofs for people who want evidence, not vibes.**

\`REACT + VITE\` · \`FASTAPI\` · \`SQLITE\` · \`LOCALHOST ONLY\` · \`DEV WEEK 2026\`

</div>
> [!IMPORTANT]
> Bug Bunny turns a security claim into a reproducible, victim-centered proof
> before it becomes a report. It runs a real local replay, records the strongest
> truthful control beside the exploit, and leaves behind inspectable evidence.

![Verified IDOR Replay matrix](evidence/dev-week/dev-week-verified-idor.png)

## // mission

Most security dashboards stop at “a scanner found something.” Bug Bunny asks the
harder question: **can the harm be replayed, compared against a valid control, and
proven from the same state?**

\`\`\`text
local fixture + deterministic identities
            │
            ├── unauthenticated request ──► 401 rejected
            ├── truthful control ─────────► attacker reads own profile
            └── disputed request ─────────► attacker reads victim data
                                                    │
                                                    └──► redacted + hashed evidence
\`\`\`

The verified IDOR replay is intentionally bounded: it starts an ephemeral API on
\`127.0.0.1\`, never probes an external target, and requires no API key.

## // quickstart

\`\`\`bash
git clone https://github.com/sftwrstef/bug-bunny.git
cd bug-bunny

npm install
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

npm run dev
\`\`\`

Open the local URL printed by Vite, then choose **Run verified IDOR replay**.
The backend runs at \`http://127.0.0.1:8000\`.

\`\`\`bash
# Run the proof without the UI
.venv/bin/python -m unittest tests.test_idor_proof -v
\`\`\`

The replay writes its artifact to
[\`evidence/dev-week/verified-idor-proof.json\`](evidence/dev-week/verified-idor-proof.json).

## // proof contract

| Stage | Assertion | Why it matters |
| --- | --- | --- |
| \`NEGATIVE CONTROL\` | No token → \`401\` | The fixture does enforce authentication. |
| \`TRUTHFUL CONTROL\` | Attacker reads their own profile | The attacker identity and endpoint are valid. |
| \`EXPLOIT\` | Attacker reads victim private data | The authorization boundary is broken. |
| \`EVIDENCE\` | Tokens redacted; state and responses hashed | The replay leaves a reviewable record. |

\`\`\`text
Not merely a status-code mismatch.
The replay asserts exposure of the victim's private data from the same seeded state.
\`\`\`

## // repository map

\`\`\`text
src/                    React dashboard + proof matrix
backend/                FastAPI application + SQLite persistence
proofs/idor_proof.py    Ephemeral vulnerable fixture + replay engine
tests/                  Focused end-to-end proof test
evidence/dev-week/      Generated artifact + demo screenshot
\`\`\`

## // API surface

| Endpoint | Purpose |
| --- | --- |
| \`GET /api/health\` | Health check |
| \`POST /api/proofs/idor/run\` | Execute the verified local IDOR replay |
| \`POST /api/audits/create\` | Create an audit run |
| \`POST /api/audits/{run_id}/run-mock-scan\` | Run the original mock scan flow |
| \`GET /api/audits/{run_id}/findings\` | Read findings for an audit run |
| \`POST /api/audits/{run_id}/generate-report\` | Generate an audit report |

## // Dev Week provenance

| Scope | Status |
| --- | --- |
| Dashboard, API, SQLite storage, mock audit pipeline | \`PRE-EXISTING BASELINE\` |
| Verified IDOR replay, control/exploit matrix, evidence artifact, test, UI integration | \`DEV WEEK EXTENSION\` |

Built collaboratively with **Codex** using **GPT-5.6 Sol**.
Primary Codex session: \`019f7376-015c-78b3-a2ea-7b43e4b03b40\`.

For the full separation of work, see [\`PREEXISTING.md\`](PREEXISTING.md) and
[\`DEV_WEEK_WORK.md\`](DEV_WEEK_WORK.md).

## // submission checklist

- [ ] Run \`/feedback\` in the Codex session and retain the resulting session ID.
- [ ] Keep the Dev Week commits, proof JSON, screenshot, and setup steps.
- [ ] Demo the proof from a clean local run in under three minutes.

<div align="center">

\`proof first · noise later\`

</div>
