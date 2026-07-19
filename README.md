<div align="center">

# 🐰 Bug Bunny

### Verified security proofs, not scanner theatre.

`LOCAL-FIRST` &nbsp; `VICTIM-CENTERED` &nbsp; `EVIDENCE-BACKED` &nbsp; `OPENAI BUILD WEEK 2026`

<sub>Built with Codex · React / FastAPI / SQLite · localhost-only demonstration</sub>

</div>

---

> [!IMPORTANT]
> **One claim. One valid control. One replayable proof.**
>
> Bug Bunny takes a security finding past a dashboard card: it replays the behavior
> against a live ephemeral local fixture, compares it with the strongest truthful
> control, and saves redacted, hashed evidence for review.

![Bug Bunny verified IDOR replay](evidence/dev-week/dev-week-verified-idor.png)

## The proof, at a glance

| | Check | Result |
| :---: | --- | --- |
| `01` | **Negative control** | No token → `401 Unauthorized` |
| `02` | **Truthful control** | Attacker can read *their own* profile |
| `03` | **Exploit replay** | Attacker reads the victim’s private data |
| `04` | **Evidence** | Tokens redacted; state and responses hashed |

> [!NOTE]
> This is not a status-code demo. The replay asserts exposure of victim-private data
> from the same seeded state and identity used for the valid control.

## How it works

```text
seed attacker + victim
          │
          ▼
start vulnerable API on localhost
          │
          ├── valid request ─────► attacker profile
          │
          └── disputed request ──► victim private data
                                          │
                                          ▼
                                  write redacted proof artifact
```

The fixture uses a random `127.0.0.1` port and never contacts a third-party target.

## Run it

```bash
git clone https://github.com/sftwrstef/bug-bunny.git
cd bug-bunny

npm install
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

npm run dev
```

Open the Vite URL, then choose **Run verified IDOR replay**.

```bash
# Or execute the proof without the UI
.venv/bin/python -m unittest tests.test_idor_proof -v
```

Evidence is written to [`evidence/dev-week/verified-idor-proof.json`](evidence/dev-week/verified-idor-proof.json).

## Inside the repo

```text
src/                    React dashboard + control/exploit matrix
backend/                FastAPI application + SQLite persistence
proofs/idor_proof.py    Local fixture + replay engine
tests/                  Focused end-to-end proof test
evidence/dev-week/      Generated artifact + demo screenshot
```

## Dev Week provenance

| Pre-existing baseline | Dev Week extension |
| --- | --- |
| Dashboard, FastAPI API, SQLite storage, mock audit pipeline | Verified IDOR replay, UI matrix, evidence artifact, focused test |

Built collaboratively with **Codex** using **GPT-5.6 Sol**.
Primary session: `019f7376-015c-78b3-a2ea-7b43e4b03b40`.

Read the boundary in [`PREEXISTING.md`](PREEXISTING.md) and [`DEV_WEEK_WORK.md`](DEV_WEEK_WORK.md).

---

<div align="center">

`make the harm legible.`

</div>
