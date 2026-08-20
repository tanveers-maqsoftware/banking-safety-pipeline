# Retail Banking Safety Pipeline

A safe-routing layer that sits in front of a Microsoft Copilot Studio retail
banking agent. Every customer message is run through ordered safety stages
before any model is called, and the service returns a routing decision the
Copilot Studio topic branches on.

## What it does

```
customer message
      |
      v
  1. language     detect language on RAW text
  2. injection    scan RAW text -> BLOCK here means no model is ever called
  3. PII          Presidio masks to typed placeholders (<UK_NINO_1>)
  4. rewrite      normalise banking shorthand, on MASKED text only
  5. intent       classify + score route_confidence
  6. assemble     fill the active versioned prompt template
  7. route        answer | refuse | escalate
      |
      v
  JSON -> Copilot Studio
```

The stage order is a security decision, not an implementation detail. See the
module docstring in [`safety/pipeline.py`](safety/pipeline.py) for why each
stage sits where it does.

The pipeline is **fail-closed**: any unexpected error returns `escalate` to a
human rather than falling through to an answer.

## Layout

The production path is `run.py` -> `main.py` -> `safety/pipeline.py`. The
pipeline calls the language, injection, PII, rewrite, intent, assembler and
prompt-library modules. The remaining files support configuration, testing or
operations; they are not imported for every request.

| Path | Purpose |
| --- | --- |
| `run.py` | Starts the API and optionally opens a Cloudflare tunnel with one cross-platform command. |
| `main.py` | FastAPI service. Thin transport layer only. |
| `safety/pipeline.py` | Stage orchestration. **Start here.** |
| `safety/injection.py` | Prompt-injection and jailbreak rules. |
| `safety/pii.py` | Presidio masking + session-scoped vault. |
| `safety/intent.py` | Intent classification and route confidence. |
| `safety/language.py` | Language detection (lingua). |
| `safety/rewriter.py` | Deterministic shorthand expansion. |
| `safety/assembler.py` | Slot-filling for prompt templates. |
| `safety/library.py` | Versioned prompt loading + sha256 integrity check. |
| `prompts/*.json` | Versioned prompts, one file per scenario-version. |
| `prompts/registry.json` | Pins the active version and hash of each prompt. Generated. |
| `tools/stamp_registry.py` | Regenerates `registry.json`. |

## Setup

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt
python -m spacy download en_core_web_lg
python tools/stamp_registry.py
```

### Windows (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
python -m spacy download en_core_web_lg
python tools\stamp_registry.py
```

The spaCy model is a separate download because it is not distributed on PyPI.
Presidio will not start without it.

If `python -m spacy download en_core_web_lg` fails with SSL certificate errors,
install the model wheel directly instead:

```bash
curl -kL -o /tmp/en_core_web_lg-3.8.0-py3-none-any.whl \
  https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl
python -m pip install --no-deps /tmp/en_core_web_lg-3.8.0-py3-none-any.whl
```

If `pip install -r requirements.txt` hits a PyPI certificate issue, retry with
trusted hosts:

```bash
python -m pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org --trusted-host pypi.python.org -r requirements.txt
```

`tools/stamp_registry.py` writes `prompts/registry.json`. The library verifies
every prompt's sha256 against that file at startup, so an edit to a prompt
without a version bump is a loud startup failure rather than a silent change in
agent behaviour. Re-run it after intentionally editing a prompt **and** bumping
its version.

> **VS Code:** if the editor flags installed packages as missing, it is pointing
> at the wrong interpreter. `Ctrl+Shift+P` -> *Python: Select Interpreter* ->
> `.venv/bin/python` on macOS/Linux or `.venv\Scripts\python.exe` on Windows.

Install `cloudflared` too — it is what puts the service on a public URL for
Copilot Studio:

### macOS

```bash
brew install cloudflared
```

### Linux

```bash
# Debian/Ubuntu
sudo apt-get update && sudo apt-get install -y cloudflared

# Fedora/RHEL
sudo dnf install -y cloudflared
```

### Windows (PowerShell)

```powershell
winget install --id Cloudflare.cloudflared
```

## Run

From the repository root, launch the app with the project virtualenv so the
correct dependencies are used:

### macOS / Linux

```bash
./.venv/bin/python run.py --port 8000
```

### Windows (PowerShell)

```powershell
.\.venv\Scripts\python.exe run.py --port 8000
```

This starts the API, waits for `/v1/health` to return `ok`, and then opens a
Cloudflare tunnel if `cloudflared` is available. It prints a public URL you can
paste into Copilot Studio.

The launcher checks whether port 8000 is already in use before it starts the
API. If you see `Port 8000 is already in use`, stop the existing process or
free that port and try again.

To skip the tunnel and run the API locally only:

```bash
./.venv/bin/python run.py --port 8000 --no-tunnel
```

### Windows (PowerShell)

```powershell
.\.venv\Scripts\python.exe run.py --port 8000 --no-tunnel
```

Interactive API docs: <http://127.0.0.1:8000/docs>

## Test

From the repository root, run the test suite with the project virtualenv:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Run only the injection tests while tuning scanner rules:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_injection.py -q
```

### Troubleshooting

- If the editor says packages are missing, select the workspace interpreter at
  `.venv/bin/python` on macOS/Linux or `.venv\\Scripts\\python.exe` on Windows.
- If the launcher reports `Port 8000 is already in use`, stop the process
  already using that port and try again.
- If the app does not start, run it once with `--no-tunnel` first so you can
  verify the local API without the Cloudflare step.

### Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/v1/process` | Run a customer message through the pipeline. |
| `GET` | `/v1/health` | Liveness + which prompt versions are being served. |

`POST /v1/process` takes:

```json
{
  "message": "whats my balance? my account is 12345678",
  "session_id": "conversation-id",
  "previous_query": null
}
```

`session_id` scopes the PII vault so placeholders resolve within one
conversation and never leak across customers.

A processed message **always returns 200**, even on internal failure — the
pipeline's fail-closed result (`action: "escalate"`) is the useful answer, and
Copilot Studio cannot branch on an HTTP 500.

### Quick check

Use the same port 8000 on macOS, Linux, and Windows.

#### macOS / Linux

```bash
curl http://127.0.0.1:8000/v1/health

curl -X POST http://127.0.0.1:8000/v1/process \
  -H "Content-Type: application/json" \
  -d '{"message":"where is my nearest branch?","session_id":"s1"}'
```

#### Windows (PowerShell)

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/v1/health"

Invoke-RestMethod `
  -Uri "http://127.0.0.1:8000/v1/process" `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"message":"where is my nearest branch?","session_id":"s1"}'
```

## Expose it for Copilot Studio

Copilot Studio needs a public HTTPS URL that an **unauthenticated** caller can
reach. `run.py` handles this end to end; this section explains what it is
doing and how to fix it when it misbehaves.

### Why Cloudflare

The alternatives all put something in front of the API that a connector cannot
get past. GitHub Codespaces and VS Code Dev Tunnels forward ports as **private**
by default, which means a GitHub sign-in page; localtunnel serves a
"click to continue" interstitial. In every case Copilot Studio receives HTML
instead of JSON and fails with a parse error that never names the real cause.

A Cloudflare quick tunnel serves the app directly — no login, no interstitial,
no extra headers on the connector.

### What run.py does

1. Starts uvicorn bound to `127.0.0.1` only, so nothing on your network can
   reach the API. The tunnel is the sole route in.
2. Polls `/v1/health` until it passes. The service warms the spaCy and lingua
   models on startup, so first boot takes a few seconds.
3. Runs `cloudflared tunnel --url http://127.0.0.1:8000` and reads the assigned
   hostname out of its output.
4. Prints the URL and stops both processes on `Ctrl+C`.

To do it by hand instead, run the API in one terminal and this in another:

```bash
cloudflared tunnel --url http://localhost:8000
```

### Verify before wiring up the connector

Check the URL returns **JSON and not HTML**:

```powershell
curl.exe -sS https://<your-tunnel-url>/v1/health
```

Expect `{"status":"ok","active_prompts":{...}}`. Anything starting with
`<!DOCTYPE html>` means something is sitting in front of the API and Copilot
Studio will fail on it.

### The URL changes on every restart

A quick tunnel gets a new random hostname each time, so the Copilot Studio
connector has to be re-pointed whenever you restart. That is fine for
development and a nuisance for a demo.

When the launcher succeeds, it prints the current public URL in the terminal in
this form:

```text
Public URL : https://<random-hostname>.trycloudflare.com
Connector  : https://<random-hostname>.trycloudflare.com/v1/process
Health     : https://<random-hostname>.trycloudflare.com/v1/health
```

For a stable hostname you need a **named tunnel**, which requires a domain on
your Cloudflare account:

```powershell
cloudflared tunnel login
cloudflared tunnel create banking-safety
cloudflared tunnel route dns banking-safety api.yourdomain.com
cloudflared tunnel run --url http://127.0.0.1:8000 banking-safety
```

`api.yourdomain.com` then stays put across restarts.

## Wire into Copilot Studio

1. **Settings -> Custom connectors -> New**, pointed at your tunnel host.
2. Add the action `POST /v1/process` with `Content-Type: application/json`.
3. In your topic, call the connector with the customer's message and the
   conversation id, then branch on the response:

| `action` | Topic behaviour |
| --- | --- |
| `refuse` | Show `customer_message`. Do not call a model. |
| `escalate` | Show `customer_message`, hand off to the live agent queue. Log `escalation_reason`. |
| `answer` | Send `system_prompt` + `user_prompt` to the model, return its reply. |

The response is deliberately flat so every field binds directly to a topic
variable. `route_confidence` exists because Copilot Studio does not expose its
own intent-matching confidence to topics — the threshold check the requirement
asks for is computed here instead.

Log `prompt_ref`, `injection_score` and `entities_found` against each turn.
`block_reason` carrying a `flagged_not_blocked:` prefix marks a turn that was
allowed through but is worth an analyst's review.

## Notes

- Nothing persists. The PII vault is in-memory and session-scoped, and is never
  serialised into a response. Restarting the process drops it.
- `masked_text` is what is safe to log. The raw message is not.
