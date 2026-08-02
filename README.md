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

| Path | Purpose |
| --- | --- |
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

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
python -m spacy download en_core_web_lg
python tools\stamp_registry.py
```

The spaCy model is a separate download because it is not distributed on PyPI.
Presidio will not start without it.

`tools\stamp_registry.py` writes `prompts/registry.json`. The library verifies
every prompt's sha256 against that file at startup, so an edit to a prompt
without a version bump is a loud startup failure rather than a silent change in
agent behaviour. Re-run it after intentionally editing a prompt **and** bumping
its version.

> **VS Code:** if the editor flags installed packages as missing, it is pointing
> at the wrong interpreter. `Ctrl+Shift+P` -> *Python: Select Interpreter* ->
> `.venv\Scripts\python.exe`.

## Run

```powershell
python -m uvicorn main:app --reload --port 8000
```

Interactive API docs: <http://127.0.0.1:8000/docs>

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

```powershell
curl.exe http://127.0.0.1:8000/v1/health

curl.exe -X POST http://127.0.0.1:8000/v1/process `
  -H "Content-Type: application/json" `
  -d '{\"message\":\"where is my nearest branch?\",\"session_id\":\"s1\"}'
```

## Expose it for Copilot Studio

Copilot Studio needs a public HTTPS URL that an **unauthenticated** caller can
reach. Every option below fails the same way if you get that second part wrong:
the connector receives a sign-in or interstitial HTML page instead of your JSON.

### Option A — GitHub Codespaces (no local server)

The app runs on GitHub's VM, so nothing needs to stay running on your laptop.
`.devcontainer/devcontainer.json` installs the dependencies, downloads the
spaCy model and stamps the prompt registry on create.

1. On the repo page: **Code -> Codespaces -> Create codespace on main**.
   Wait for `postCreateCommand` to finish — the spaCy model is ~560MB.
2. In the Codespace terminal:

   ```bash
   python -m uvicorn main:app --port 8000
   ```

3. Open the **PORTS** panel. Port 8000 should be forwarded. **Confirm the
   Visibility column says `Public`** — right-click -> *Port Visibility* ->
   *Public* if not.
4. Copy the forwarded address, of the form
   `https://<codespace-name>-8000.app.github.dev`.

> **This is the step that breaks the connector.** A forwarded port defaults to
> **Private**, which puts GitHub authentication in front of it. Copilot Studio
> has no GitHub session, so it gets an HTML login page and the action fails with
> a parse error rather than anything that names the real cause.

Codespaces stop after ~30 minutes idle and the URL dies with them. The URL is
stable across stop/start of the *same* Codespace, but a new one gets a new
name. Codespaces bills against a monthly free quota — check your usage under
**Settings -> Billing** before leaving one running.

### Option B — Cloudflare Tunnel (local, most reliable)

Best of the local options: no interstitial and no auth in front of it, so the
connector works with no extra headers.

```powershell
winget install --id Cloudflare.cloudflared
cloudflared tunnel --url http://localhost:8000
```

Prints `https://<random-words>.trycloudflare.com`. No account needed.

### Option C — VS Code Dev Tunnels

The other feature often called "the GitHub tunnel" — it is Microsoft Dev
Tunnels, which you sign into with your GitHub account. Your app still runs
locally.

In VS Code: **PORTS** panel -> *Forward a Port* -> `8000` -> right-click ->
*Port Visibility* -> **Public**. Same private-by-default trap as Codespaces.

Or from the CLI:

```powershell
winget install --id Microsoft.devtunnel
devtunnel user login
devtunnel host -p 8000 --allow-anonymous
```

`--allow-anonymous` is not optional for Copilot Studio — without it the tunnel
demands a login.

### Option D — localtunnel

```powershell
npx localtunnel --port 8000
```

Prints `https://<subdomain>.loca.lt`.

> **Gotcha:** localtunnel serves a "click to continue" interstitial to
> first-time visitors, which the connector receives instead of your JSON. Send
> `bypass-tunnel-reminder: true` on every request to skip it. Add it to the
> connector's headers, or test with:
>
> ```powershell
> curl.exe -H "bypass-tunnel-reminder: true" https://<subdomain>.loca.lt/v1/health
> ```

### Verify before wiring up the connector

Whichever option you pick, check the URL returns **JSON and not HTML** from
somewhere without your session — a phone on mobile data, or:

```powershell
curl.exe -sS https://<your-tunnel-url>/v1/health
```

Expect `{"status":"ok","active_prompts":{...}}`. Anything starting with
`<!DOCTYPE html>` means the port is still private or an interstitial is in the
way, and Copilot Studio will fail on it.

Tunnel URLs change on restart. Re-point the connector each time.

## Wire into Copilot Studio

1. **Settings -> Custom connectors -> New**, pointed at your tunnel host.
2. Add the action `POST /v1/process` with `Content-Type: application/json` (plus
   `bypass-tunnel-reminder: true` if you used localtunnel).
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
