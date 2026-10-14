# Code-to-Governance Intelligence Platform

Turn an AI application repository into governance-ready, traceable technical evidence.

Point it at a Git URL (or upload a zip) and it produces:

- **Findings** — hard-coded secrets, PII, unsafe patterns, AI model/provider usage
- **AI inventory** — models, providers, SDKs/frameworks, vector stores, external hosts, SBOM
- **Control evidence** — 14 controls mapped to EU AI Act, NIST AI RMF, ISO/IEC 42001 and OWASP LLM Top 10
- **Evidence graph** — repository → package / model / provider / host / finding relationships
- **Exports** — Excel (`/scans/{id}/export/xlsx`, `/reports/excel`), SARIF, CycloneDX, CI gate, Jira, webhook
- **Runtime telemetry** — ingest LLM-call events and enforce an approved provider/model/tool/host policy
- **Policy documents** — upload PDF/DOCX/TXT, extract requirements, map them to controls
- **Multi-tenant auth** — roles `admin` / `reviewer` / `viewer`, revocable JWT sessions, optional OIDC SSO, audit log

> This is a rebuild of an earlier Railway-deployed POC, reconstructed from its public API contract
> (`/openapi.json`, v0.6.0). Endpoint paths match the original; internals are new.

## Run locally

```bash
pip install -r requirements.txt
ADMIN_PASSWORD='choose-a-password' uvicorn app.main:app --reload
```

Open <http://localhost:8000>, sign in as `admin`, then **Scans → Scan Git URL**.
API docs: <http://localhost:8000/docs>. `git` must be installed for Git-URL scans.

## Run with Docker

```bash
docker build -t cgip .
docker run -p 8000:8000 -e ADMIN_PASSWORD=choose-a-password -v cgip-data:/data cgip
```

## Deploy on Railway

1. Push this repo to GitHub, then in Railway: **New → Deploy from GitHub repo**.
2. Add a **Volume** mounted at `/data` (keeps the database across deploys).
3. Set variables: `ADMIN_PASSWORD`, `SECRET_KEY`, and optionally `GROQ_API_KEY`.
4. Generate a public domain. Railway supplies `$PORT`; the Dockerfile honours it.

Without `ADMIN_PASSWORD`, a random admin password is generated and printed **once** in the deploy logs.

## How scans work

`fetch → inventory → controls → graph → persist`. Git URLs must be public `http(s)` hosts
(private IPs, `file://` and credentials in URLs are rejected). Zip uploads are extracted with
path-traversal and size checks. Working copies are deleted after each scan.

## Runtime telemetry

```bash
# 1. create a key (admin):  POST /runtime/credentials {"name":"my-app","application_id":"my-app"}
# 2. send events:
curl -X POST $HOST/runtime/events -H "X-Runtime-Key: rtk_..." -H "Content-Type: application/json" \
  -d '{"event_id":"e1","event_type":"llm_call","provider":"OpenAI","model":"gpt-4o"}'
```

Events outside the approved lists (set under **Runtime → Approved policy**) are flagged as violations.

## CI gate

```bash
curl -fsS "$HOST/scans/$SCAN_ID/ci-gate?fail_on=high&strict=true" -H "Authorization: Bearer $TOKEN"
```
Returns HTTP 409 (with `strict=true`) when open findings at/above the threshold or violated controls exist.

## Optional integrations

| Variable | Purpose |
|---|---|
| `GROQ_API_KEY`, `GROQ_MODEL` | LLM explanations / suggested fixes (rule-based fallback if unset) |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI` | SSO |
| `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY` | Create Jira issues from high findings |
| `WEBHOOK_EXPORT_URL` | Default target for scan-completed webhook export |

## Known limits

- The scanner is built in (regex/AST-free). It is not a replacement for semgrep/gitleaks; those can be added behind `scanner.scan_directory`.
- `apply-fix` returns guidance but does not commit to repositories.
- Storage is SQLite; for multiple replicas move `app/db.py` to Postgres.

## What is new in 1.1

- **Source-to-LLM data-flow analysis** (`app/dataflow.py`): Python AST taint tracking from personal/health data to model calls, with masking-barrier detection and one level of call summaries. Limits are stated in the finding.
- **Release gate policy** (`GET/PUT /policy`): blocks on credentials, critical findings, PHI, PII (threshold), unmasked data flow and code-security findings; every decision lists its reasons and the policy version.
- **Waivers with owner, rationale, compensating controls and expiry** (`POST /findings/{id}/waiver`, `GET /waivers`, `DELETE /waivers/{fingerprint}`); credentials cannot be waived; maximum 180 days.
- **Signed evidence packs** (`GET /scans/{id}/evidence-pack/signed`, `POST /evidence-pack/verify`), HMAC-SHA256 with `EVIDENCE_SIGNING_KEY`.
- **Push-triggered rescans** (`POST /integrations/github/webhook`, HMAC-verified, registered repositories only, rate limited).
- **Hardening**: API docs off unless `ENABLE_API_DOCS=1`, security headers, no CORS unless `CORS_ORIGINS` is set, login lockout.

## Repository layout

| Path | What |
|---|---|
| `app/` | The platform (API + bundled UI) |
| `production-frontend/` | Copy of the live production frontend |
| `production-backend-contract/` | OpenAPI snapshot of the live production backend |
| `Start-Platform.bat` | One-click local launcher |