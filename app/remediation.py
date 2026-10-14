"""Automatic, evidence-grounded fix suggestions for findings, controls and blueprint checks.

Suggestions are deterministic (rule-based) so they are always available and reproducible; an LLM
can add narrative on top but is never required. They describe what to change, how to verify it,
and which framework requirement the change helps satisfy. They are guidance, not a compliance claim.
"""

_SECRET = {
    "summary": "Revoke and rotate the exposed credential, then load it from the environment or a secrets manager.",
    "steps": [
        "Treat the credential as compromised: revoke or rotate it at the provider now.",
        "Remove it from the code and purge it from git history (git filter-repo or BFG), then force-push.",
        "Read the value from an environment variable or a secrets manager (Railway variables, Vault, AWS Secrets Manager).",
        "Add a pre-commit secret scan (gitleaks) and a CI gate so it cannot return.",
    ],
    "example": 'import os\napi_key = os.environ["OPENAI_API_KEY"]  # never hard-code keys\nclient = OpenAI(api_key=api_key)',
    "verify": "Rescan: the Hardcoded Secrets control should turn PASS and the finding disappears.",
    "effort": "Low",
    "frameworks": ["OWASP LLM02", "EU AI Act Art. 15", "NIST AI RMF MANAGE"],
}
_PII = {
    "summary": "Remove real personal data from code and mask it before it can reach a prompt or a log.",
    "steps": [
        "Replace the real value with synthetic test data (Faker) or reference a governed data store.",
        "Add a redaction/masking step (e.g. Microsoft Presidio) before any text is sent to a model or written to logs.",
        "Document the data category, lawful basis and retention for this data path.",
        "Add a unit test asserting prompts contain no raw identifiers.",
    ],
    "example": ("from presidio_analyzer import AnalyzerEngine\nfrom presidio_anonymizer import AnonymizerEngine\n"
                "text = anonymizer.anonymize(text=raw, analyzer_results=analyzer.analyze(text=raw, language='en')).text\n"
                "response = llm.invoke(text)  # only masked text leaves the boundary"),
    "verify": "Rescan: Sensitive Data in Repository should turn PASS; blueprint check 3 (masking) should show Present.",
    "effort": "Medium",
    "frameworks": ["EU AI Act Art. 10", "OWASP LLM02", "ISO/IEC 42001 Clause 8"],
}
RULES = {
    "sec.eval-exec": {
        "summary": "Never evaluate strings; parse structured output and dispatch to an allow-list.",
        "steps": ["Replace eval/exec with json.loads plus schema validation (pydantic).",
                  "Map allowed actions to functions in a dict; reject anything else.",
                  "If model output can reach this call, add a human-approval step."],
        "example": 'import json\nALLOWED = {"search": search, "summarise": summarise}\ncmd = json.loads(model_output)\nfn = ALLOWED[cmd["action"]]  # KeyError = rejected\nfn(**cmd["args"])',
        "verify": "Rescan: Unsafe Code Execution control turns PASS.", "effort": "Medium",
        "frameworks": ["OWASP LLM05", "EU AI Act Art. 15"]},
    "sec.shell-true": {
        "summary": "Pass an argument list and drop shell=True so input cannot inject commands.",
        "steps": ["Use subprocess.run([...], shell=False).", "Validate every argument against an allow-list."],
        "example": 'subprocess.run(["git", "clone", "--", url, dest], check=True)  # no shell',
        "verify": "Rescan: Unsafe Code Execution control turns PASS.", "effort": "Low", "frameworks": ["OWASP LLM05"]},
    "sec.pickle-loads": {
        "summary": "Do not unpickle data you did not produce; use JSON or a signed format.",
        "steps": ["Replace pickle with json / safetensors.", "If pickle is unavoidable, verify a checksum or signature first."],
        "example": "import json\ndata = json.loads(raw)", "verify": "Rescan: no pickle findings.", "effort": "Medium", "frameworks": ["OWASP LLM05"]},
    "sec.yaml-unsafe-load": {
        "summary": "Use yaml.safe_load.", "steps": ["Replace yaml.load(...) with yaml.safe_load(...)."],
        "example": "config = yaml.safe_load(stream)", "verify": "Rescan.", "effort": "Low", "frameworks": ["OWASP LLM05"]},
    "sec.tls-verify-disabled": {
        "summary": "Re-enable certificate verification and install the proper CA bundle.",
        "steps": ["Remove verify=False / rejectUnauthorized:false.", "Point REQUESTS_CA_BUNDLE (or NODE_EXTRA_CA_CERTS) at your corporate CA if needed."],
        "example": "resp = requests.get(url, timeout=10)  # verify=True is the default",
        "verify": "Rescan: Encrypted Transport control turns PASS.", "effort": "Low", "frameworks": ["EU AI Act Art. 15", "OWASP LLM02"]},
    "sec.insecure-http": {
        "summary": "Use HTTPS endpoints for every external call.",
        "steps": ["Change http:// to https://.", "Add the host to the approved API hosts policy once reviewed."],
        "example": 'BASE_URL = "https://api.partner.io/v1"', "verify": "Rescan.", "effort": "Low", "frameworks": ["EU AI Act Art. 15"]},
    "sec.debug-enabled": {
        "summary": "Disable debug mode outside local development.",
        "steps": ["Drive debug from an environment variable that defaults to False."],
        "example": 'DEBUG = os.getenv("DEBUG", "0") == "1"', "verify": "Rescan.", "effort": "Low", "frameworks": ["ISO/IEC 42001 Clause 8"]},
    "flow.phi-to-llm": {
        "summary": "Health information reaches an AI model with no masking step. De-identify it before the call.",
        "steps": ["Remove the patient identifiers (name, MRN, date of birth, address, phone) from the text before it is placed in the prompt.",
                  "Keep a re-identification map on your side only, never in the prompt.",
                  "Confirm a signed business-associate agreement and a zero-retention endpoint with the model provider.",
                  "Add a test that fails when a raw identifier reaches the prompt builder."],
        "example": "safe_text = deidentify(record['diagnosis'] + ' ' + record['medication'])  # no name / MRN / DOB\nclient.chat.completions.create(model=MODEL, messages=[{'role': 'user', 'content': safe_text}])",
        "verify": "Rescan: the flow disappears or is reported as 'masked before reaching an AI model'.", "effort": "Medium",
        "frameworks": ["HIPAA 164.514(b)", "GDPR Art. 9", "OWASP LLM02", "NIST AI RMF MANAGE"]},
    "flow.pii-to-llm": {
        "summary": "Personal data reaches an AI model with no masking step. Mask it before the call.",
        "steps": ["Mask or tokenise names, e-mails, phone numbers and IDs before building the prompt.",
                  "Send only the fields the task needs (data minimisation).",
                  "Confirm a data-processing agreement with the provider.",
                  "Log the masked prompt, never the original."],
        "example": "safe_text = mask_pii(user_text)  # e.g. Presidio AnonymizerEngine\nllm.invoke(safe_text)",
        "verify": "Rescan: the flow disappears or is reported as masked.", "effort": "Medium",
        "frameworks": ["GDPR Art. 5(1)(c)", "GDPR Art. 28", "OWASP LLM02"]},
    "flow.masked-before-llm": {
        "summary": "A masking step was observed before the model call. Keep it covered by a test.",
        "steps": ["Add a regression test that sends a sample identifier through this path and asserts it never reaches the model client.",
                  "Review the masking function for coverage of every identifier type you handle."],
        "example": "assert 'MRN-' not in captured_prompt", "verify": "Rescan keeps this as a positive finding.", "effort": "Low",
        "frameworks": ["NIST AI RMF MEASURE"]},    "ai.model-usage": {
        "summary": "Record this model in the approved-model policy, pin its version and document it in a model card.",
        "steps": ["Review the model with the model owner (purpose, data sent, region, retention).",
                  "Add it under AI Usage → Policy → Approved models so the control can pass.",
                  "Pin an exact version string rather than a floating alias.",
                  "Create or update the model card (Evidence packs → model card)."],
        "example": 'MODEL = "gpt-4o-2024-08-06"  # pinned, approved, documented',
        "verify": "Approved Model Use control turns PASS and blueprint check 8 is Present.", "effort": "Low",
        "frameworks": ["EU AI Act Art. 13", "NIST AI RMF GOVERN", "ISO/IEC 42001 Clause 7.5"]},
    "ai.provider-sdk": {
        "summary": "Confirm a data-processing agreement and approve the provider before production data is sent.",
        "steps": ["Confirm contract terms: data retention, training use, region, sub-processors.",
                  "Add the provider under AI Usage → Policy → Approved providers.",
                  "Configure zero-retention / enterprise endpoints where available.",
                  "Configure a fallback model or degrade gracefully if the provider is down."],
        "example": '# keep provider config explicit and reviewable\nPROVIDER = {"name": "OpenAI", "endpoint": "https://api.openai.com/v1", "region": "us"}',
        "verify": "Approved Provider Use control turns PASS.", "effort": "Medium",
        "frameworks": ["EU AI Act Art. 10", "OWASP LLM02", "ISO/IEC 42001 Clause 8"]},
}

CHECKS = {
    1: ("Mask or tokenise personal data before the model call.", ["Introduce a redaction step before the LLM client call.", "Log only masked content.", "Add a test that fails if raw identifiers reach the prompt builder."], "text = redact(text)\nllm.invoke(text)"),
    2: ("Protect health data: de-identify before any model call and confirm a BAA with the provider.", ["De-identify PHI (remove the 18 HIPAA identifiers).", "Confirm a BAA/DPA with the provider.", "Prefer a private/enterprise endpoint."], "text = deidentify(text)"),
    3: ("Add a masking/redaction step.", ["Adopt Microsoft Presidio or an equivalent.", "Apply it at every boundary where text leaves the service."], "AnalyzerEngine().analyze(text=text, language='en')"),
    4: ("Move credentials out of code.", ["Rotate exposed secrets.", "Use environment variables or a secrets manager."], 'os.environ["API_KEY"]'),
    5: ("Stop logging raw prompts.", ["Log a hash or length, not content.", "Gate verbose logging behind a debug flag that is off in production."], 'log.info("prompt_len=%d", len(prompt))'),
    6: ("Stop logging raw model output.", ["Log metadata (tokens, latency) not content.", "Redact before logging if content is needed."], 'log.info("tokens=%d", usage.total_tokens)'),
    7: ("Make the provider explicit in configuration.", ["Declare provider, endpoint and region in one config module."], 'PROVIDER = "openai"'),
    8: ("Pin the exact model name and version.", ["Use dated model identifiers.", "Record them in the model card."], 'MODEL = "gpt-4o-2024-08-06"'),
    9: ("Set a maximum output token limit.", ["Set max_tokens on every completion call.", "Set a per-request and per-day budget."], "client.chat.completions.create(..., max_tokens=512)"),
    10: ("Bound the conversation context.", ["Trim or summarise history to a token budget before each call."], "messages = messages[-12:]"),
    11: ("Document the RAG data sources.", ["List sources, owners and refresh cadence.", "Enforce document-level access control at retrieval."], "retriever.search(query, filter={'tenant': tenant_id})"),
    12: ("Document the vector store.", ["Record hosting, encryption, deletion and tenant isolation."], "index = Chroma(collection_name=f'tenant_{tenant_id}')"),
    13: ("Add prompt-injection protection.", ["Treat retrieved and user text as untrusted data.", "Add an input screening/guardrail layer (NeMo Guardrails, LLM Guard).", "Never let retrieved text change tool permissions."], "safe = guard.scan_prompt(user_input)"),
    14: ("Validate model output.", ["Request structured output and validate with a schema.", "Moderate output before showing it."], "Answer.model_validate_json(raw)"),
    15: ("Document the agent's purpose and boundaries.", ["State what the agent may and may not do."], "# AGENT_SCOPE.md"),
    16: ("Declare the tools an agent can use.", ["Keep an explicit allow-list of tools."], "tools = [search_docs, create_ticket]"),
    17: ("Narrow tool permissions.", ["Remove shell, file-write and DB-mutation tools or put them behind approval.", "Use least-privilege credentials per tool."], "# remove ShellTool; use a typed, read-only tool"),
    18: ("Remove dynamic code/shell execution.", ["Replace with typed functions and an allow-list."], "ALLOWED[cmd]()"),
    19: ("Review and allow-list external hosts.", ["List every outbound destination.", "Add reviewed hosts to Approved API hosts."], "ALLOWED_HOSTS = {'api.openai.com'}"),
    20: ("Add a human approval step for consequential actions.", ["Require approval before writes, payments or external messages."], "if action.risky: await approval.request(action)"),
    21: ("Configure a fallback model.", ["Define a secondary approved model and test failover."], "llm.with_fallbacks([backup_llm])"),
    22: ("Add dependency vulnerability scanning.", ["Run pip-audit / npm audit / Trivy in CI."], "pip-audit -r requirements.txt"),
    23: ("Avoid pickle-based model files.", ["Prefer safetensors; verify checksums for any binary artefact."], "load_file('model.safetensors')"),
    24: ("Enable encryption in transit and at rest.", ["Use HTTPS/TLS everywhere.", "Encrypt stored prompts and evidence."], "ssl_context = ssl.create_default_context()"),
    25: ("Authenticate every caller.", ["Require a token/SSO on every API route."], "Depends(get_current_user)"),
    26: ("Enforce role-based authorisation.", ["Check roles on each sensitive operation."], "require_role('admin')"),
    27: ("Add monitoring and tracing.", ["Emit structured logs and traces (OpenTelemetry).", "Alert on error rate and cost."], "tracer.start_as_current_span('llm_call')"),
    28: ("Add evaluation tests.", ["Create a small golden dataset.", "Run it in CI (promptfoo, deepeval, ragas)."], "pytest tests/eval/"),
    29: ("Create a model card.", ["Document purpose, data, limits and owner (use Evidence packs → model card)."], "docs/MODEL_CARD.md"),
    30: ("Create an architecture document.", ["Draw components, data flows and trust boundaries (Architecture page can export diagrams)."], "docs/architecture.md"),
}


def for_finding(f: dict) -> dict:
    rid, cat = f.get("rule_id", ""), f.get("category", "")
    base = RULES.get(rid)
    if base is None:
        if cat == "secret":
            base = _SECRET
        elif cat == "pii":
            base = _PII
        else:
            base = {"summary": "Review this finding in context and either fix it or record an accepted-risk decision.",
                    "steps": ["Confirm the finding is real.", "Fix, or document an exception with owner and expiry."],
                    "example": "", "verify": "Rescan.", "effort": "Medium", "frameworks": []}
    return {**base, "applies_to": {"file": f.get("file"), "line": f.get("line"), "rule_id": rid}}


def for_check(cid: int) -> dict:
    s, steps, ex = CHECKS.get(cid, ("Review this check.", [], ""))
    return {"summary": s, "steps": steps, "example": ex, "verify": "Rescan to re-evaluate this blueprint check.", "effort": "Medium", "frameworks": []}


CONTROL_FIXES = {
    "CTRL-SENSITIVE-DATA": _PII,
    "CTRL-HARDCODED-SECRETS": _SECRET,
    "CTRL-UNSAFE-EXEC": RULES["sec.eval-exec"],
    "CTRL-TLS": RULES["sec.tls-verify-disabled"],
    "CTRL-APPROVED-MODELS": RULES["ai.model-usage"],
    "CTRL-PROVIDER-DISCLOSURE": RULES["ai.provider-sdk"],
    "CTRL-APPROVED-PROVIDERS": RULES["ai.provider-sdk"],
    "CTRL-SBOM": {"summary": "Declare dependencies in a manifest.", "steps": ["Add requirements.txt / package.json with pinned versions."],
                  "example": "openai==1.30.0\npydantic==2.7.0", "verify": "SBOM control turns PASS.", "effort": "Low", "frameworks": []},
    "CTRL-AUTHORIZED-TOOLS": {"summary": "Restrict tools to an approved list and require approval for risky actions.",
                              "steps": ["Add approved tool names under AI Usage → Policy.", "Remove tools with shell/file/DB reach."],
                              "example": "approved_tools = ['search_docs', 'create_ticket']", "verify": "Control turns PASS.", "effort": "Medium", "frameworks": ["OWASP LLM06"]},
    "CTRL-APPROVED-DESTINATIONS": {"summary": "Review and allow-list outbound API hosts.",
                                   "steps": ["Add reviewed hosts under AI Usage → Policy → Approved API hosts."],
                                   "example": "approved_api_hosts = ['api.openai.com']", "verify": "Control turns PASS.", "effort": "Low", "frameworks": []},
}


def for_control(control_id: str) -> dict:
    return CONTROL_FIXES.get(control_id, {"summary": "Review the evidence and address the gap.", "steps": [], "example": "", "verify": "Rescan.", "effort": "Medium", "frameworks": []})
