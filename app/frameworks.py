"""Governance framework catalog and the evidence-based control checks."""
import re

FRAMEWORKS = [
    {"id": "eu-ai-act", "name": "EU AI Act", "version": "Regulation (EU) 2024/1689", "kind": "regulation"},
    {"id": "nist-ai-rmf", "name": "NIST AI Risk Management Framework", "version": "1.0", "kind": "framework"},
    {"id": "iso-42001", "name": "ISO/IEC 42001", "version": "2023", "kind": "standard"},
    {"id": "owasp-llm", "name": "OWASP Top 10 for LLM Applications", "version": "2025", "kind": "security"},
]

# type "negative": satisfied when NO matching findings exist (violated otherwise).
# type "positive": satisfied only when evidence (pattern / file / dependency) is found.
CONTROLS = [
    {
        "id": "CTRL-SECRETS", "type": "negative", "categories": ["secret"],
        "title": "No hard-coded credentials",
        "description": "Source code must not contain API keys, tokens or private keys.",
        "refs": {"eu-ai-act": ["Art. 15"], "nist-ai-rmf": ["MANAGE"], "iso-42001": ["Clause 8"], "owasp-llm": ["LLM02"]},
    },
    {
        "id": "CTRL-PII", "type": "negative", "categories": ["pii"],
        "title": "No personal data embedded in code",
        "description": "Personal identifiers must not be hard-coded in source or fixtures.",
        "refs": {"eu-ai-act": ["Art. 10"], "nist-ai-rmf": ["MAP"], "iso-42001": ["Clause 8"], "owasp-llm": ["LLM02"]},
    },
    {
        "id": "CTRL-SAFE-EXEC", "type": "negative", "rule_ids": ["sec.eval-exec", "sec.shell-true", "sec.pickle-loads", "sec.yaml-unsafe-load"],
        "title": "No unsafe code execution / deserialisation",
        "description": "Avoid eval/exec, shell=True and unsafe deserialisation, especially near model output.",
        "refs": {"eu-ai-act": ["Art. 15"], "nist-ai-rmf": ["MANAGE"], "owasp-llm": ["LLM05"]},
    },
    {
        "id": "CTRL-TLS", "type": "negative", "rule_ids": ["sec.tls-verify-disabled", "sec.insecure-http"],
        "title": "Encrypted transport only",
        "description": "TLS verification must stay enabled and external calls must use HTTPS.",
        "refs": {"eu-ai-act": ["Art. 15"], "iso-42001": ["Clause 8"], "owasp-llm": ["LLM02"]},
    },
    {
        "id": "CTRL-LOGGING", "type": "positive",
        "title": "Audit logging and traceability",
        "description": "AI interactions and decisions are logged so they can be reconstructed.",
        "patterns": [r"\bimport logging\b", r"\blogging\.getLogger\b", r"\bstructlog\b", r"\bopentelemetry\b", r"\blangfuse\b", r"\blangsmith\b", r"\bwinston\b", r"\bpino\b", r"console\.(?:log|error)\("],
        "deps": ["structlog", "opentelemetry-api", "opentelemetry-sdk", "langfuse", "langsmith", "winston", "pino"],
        "refs": {"eu-ai-act": ["Art. 12"], "nist-ai-rmf": ["MEASURE"], "iso-42001": ["Clause 9.1"], "owasp-llm": ["LLM10"]},
    },
    {
        "id": "CTRL-HUMAN-OVERSIGHT", "type": "positive",
        "title": "Human oversight of AI output",
        "description": "A reviewer/approval step exists before AI output has effect.",
        "patterns": [r"human[_ -]?(?:in[_ -]the[_ -]loop|review|approval|oversight)", r"requires?[_-]approval", r"manual[_-]review", r"\bhitl\b", r"needs[_-]review"],
        "refs": {"eu-ai-act": ["Art. 14"], "nist-ai-rmf": ["GOVERN"], "iso-42001": ["Clause 8"], "owasp-llm": ["LLM06"]},
    },
    {
        "id": "CTRL-INPUT-GUARD", "type": "positive",
        "title": "Prompt-injection / input guardrails",
        "description": "User and retrieved content is screened before reaching a model.",
        "patterns": [r"guardrail", r"prompt[_ -]?injection", r"sanitiz(?:e|ation)", r"llm[_-]guard", r"nemoguardrails", r"\brebuff\b"],
        "deps": ["guardrails-ai", "nemoguardrails", "llm-guard", "rebuff", "presidio-analyzer"],
        "refs": {"eu-ai-act": ["Art. 15"], "nist-ai-rmf": ["MANAGE"], "owasp-llm": ["LLM01"]},
    },
    {
        "id": "CTRL-OUTPUT-VALIDATION", "type": "positive",
        "title": "Model output validation",
        "description": "Model output is validated against a schema before downstream use.",
        "patterns": [r"response_format", r"json[_-]?schema", r"model_validate", r"BaseModel\)", r"\bzod\b", r"\bajv\b"],
        "deps": ["pydantic", "jsonschema", "zod", "ajv"],
        "refs": {"eu-ai-act": ["Art. 15"], "nist-ai-rmf": ["MEASURE"], "owasp-llm": ["LLM05"]},
    },
    {
        "id": "CTRL-RATE-LIMIT", "type": "positive",
        "title": "Usage and cost limits",
        "description": "Rate limits, token caps or budgets bound model consumption.",
        "patterns": [r"rate[_ -]?limit", r"\bslowapi\b", r"max_tokens", r"max_budget", r"\bthrottle\b"],
        "deps": ["slowapi", "ratelimit", "express-rate-limit"],
        "refs": {"nist-ai-rmf": ["MANAGE"], "iso-42001": ["Clause 8"], "owasp-llm": ["LLM10"]},
    },
    {
        "id": "CTRL-MODEL-DOC", "type": "positive",
        "title": "Model documentation (model card)",
        "description": "Models in use are documented with purpose, limits and data provenance.",
        "patterns": [r"model[_ -]card", r"intended[_ -]use"],
        "files": [r"(?i)model[_-]?card", r"(?i)(?:^|/)docs?/.*(?:model|ai)"],
        "refs": {"eu-ai-act": ["Art. 13"], "nist-ai-rmf": ["GOVERN"], "iso-42001": ["Clause 7.5"]},
    },
    {
        "id": "CTRL-DATA-GOVERNANCE", "type": "positive",
        "title": "Data lineage and quality governance",
        "description": "Data sources, retention and quality checks are defined.",
        "patterns": [r"data[_ -]?(?:lineage|governance|retention|catalog)", r"great_expectations", r"\bdvc\b"],
        "deps": ["great-expectations", "dvc", "pandera"],
        "refs": {"eu-ai-act": ["Art. 10"], "nist-ai-rmf": ["MAP"], "iso-42001": ["Clause 8"]},
    },
    {
        "id": "CTRL-TESTING", "type": "positive",
        "title": "Automated testing / evaluation",
        "description": "Automated tests or evaluations cover the AI-enabled behaviour.",
        "files": [r"(?i)(?:^|/)tests?/", r"(?i)test_[^/]*\.py$", r"(?i)\.(?:test|spec)\.[jt]sx?$"],
        "deps": ["pytest", "jest", "vitest", "deepeval", "ragas", "promptfoo"],
        "refs": {"eu-ai-act": ["Art. 15"], "nist-ai-rmf": ["MEASURE"], "iso-42001": ["Clause 9.1"]},
    },
    {
        "id": "CTRL-RISK-REGISTER", "type": "positive",
        "title": "Documented risk assessment",
        "description": "A risk assessment or register exists for the AI system.",
        "files": [r"(?i)risk[_-]?(?:assessment|register|management)", r"(?i)threat[_-]?model"],
        "patterns": [r"risk[_ -]assessment", r"risk[_ -]register"],
        "refs": {"eu-ai-act": ["Art. 9"], "nist-ai-rmf": ["MAP"], "iso-42001": ["Clause 6.1"]},
    },
    {
        "id": "CTRL-SBOM", "type": "positive",
        "title": "Dependency inventory (SBOM source)",
        "description": "Dependencies are declared in a manifest so a bill of materials can be produced.",
        "files": [r"(?i)(?:^|/)requirements[^/]*\.txt$", r"(?i)(?:^|/)package\.json$", r"(?i)(?:^|/)pyproject\.toml$", r"(?i)(?:^|/)go\.mod$", r"(?i)(?:^|/)pom\.xml$"],
        "refs": {"nist-ai-rmf": ["MAP"], "iso-42001": ["Clause 8"]},
    },
]

_compiled = {}


def compiled_patterns(control: dict):
    cid = control["id"]
    if cid not in _compiled:
        _compiled[cid] = (
            [re.compile(p, re.I) for p in control.get("patterns", [])],
            [re.compile(p) for p in control.get("files", [])],
        )
    return _compiled[cid]


def evaluate(findings: list, components: list, evidence: dict) -> list:
    """evidence: {control_id: [{"file":..., "line":...}]} gathered while scanning."""
    dep_names = {c["name"].lower().replace("_", "-") for c in components}
    results = []
    for c in CONTROLS:
        ev = list(evidence.get(c["id"], []))
        status, reasons = "missing_evidence", []
        if c["type"] == "negative":
            bad = [
                f for f in findings
                if f["category"] in c.get("categories", []) or f["rule_id"] in c.get("rule_ids", [])
            ]
            if bad:
                status = "violated"
                reasons.append(f"{len(bad)} finding(s) violate this control")
                ev = [{"file": f["file"], "line": f["line"], "finding_id": f.get("id")} for f in bad[:20]]
            else:
                status = "satisfied"
                reasons.append("No violating findings in the scan")
        else:
            hit_deps = sorted(d for d in c.get("deps", []) if d.lower() in dep_names)
            for d in hit_deps:
                ev.append({"file": "(dependency)", "line": 0, "dependency": d})
            if ev:
                status = "satisfied"
                reasons.append(f"{len(ev)} piece(s) of supporting evidence found")
            else:
                reasons.append("No supporting evidence found in code, files or dependencies")
        results.append(
            {
                "control_id": c["id"],
                "title": c["title"],
                "description": c["description"],
                "type": c["type"],
                "status": status,
                "reasons": reasons,
                "evidence": ev[:25],
                "evidence_count": len(ev),
                "framework_refs": [
                    {"framework": fw, "refs": refs} for fw, refs in c["refs"].items()
                ],
            }
        )
    return results


def catalog() -> list:
    out = []
    for fw in FRAMEWORKS:
        controls = [
            {"control_id": c["id"], "title": c["title"], "refs": c["refs"][fw["id"]]}
            for c in CONTROLS
            if fw["id"] in c["refs"]
        ]
        out.append({**fw, "controls": controls})
    return out
