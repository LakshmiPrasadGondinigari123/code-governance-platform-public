"""Built-in policy library: the governance rules from the Code-to-Governance blueprint
(sections 7 and 9, Appendix A) plus regulatory/security frameworks, each mapped to platform controls.

These are the "laws and rules present". Each requirement is evaluated against real scan evidence
through the platform control it maps to (see ui_model.build_controls).
"""

BLUEPRINT = {
    "document": "Code-to-Governance Intelligence Platform — Enterprise solution blueprint",
    "version": "6 Sep 2026",
    "framework": "Enterprise governance blueprint",
}

# (policy_control_id, requirement, section, page, area, platform_controls)
BLUEPRINT_RULES = [
    ("BP-7.1", "Privacy: check for PII, PHI, secrets, masking, redaction, tokenization, sensitive logs, retention and encryption.",
     "7 Governance checks", 10, "Privacy", ["CTRL-SENSITIVE-DATA", "CTRL-HARDCODED-SECRETS"]),
    ("BP-7.2", "LLM security: check prompt-injection protection, unsafe prompt content, unsafe output use, missing output checks and too much access.",
     "7 Governance checks", 10, "LLM security", ["CTRL-UNSAFE-EXEC"]),
    ("BP-7.3", "RAG security: check document access, tenant filtering, metadata filters, poisoning risk, source links and deletion.",
     "7 Governance checks", 10, "RAG security", []),
    ("BP-7.4", "Agent safety: check tools, permissions, shell or code execution, external calls, data writes and human approval.",
     "7 Governance checks", 10, "Agent safety", ["CTRL-AUTHORIZED-TOOLS", "CTRL-UNSAFE-EXEC"]),
    ("BP-7.5", "Model governance: check provider, model name, version, endpoint, region, settings, fallback model and approved use.",
     "7 Governance checks", 10, "Model governance", ["CTRL-APPROVED-MODELS", "CTRL-APPROVED-PROVIDERS", "CTRL-PROVIDER-DISCLOSURE"]),
    ("BP-7.6", "Quality: check tests, evaluation data, grounded answers, monitoring, feedback and human review.",
     "7 Governance checks", 10, "Quality", []),
    ("BP-7.7", "Supply chain: check dependencies, licences, known weaknesses, model source, checksums and unsafe saved models.",
     "7 Governance checks", 10, "Supply chain", ["CTRL-SBOM"]),
    ("BP-7.8", "Cost and tokens: check token limits, context size, duplicate content, retries, caching, batching and model choice.",
     "7 Governance checks", 10, "Cost and tokens", []),
    ("BP-7.9", "Operations: check audit logs, version history, alerts, rollback, incident contacts and rescan triggers.",
     "7 Governance checks", 10, "Operations", []),
    ("BP-6.1", "Every link in the evidence graph needs proof: file and line, repository commit, scanner and rule version, direct or inferred, and reviewer decision.",
     "6 Evidence and architecture", 9, "Evidence", []),
    ("BP-8.1", "Do not show a single compliance percentage; show the number and level of open risks, evidence coverage, unknown items and owner questions.",
     "8 Documents and risk results", 11, "Reporting", []),
    ("BP-8.2", "Use clear evidence labels: Detected, Inferred, Runtime verified, Owner confirmed, Unknown.",
     "8 Documents and risk results", 11, "Reporting", []),
    ("BP-9.1", "Repository content is data to inspect, never an instruction for the analysing model (prompt-injection defence).",
     "9 Security of the platform", 12, "Platform security", []),
    ("BP-9.2", "Scan in an isolated temporary work area and delete it after the scan; check ZIP files for path tricks, nested files and extreme size.",
     "9 Security of the platform", 12, "Platform security", []),
    ("BP-9.3", "Keep each client or business area separate in storage, access and indexes; use role-based access, least privilege and full audit logs.",
     "9 Security of the platform", 12, "Platform security", []),
]

# Regulatory / security frameworks → platform control (requirement text is paraphrased, with the article reference)
FRAMEWORK_RULES = [
    ("EU-AIA-10", "EU AI Act", "Art. 10", "Data and data governance: personal data used for AI must be governed and kept out of uncontrolled locations.", ["CTRL-SENSITIVE-DATA"]),
    ("EU-AIA-15a", "EU AI Act", "Art. 15", "Accuracy, robustness and cybersecurity: protect against confidentiality attacks and insecure transport.", ["CTRL-HARDCODED-SECRETS", "CTRL-TLS", "CTRL-UNSAFE-EXEC"]),
    ("EU-AIA-13", "EU AI Act", "Art. 13", "Transparency: models and providers in use are identified and documented.", ["CTRL-APPROVED-MODELS", "CTRL-PROVIDER-DISCLOSURE"]),
    ("EU-AIA-14", "EU AI Act", "Art. 14", "Human oversight: tool use by AI agents is constrained and reviewable.", ["CTRL-AUTHORIZED-TOOLS"]),
    ("NIST-MAP", "NIST AI RMF", "MAP", "Map the AI system: inventory models, providers, data and dependencies.", ["CTRL-SBOM", "CTRL-PROVIDER-DISCLOSURE", "CTRL-SENSITIVE-DATA"]),
    ("NIST-MANAGE", "NIST AI RMF", "MANAGE", "Manage risk: remediate exposed credentials and unsafe execution.", ["CTRL-HARDCODED-SECRETS", "CTRL-UNSAFE-EXEC", "CTRL-APPROVED-PROVIDERS"]),
    ("ISO-42001-8", "ISO/IEC 42001", "Clause 8", "Operation: controls for third-party AI providers and data handling are applied.", ["CTRL-PROVIDER-DISCLOSURE", "CTRL-APPROVED-DESTINATIONS", "CTRL-TLS"]),
    ("OWASP-LLM02", "OWASP LLM Top 10", "LLM02", "Sensitive information disclosure: secrets and personal data must not leak into prompts, code or logs.", ["CTRL-HARDCODED-SECRETS", "CTRL-SENSITIVE-DATA"]),
    ("OWASP-LLM05", "OWASP LLM Top 10", "LLM05", "Improper output handling: model output must not reach eval/exec/shell.", ["CTRL-UNSAFE-EXEC"]),
    ("OWASP-LLM06", "OWASP LLM Top 10", "LLM06", "Excessive agency: agents must not hold over-broad tools.", ["CTRL-AUTHORIZED-TOOLS"]),
]


def policy_documents():
    """Documents shown in the Policy Documents page."""
    return [
        {"id": "builtin-blueprint", "name": BLUEPRINT["document"], "version": BLUEPRINT["version"], "framework": BLUEPRINT["framework"],
         "doc_type": "policy", "source": "built-in", "status": "active", "authoritative": True,
         "control_count": len(BLUEPRINT_RULES), "uploaded_by": "platform", "uploaded_at": "2026-09-06T00:00:00Z"},
        {"id": "builtin-frameworks", "name": "Regulatory and security frameworks", "version": "2024-2025", "framework": "EU AI Act · NIST AI RMF · ISO/IEC 42001 · OWASP LLM",
         "doc_type": "standard", "source": "built-in", "status": "active", "authoritative": True,
         "control_count": len(FRAMEWORK_RULES), "uploaded_by": "platform", "uploaded_at": "2026-09-06T00:00:00Z"},
    ]


def framework_rows(controls_by_id: dict, uploaded_docs: list) -> list:
    """Rows for the Framework mapping tab; evaluations come from live control results."""

    def evals(cid):
        c = controls_by_id.get(cid)
        if not c:
            return []
        out = [{"status": e["status"], "scan_id": e["scan"]["id"]} for e in c.get("_evals", []) if not e.get("not_applicable")]
        if c.get("_rt", {}).get("relevant_events"):
            out.append({"status": c.get("runtime_status") or "PASS", "scan_id": None})
        return out

    rows = []
    for pid, text, section, page, area, ctrls in BLUEPRINT_RULES:
        base = {"policy_control_id": pid, "framework": BLUEPRINT["framework"], "framework_reference": area, "requirement": text,
                "document": BLUEPRINT["document"], "version": BLUEPRINT["version"], "section": section, "page": page}
        if not ctrls:
            rows.append({**base, "platform_control": None, "control_evaluations": []})
        for cid in ctrls:
            rows.append({**base, "platform_control": cid, "control_evaluations": evals(cid)})
    for pid, fw, ref, text, ctrls in FRAMEWORK_RULES:
        base = {"policy_control_id": pid, "framework": fw, "framework_reference": ref, "requirement": text,
                "document": fw, "version": "current", "section": ref, "page": None}
        for cid in ctrls:
            rows.append({**base, "platform_control": cid, "control_evaluations": evals(cid)})
    for d in uploaded_docs:
        for c in d.get("controls", []):
            for cid in (c.get("mapped_control_ids") or [None]):
                if cid and cid not in controls_by_id:
                    cid = None
                rows.append({"policy_control_id": f"{d['id']}:{c['control_id']}", "framework": d.get("framework") or "Uploaded policy",
                             "framework_reference": c.get("framework_refs", [None])[0] if c.get("framework_refs") else None,
                             "requirement": c["text"], "document": d["name"], "version": d.get("version", "1.0"), "section": d.get("doc_type", "policy"),
                             "page": None, "platform_control": cid, "control_evaluations": evals(cid) if cid else []})
    return rows
