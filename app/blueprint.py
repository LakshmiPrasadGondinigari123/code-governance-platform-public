"""The 30 first governance checks (blueprint Appendix A) and the nine check areas (Section 7).

Detection is deterministic and evidence-bearing (file + line). A check with no honest detector
is reported NO_DETECTOR — it is never silently passed or failed (blueprint rule: tools find
facts; people confirm what the code cannot prove).
"""
import re

# kind: risk  -> FOUND means a problem was found
#       control -> FOUND means the safeguard is present
#       inventory -> FOUND means the item was detected (neutral)
CHECKS = [
    # id, area, kind, label, detail, line_patterns, file_patterns, special
    (1, "Privacy", "risk", "PII reaches an LLM", "Personal data is handled in code that calls a model.", [], [], "pii_to_llm"),
    (2, "Privacy", "risk", "PHI reaches an LLM", "Health data is handled in code that calls a model.", [], [], "phi_to_llm"),
    (3, "Privacy", "control", "Masking or redaction is present", "Redaction/anonymisation logic (e.g. Presidio) is used.",
     [r"presidio", r"\bredact\w*", r"\bmask_\w+|\bmasking\b|\bmask\(", r"anonymi[sz]e", r"\bscrub\w*", r"tokeni[sz]e_pii"], [], None),
    (4, "Privacy", "risk", "Secrets are stored in code", "Credentials committed to source.", [], [], "secrets"),
    (5, "Privacy", "risk", "Sensitive prompts are logged", "Prompt or message content is written to logs.",
     [r"(?i)\b(?:log(?:ger)?\.\w+|print|console\.log)\s*\(.*\b(?:prompt|messages|user_input|query)\b"], [], None),
    (6, "Privacy", "risk", "Sensitive responses are logged", "Model output is written to logs.",
     [r"(?i)\b(?:log(?:ger)?\.\w+|print|console\.log)\s*\(.*\b(?:response|completion|answer|output|result)\b"], [], None),
    (7, "Model governance", "inventory", "Model provider is known", "At least one AI provider is identified.", [], [], "providers"),
    (8, "Model governance", "inventory", "Model name and version are known", "Concrete model identifiers are present in code.", [], [], "models"),
    (9, "Cost and tokens", "control", "Token limit is set", "A maximum output/token limit is configured.",
     [r"\bmax_(?:output_|completion_|new_)?tokens\b", r"\bmaxTokens\b", r"\bmax_tokens_to_sample\b"], [], None),
    (10, "Cost and tokens", "risk", "Context can grow without a limit", "Conversation history is appended with no trimming.", [], [], "unbounded_context"),
    (11, "RAG security", "inventory", "RAG is used", "Retrieval-augmented generation components are present.",
     [r"(?i)\bretriev\w+|RetrievalQA|as_retriever|similarity_search|\bembedding\w*|VectorStoreIndex|query_engine"], [], None),
    (12, "RAG security", "inventory", "Vector store is used", "A vector database or index is used.", [], [], "vector_store"),
    (13, "LLM security", "control", "Prompt-injection protection is present", "Guardrails or input screening are used.",
     [r"(?i)guardrail", r"prompt[_ -]?injection", r"llm[_-]?guard", r"nemoguardrails", r"\brebuff\b", r"sanitize_prompt|sanitise_prompt"], [], None),
    (14, "LLM security", "control", "Output is checked", "Model output is validated or moderated.",
     [r"(?i)response_format", r"json[_-]?schema", r"output_parser|OutputParser", r"model_validate|parse_obj|\.validate\(", r"moderation", r"\bpydantic\b"], [], None),
    (15, "Agent safety", "inventory", "Agent is used", "An autonomous agent loop is present.",
     [r"(?i)\bAgentExecutor\b|\bcreate_(?:react|openai_tools|tool_calling)_agent\b|\blanggraph\b|\bcrewai\b|\bautogen\b|\bagent\.run\b|class \w*Agent\b"], [], None),
    (16, "Agent safety", "inventory", "Agent tools are listed", "Tools exposed to a model are declared.",
     [r"(?i)\btools\s*=\s*\[", r"@tool\b", r"\bTool\(", r"\bStructuredTool\b", r"\bfunctions\s*=\s*\["], [], None),
    (17, "Agent safety", "risk", "Tool access is too broad", "A tool can reach shell, filesystem writes or database mutation.",
     [r"(?i)\b(?:ShellTool|BashTool|PythonREPLTool|FileManagementToolkit|write_file|delete_file|drop\s+table|SQLDatabaseToolkit)\b"], [], None),
    (18, "Agent safety", "risk", "Shell or code execution is allowed", "The code can execute shell commands or dynamic code.", [], [], "code_exec"),
    (19, "Agent safety", "inventory", "External API calls are made", "Outbound HTTP calls are present.", [], [], "hosts"),
    (20, "Agent safety", "control", "Human approval is present", "A human approval / review step exists.",
     [r"(?i)human[_ -]?(?:in[_ -]the[_ -]loop|approval|review)", r"interrupt_before|require_(?:confirmation|approval)|needs_approval|\bhitl\b"], [], None),
    (21, "Model governance", "inventory", "Fallback model is used", "A secondary/fallback model is configured.",
     [r"(?i)with_fallbacks|fallback[_ ]model|fallbacks\s*=|model_fallback"], [], None),
    (22, "Supply chain", "risk", "Dependency risks exist", "Known-vulnerable dependencies (needs a vulnerability database).", [], [], "no_detector"),
    (23, "Supply chain", "risk", "Unsafe model files exist", "Pickle-based or opaque model artefacts are committed.", [],
     [r"(?i)\.(?:pkl|pickle|pt|pth|joblib|bin|h5|onnx|safetensors)$"], None),
    (24, "Privacy", "control", "Encryption settings are present", "TLS/encryption configuration or libraries are used.",
     [r"(?i)\bssl\b|\btls\b|\bencrypt\w*|\bfernet\b|\bkms\b|\baes[-_]?\d*", r"https://"], [], None),
    (25, "Operations", "control", "Authentication is present", "Callers are authenticated.",
     [r"(?i)\bjwt\b|oauth|authenticate\w*|\blogin_required\b|HTTPBearer|OAuth2PasswordBearer|\bpassport\b|\bNextAuth\b|\bclerk\b"], [], None),
    (26, "Operations", "control", "Authorization is present", "Roles/permissions are enforced.",
     [r"(?i)\brbac\b|\bpermission\w*|require_role|authori[sz]e\w*|\bis_admin\b|\bhas_role\b|\bcasbin\b|\bopa\b"], [], None),
    (27, "Operations", "control", "Monitoring is present", "Logging/metrics/tracing is configured.",
     [r"(?i)opentelemetry|prometheus|sentry|datadog|langfuse|langsmith|\bstructlog\b|logging\.getLogger|\bwinston\b|\bpino\b"], [], None),
    (28, "Quality", "control", "Evaluation tests exist", "Automated tests or LLM evaluations exist.",
     [r"(?i)\bragas\b|deepeval|promptfoo|\btruelens\b|\bevaluat(?:e|or|ion)\b.*\bdataset\b"],
     [r"(?i)(?:^|/)tests?/", r"(?i)test_[^/]*\.py$", r"(?i)\.(?:test|spec)\.[jt]sx?$"], None),
    (29, "Model governance", "control", "Model card exists", "Model/system documentation is present.",
     [r"(?i)model[_ -]card|system[_ -]card"], [r"(?i)model[_-]?card", r"(?i)system[_-]?card"], None),
    (30, "Operations", "control", "Architecture document exists", "An architecture or design document is present.",
     [], [r"(?i)architecture[^/]*\.(?:md|rst|txt|pdf|png|svg|drawio)$", r"(?i)(?:^|/)docs?/.*(?:architecture|design)", r"(?i)(?:^|/)adr/", r"(?i)design[_-]?doc"], None),
]

AREAS = [
    ("Privacy", "PII, PHI, secrets, masking, redaction, tokenization, sensitive logs, retention, encryption"),
    ("LLM security", "Prompt injection protection, unsafe prompt content, unsafe output use, missing output checks, too much access"),
    ("RAG security", "Document access, tenant filtering, metadata filters, poisoning risk, source links, deletion"),
    ("Agent safety", "Tools, permissions, shell or code execution, external calls, data writes, human approval"),
    ("Model governance", "Provider, model name, version, endpoint, region, settings, fallback model, approved use"),
    ("Quality", "Tests, evaluation data, grounded answers, monitoring, feedback, human review"),
    ("Supply chain", "Dependencies, licences, known weaknesses, model source, checksums, unsafe saved models"),
    ("Cost and tokens", "Token limits, context size, duplicate content, retries, caching, batching, model choice"),
    ("Operations", "Audit logs, version history, alerts, rollback, incident contacts, rescan triggers"),
]

LLM_CALL = re.compile(
    r"(?i)chat\.completions\.create|\.messages\.create|\bChatOpenAI\b|\bChatAnthropic\b|\bChatGroq\b|\bgenerate_content\b|"
    r"\bAzureOpenAI\b|\bopenai\.|\banthropic\.|\bllm\.(?:invoke|predict|complete)|\.invoke\(|\bChatCompletion\b|\bgroq\b.*\bchat\b"
)
PII_MARK = re.compile(r"(?i)\b(?:ssn|social_security|e-?mail|phone(?:_number)?|date_of_birth|\bdob\b|first_name|last_name|full_name|home_address|passport|credit_card|customer_(?:name|data)|user_(?:email|name))\b")
PHI_MARK = re.compile(r"(?i)\b(?:patient\w*|diagnos\w+|\bmrn\b|icd[-_]?10|medical\w*|prescription\w*|\bhipaa\b|\bphi\b|health_record|clinical\w*)\b")
CODE_EXEC = re.compile(r"(?<![\w.])(?:eval|exec)\s*\(|os\.system\(|subprocess\.(?:run|Popen|call|check_output)|shell\s*=\s*True|PythonREPL|ShellTool")
CONTEXT_APPEND = re.compile(r"(?i)(?:messages|history|chat_history|conversation)\w*\.append\(")
CONTEXT_TRIM = re.compile(r"(?i)\[-\d+:\]|truncate|trim_messages|max_history|\.pop\(0\)|ConversationBufferWindow|token_limit|summari[sz]e")

_compiled = {c[0]: ([re.compile(p) for p in c[5]], [re.compile(p) for p in c[6]]) for c in CHECKS}


def _scoped(rx):
    pat = rx.pattern
    if pat.startswith("(?i)"):
        return "(?i:" + pat[4:] + ")"
    return "(?:" + pat + ")"


_ALL_LINE = re.compile("|".join(_scoped(r) for r in (
    [rx for lr, _ in _compiled.values() for rx in lr] + [LLM_CALL, PII_MARK, PHI_MARK, CODE_EXEC, CONTEXT_APPEND, CONTEXT_TRIM])))


class Collector:
    """Gathers per-check evidence during the single scanner pass."""

    def __init__(self):
        self.ev = {c[0]: [] for c in CHECKS}
        self.llm_files = {}      # file -> first llm line
        self.pii_files = {}      # file -> first pii marker line
        self.phi_files = {}
        self.exec_lines = []
        self.append_files = {}
        self.trim_files = set()

    def _add(self, cid, rel, line):
        lst = self.ev[cid]
        if len(lst) < 6 and not any(e["file"] == rel and e["line"] == line for e in lst):
            lst.append({"file": rel, "line": line})

    def files(self, rels):
        for cid, (_, file_rx) in _compiled.items():
            for rel in rels:
                if any(rx.search(rel) for rx in file_rx):
                    self._add(cid, rel, 0)

    def line(self, rel, no, text, is_test=False, is_doc=False):
        if is_doc or not _ALL_LINE.search(text):
            return
        for cid, (line_rx, _) in _compiled.items():
            if line_rx and any(rx.search(text) for rx in line_rx):
                if is_test and cid not in (28,):
                    continue
                self._add(cid, rel, no)
        if is_test:
            return
        if LLM_CALL.search(text):
            self.llm_files.setdefault(rel, no)
        if PII_MARK.search(text):
            self.pii_files.setdefault(rel, no)
        if PHI_MARK.search(text):
            self.phi_files.setdefault(rel, no)
        if CODE_EXEC.search(text):
            self.exec_lines.append((rel, no))
        if CONTEXT_APPEND.search(text):
            self.append_files.setdefault(rel, no)
        if CONTEXT_TRIM.search(text):
            self.trim_files.add(rel)

    def finish(self, findings, inventory):
        """Combine file-level signals into evidence for the combo checks."""
        for rel, no in self.llm_files.items():
            if rel in self.pii_files:
                self._add(1, rel, no)
            if rel in self.phi_files:
                self._add(2, rel, no)
        for rel, no in self.append_files.items():
            if rel not in self.trim_files:
                self._add(10, rel, no)
        for rel, no in self.exec_lines[:6]:
            self._add(18, rel, no)
        for f in findings:
            if f["category"] == "secret":
                self._add(4, f["file"], f["line"])
        for p in inventory.get("providers", []):
            for fl in p.get("files", [])[:2]:
                self._add(7, fl, 0)
        for m in inventory.get("models", []):
            fs = m.get("first_seen", {})
            self._add(8, fs.get("file", ""), fs.get("line", 0))
        for c in inventory.get("ai_components", []):
            if c.get("category") == "vector_store":
                for fl in c.get("files", [])[:2]:
                    self._add(12, fl, 0)
        for fl, _ in list(self.llm_files.items())[:0]:
            pass
        return self.ev, bool(self.llm_files)


def classify(cid, kind, evidence, ctx):
    """Return the status for one check from collected evidence and scan context."""
    special = next(c[7] for c in CHECKS if c[0] == cid)
    sc = ctx.get("scope")
    if sc is not None and cid == 4 and "secrets" not in sc:
        return "UNKNOWN"  # secrets are outside this scan's detection scope: not evaluated, never reported as clear
    if special == "no_detector":
        return "NO_DETECTOR"
    if ctx.get("files_scanned", 0) == 0:
        return "UNKNOWN"
    if special in ("pii_to_llm", "phi_to_llm") and not ctx.get("has_llm"):
        return "NOT_APPLICABLE"
    if kind == "risk" and special == "unbounded_context" and not ctx.get("has_llm"):
        return "NOT_APPLICABLE"
    if special == "hosts":
        return "FOUND" if ctx.get("hosts") else "NOT_FOUND"
    if evidence:
        return "FOUND"
    return "NOT_FOUND"
