"""Static scanner: secrets, PII, unsafe patterns, AI inventory, SBOM, control evidence, graph."""
import hashlib
import json
import os
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from . import blueprint, frameworks, pii_detect

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "env", "dist", "build", ".next", "vendor", ".idea", ".tox", "site-packages"}
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".so", ".dll", ".exe", ".pyc", ".class", ".jar", ".bin", ".onnx", ".pt", ".pth", ".h5", ".parquet", ".xlsx", ".xls"}
MAX_BYTES = 1_000_000
# keep the matched personal/health value so authorised reviewers can see exactly what was found (set STORE_SENSITIVE_VALUES=0 to disable)
STORE_VALUES = os.getenv("STORE_SENSITIVE_VALUES", "1") not in ("0", "false", "no")
MAX_FILES = 20000
SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# --- speed: cheap triggers decide whether the (many) detailed regexes need to run on a line
SECRET_TRIGGER = re.compile(r"AKIA|gh[pousr]_|gsk_|sk-|AIza|xox[baprs]-|PRIVATE KEY|(?i:api[_-]?key|secret|token|passw|client[_-]?secret)")
PII_TRIGGER = re.compile(r"\d{3}-\d{2}-\d{4}|@|(?:\d[ -]?){13}|(?i:mrn|icd|diagnos)")
SEC_TRIGGER = re.compile(r"(?i)eval|exec|shell|pickle|yaml\.load|verify|rejectUnauthorized|debug")
MODEL_TRIGGER = re.compile(r"(?i)gpt|o[134]\b|claude|llama|gemini|mistral|mixtral|command-r|embedding|gemma|deepseek|qwen")
SKIP_FILE_RX = re.compile(r"(?i)(?:\.min\.(?:js|css)|\.map|\.lock|\.svg|(?:^|[/\\])(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|uv\.lock))$")
NOISE_DIR_RX = re.compile(r"(?i)(?:^|/)(?:locales?|i18n|translations?|l10n)/")
TEST_RX = re.compile(r"(?i)(?:^|/)(?:tests?|__tests__|fixtures?)/|test_|\.test\.|\.spec\.")
TEST_CARDS = {"4242424242424242", "4111111111111111", "5555555555554444", "378282246310005", "6011111111111117",
              "3530111333300000", "4000056655665556", "5105105105105100", "4012888888881881", "2223003122003222"}
PLACEHOLDER = re.compile(r"(?i)example|your[_-]|xxxx|changeme|placeholder|dummy|sample|<.*>|\*{3,}|\.\.\.")

SECRET_RULES = [
    ("secret.aws-access-key", "AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical"),
    ("secret.github-token", "GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "critical"),
    ("secret.groq-key", "Groq API key", re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b"), "critical"),
    ("secret.anthropic-key", "Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), "critical"),
    ("secret.openai-key", "OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b"), "critical"),
    ("secret.google-api-key", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    ("secret.slack-token", "Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "high"),
    ("secret.private-key", "Private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY"), "critical"),
    (
        "secret.generic-assignment",
        "Hard-coded credential assignment",
        re.compile(r"""(?i)\b(?:api[_-]?key|secret|token|passwd|password|client[_-]?secret)\b["']?\s*[:=]\s*["']([A-Za-z0-9_\-/+=.]{12,})["']"""),
        "high",
    ),
]

PII_RULES = [
    ("pii.ssn", "US Social Security number", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "high"),
    ("pii.email", "Email address", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "low"),
    ("pii.card", "Payment card number", re.compile(r"\b(?:\d[ -]?){13,16}\b"), "high"),
    ("phi.mrn", "Medical record number", re.compile(r"(?i)\bMRN\s*[:#]?\s*\d{6,10}\b"), "high"),
    ("phi.icd10", "Diagnosis code (ICD-10)", re.compile(r"(?i)(?:icd[-_ ]?10|diagnos\w+)\D{0,20}\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b"), "high"),
]
EMAIL_ALLOW = re.compile(r"(?i)@(?:example\.|test\.|localhost|users\.noreply\.github\.com)|noreply|no-reply")

SEC_RULES = [
    ("sec.eval-exec", "Use of eval/exec", re.compile(r"(?<![\w.])(?:eval|exec)\s*\("), "medium"),
    ("sec.shell-true", "subprocess with shell=True", re.compile(r"shell\s*=\s*True"), "medium"),
    ("sec.pickle-loads", "Unsafe pickle deserialisation", re.compile(r"\bpickle\.loads?\("), "medium"),
    ("sec.yaml-unsafe-load", "yaml.load without safe loader", re.compile(r"\byaml\.load\((?![^)]*Safe)"), "medium"),
    ("sec.tls-verify-disabled", "TLS verification disabled", re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false", re.I), "high"),
    ("sec.debug-enabled", "Debug mode enabled", re.compile(r"\bdebug\s*=\s*True\b"), "low"),
]
URL_RE = re.compile(r"""https?://([A-Za-z0-9.\-]+)(?::\d+)?[^\s"'<>)]*""")
LOCAL_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "example.com", "example.org", "schemas.", "www.w3.org", "json-schema.org", "purl.org")

# package/module name -> (category, display, provider)
AI_PACKAGES = {
    "openai": ("llm_sdk", "OpenAI SDK", "OpenAI"),
    "anthropic": ("llm_sdk", "Anthropic SDK", "Anthropic"),
    "@anthropic-ai": ("llm_sdk", "Anthropic SDK", "Anthropic"),
    "groq": ("llm_sdk", "Groq SDK", "Groq"),
    "groq-sdk": ("llm_sdk", "Groq SDK", "Groq"),
    "cohere": ("llm_sdk", "Cohere SDK", "Cohere"),
    "mistralai": ("llm_sdk", "Mistral SDK", "Mistral"),
    "google.generativeai": ("llm_sdk", "Google Generative AI", "Google"),
    "google.genai": ("llm_sdk", "Google GenAI", "Google"),
    "@google/generative-ai": ("llm_sdk", "Google Generative AI", "Google"),
    "vertexai": ("llm_sdk", "Vertex AI", "Google"),
    "ollama": ("llm_sdk", "Ollama", "Ollama (self-hosted)"),
    "litellm": ("llm_gateway", "LiteLLM", "multi-provider"),
    "langchain": ("framework", "LangChain", "LangChain"),
    "langchain_openai": ("framework", "LangChain OpenAI", "OpenAI"),
    "langchain_community": ("framework", "LangChain Community", "LangChain"),
    "langchain_core": ("framework", "LangChain Core", "LangChain"),
    "@langchain": ("framework", "LangChain.js", "LangChain"),
    "llama_index": ("framework", "LlamaIndex", "LlamaIndex"),
    "transformers": ("ml_library", "Hugging Face Transformers", "Hugging Face"),
    "huggingface_hub": ("ml_library", "Hugging Face Hub", "Hugging Face"),
    "sentence_transformers": ("ml_library", "Sentence Transformers", "Hugging Face"),
    "torch": ("ml_library", "PyTorch", "PyTorch"),
    "tensorflow": ("ml_library", "TensorFlow", "TensorFlow"),
    "sklearn": ("ml_library", "scikit-learn", "scikit-learn"),
    "pinecone": ("vector_store", "Pinecone", "Pinecone"),
    "@pinecone-database": ("vector_store", "Pinecone", "Pinecone"),
    "chromadb": ("vector_store", "Chroma", "Chroma"),
    "qdrant_client": ("vector_store", "Qdrant", "Qdrant"),
    "weaviate": ("vector_store", "Weaviate", "Weaviate"),
    "faiss": ("vector_store", "FAISS", "Meta"),
    "pgvector": ("vector_store", "pgvector", "PostgreSQL"),
    "presidio_analyzer": ("safety", "Presidio", "Microsoft"),
    "guardrails": ("safety", "Guardrails AI", "Guardrails AI"),
}
MODEL_RE = re.compile(
    r"""["']((?:gpt-[0-9][\w.\-]*|o[134](?:-mini|-preview)?|claude-[\w.\-]+|llama-?[\w.\-]*\d[\w.\-]*|gemini-[\w.\-]+|"""
    r"""mistral-[\w.\-]+|mixtral-[\w.\-]+|command-r[\w+\-]*|text-embedding-[\w\-]+|gemma[\w.\-]*|deepseek-[\w.\-]+|qwen[\w.\-]*))["']""",
    re.I,
)
MODEL_PROVIDERS = [
    (re.compile(r"^(gpt|o[134]|text-embedding)", re.I), "OpenAI"),
    (re.compile(r"^claude", re.I), "Anthropic"),
    (re.compile(r"^(llama|mixtral|gemma|qwen)", re.I), "Open-weights (Meta/Mistral/Google/Alibaba)"),
    (re.compile(r"^gemini", re.I), "Google"),
    (re.compile(r"^(mistral)", re.I), "Mistral"),
    (re.compile(r"^command", re.I), "Cohere"),
    (re.compile(r"^deepseek", re.I), "DeepSeek"),
]
LANG = {".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".ts": "typescript",
        ".tsx": "typescript", ".json": "json", ".yml": "yaml", ".yaml": "yaml", ".md": "markdown", ".rst": "markdown", ".txt": "text",
        ".toml": "toml", ".cfg": "config", ".ini": "config", ".env": "config", ".sh": "shell", ".sql": "sql", ".html": "html",
        ".css": "css", ".rego": "rego"}
ROUTE_RE = re.compile(r"@\w+\.(?:get|post|put|delete|patch|route|websocket)\(|\b(?:app|router)\.(?:get|post|put|delete|patch)\(")
DEF_RE = re.compile(r"^\s*(?:export\s+)?(?:async\s+)?(?:def|function)\s+([A-Za-z_$][\w$]*)|^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)")
PY_IMPORT = re.compile(r"^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import|import\s+([A-Za-z_][\w.]*))")
JS_IMPORT = re.compile(r"""(?:from\s+|require\(\s*|import\s+)["']([^"']+)["']""")


def redact(value: str) -> str:
    v = value.strip()
    return (v[:4] + "…[redacted]") if len(v) > 8 else "[redacted]"


def luhn(num: str) -> bool:
    digits = [int(c) for c in num if c.isdigit()]
    if not 13 <= len(digits) <= 16:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _fp(rule_id: str, file: str, snippet: str) -> str:
    return hashlib.sha256(f"{rule_id}|{file}|{snippet}".encode()).hexdigest()[:16]


def _lookup_pkg(name: str):
    n = name.lower().replace("-", "_") if not name.startswith("@") else name.lower()
    for key, meta in AI_PACKAGES.items():
        k = key.lower()
        if n == k or n.startswith(k + ".") or n.startswith(k + "/") or n.replace("-", "_") == k.replace("-", "_"):
            return key, meta
    return None, None


def model_provider(model: str) -> str:
    for rx, prov in MODEL_PROVIDERS:
        if rx.match(model):
            return prov
    return "unknown"


def parse_manifest(rel: str, text: str) -> list:
    comps = []
    base = os.path.basename(rel).lower()
    try:
        if base.startswith("requirements") and base.endswith(".txt"):
            for line in text.splitlines():
                line = line.split("#")[0].strip()
                if not line or line.startswith(("-", "git+", "http")):
                    continue
                m = re.match(r"([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*(?:[=<>!~]=?\s*([\w.*+\-]+))?", line)
                if m:
                    comps.append({"name": m.group(1), "version": m.group(2) or "", "ecosystem": "pypi", "manifest": rel})
        elif base == "package.json":
            data = json.loads(text)
            for sect in ("dependencies", "devDependencies"):
                for name, ver in (data.get(sect) or {}).items():
                    comps.append({"name": name, "version": str(ver).lstrip("^~"), "ecosystem": "npm", "manifest": rel})
        elif base == "pyproject.toml":
            for m in re.finditer(r'"([A-Za-z0-9_.\-]+)\s*(?:[=<>!~]=?\s*([\w.*+\-]+))?[^"]*"', text):
                if m.group(1).lower() not in ("python",) and re.search(r"dependencies", text):
                    comps.append({"name": m.group(1), "version": m.group(2) or "", "ecosystem": "pypi", "manifest": rel})
    except Exception:
        pass
    return comps


def scan_directory(root: str, cancelled=lambda: False, progress=None, scope=None) -> dict:
    scope = set(scope or ("pii", "phi"))  # detection scope: default personal and health data only
    controls = frameworks.CONTROLS
    findings, components = [], []
    evidence = defaultdict(list)
    bp = blueprint.Collector()
    file_list = []
    routes = []
    imports, model_uses, host_uses = [], [], []
    dir_stats = defaultdict(lambda: {"files": 0, "findings": 0})
    seen_comp = set()
    agent_stats = []
    files_scanned = 0
    languages = defaultdict(int)
    per_rule_file = defaultdict(int)

    def add(rule_id, category, severity, title, desc, rel, line, snippet, ctx=None, agent=None, value=None, context_lines=None):
        key = (rule_id, rel)
        per_rule_file[key] += 1
        if per_rule_file[key] > (200 if category == "pii" else 5):
            return
        findings.append(
            {
                "rule_id": rule_id, "category": category, "severity": severity, "title": title,
                "description": desc, "file": rel, "line": line, "snippet": snippet[:200],
                "fingerprint": _fp(rule_id, rel, snippet[:200]), "context": ctx, "agent": agent,
                "value": (value[:300] if (value and category == "pii" and STORE_VALUES) else None),
                "context_lines": (context_lines if (context_lines and category == "pii" and STORE_VALUES) else None),
            }
        )
        dir_stats[os.path.dirname(rel) or "."]["findings"] += 1

    paths = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for f in fn:
            paths.append(os.path.join(dp, f))
            if len(paths) >= MAX_FILES:
                break
        if len(paths) >= MAX_FILES:
            break

    # file-name based control evidence first
    rels = [os.path.relpath(p, root).replace("\\", "/") for p in paths]
    bp.files(rels)
    for c in controls:
        _, file_rx = frameworks.compiled_patterns(c)
        for rel in rels:
            if any(rx.search(rel) for rx in file_rx) and len(evidence[c["id"]]) < 5:
                evidence[c["id"]].append({"file": rel, "line": 0})

    pats_all = [p.pattern for c in controls for p in frameworks.compiled_patterns(c)[0]]
    ctrl_union = re.compile("|".join(f"(?:{p})" for p in pats_all), re.I) if pats_all else None
    pool = ThreadPoolExecutor(max_workers=8)
    cache = {}

    def _read(p):
        ex = os.path.splitext(p)[1].lower()
        if ex in BINARY_EXT or SKIP_FILE_RX.search(p.replace("\\", "/")):
            return None
        try:
            if os.path.getsize(p) > MAX_BYTES:
                return None
            with open(p, "rb") as fh:
                return fh.read()
        except OSError:
            return None

    for idx, (path, rel) in enumerate(zip(paths, rels)):
        if cancelled():
            break
        if idx % 128 == 0:  # read the next window of files concurrently (disk I/O is the bottleneck on Windows)
            cache.clear()
            window = paths[idx:idx + 128]
            for p, data in zip(window, pool.map(_read, window)):
                cache[p] = data
            if progress:
                progress(idx, len(paths))
        ext = os.path.splitext(rel)[1].lower()
        if ext in BINARY_EXT or SKIP_FILE_RX.search(rel):
            continue
        raw = cache.pop(path, None)
        if raw is None:
            continue
        if b"\0" in raw[:4096]:
            continue
        text = raw.decode("utf-8", errors="ignore")
        files_scanned += 1
        dir_stats[os.path.dirname(rel) or "."]["files"] += 1
        if ext:
            languages[ext] += 1
        lang = LANG.get(ext, "other")
        finfo = {"path": rel, "language": lang, "size_bytes": len(raw), "parsed": lang in ("python", "javascript", "typescript"),
                 "classes": [], "functions": [], "imports": []}
        if len(file_list) < 3000:
            file_list.append(finfo)
        if NOISE_DIR_RX.search(rel):  # translation catalogues: counted, not line-scanned
            continue

        is_test = bool(TEST_RX.search(rel))
        is_doc = ext in (".md", ".rst", ".txt")

        if os.path.basename(rel).lower() in ("package.json", "pyproject.toml") or re.match(r"requirements.*\.txt$", os.path.basename(rel).lower()):
            for comp in parse_manifest(rel, text):
                k = (comp["ecosystem"], comp["name"].lower())
                if k not in seen_comp:
                    seen_comp.add(k)
                    components.append(comp)

        _all_lines = text.splitlines()

        def ctxl(n, L=_all_lines):  # the few lines around a finding, kept so reviewers can see how it was detected
            return [[k, L[k - 1][:220]] for k in range(max(1, n - 2), min(len(L), n + 2) + 1)]

        covered_lines = set()
        if ext not in (".md", ".rst") and ({"pii", "phi"} & scope):
            det = pii_detect.analyze(rel, text, ext)
            for it in det["items"]:
                if ("phi" if it["class"] == "PHI" else "pii") not in scope:
                    continue
                label = "Health information" if it["class"] == "PHI" else "Personal information"
                add(it["rule_id"], "pii", it["severity"], it["title"],
                    f"{label}: {it['title'].lower()} found in a {it['agent']}-detected field on line {it['line']}.",
                    rel, it["line"], pii_detect.redacted_snippet(it), None, it["agent"], it["value"], ctxl(it["line"]))
                covered_lines.add(it["line"])
            if det["items"]:
                agent_stats.append({"file": rel, "agents": det["agents"], "health_context": det["health_context"]})

        for lineno, line in enumerate(text.splitlines(), 1):
            if len(line) > 2000:
                continue
            if len(line) < 4:
                continue
            bp.line(rel, lineno, line, is_test, is_doc)
            if "secrets" in scope and not is_doc and SECRET_TRIGGER.search(line):
                for rule_id, title, rx, sev in SECRET_RULES:
                    m = rx.search(line)
                    if m:
                        val = m.group(1) if m.groups() else m.group(0)
                        if PLACEHOLDER.search(val) or PLACEHOLDER.search(line) and "secret.generic" in rule_id:
                            continue
                        if "secret.generic" in rule_id and not re.search(r"\d", val):
                            continue  # plain words are rarely secrets
                        ctx = None
                        if is_test and "secret.generic" in rule_id:
                            sev, ctx = "low", "test"  # a placeholder in a test fixture is not a leaked credential
                        add(rule_id, "secret", sev, title, "Credential-like value committed to source control.", rel, lineno, line.replace(val, redact(val)).strip(), ctx)
                        break
            if not is_test and lineno not in covered_lines and PII_TRIGGER.search(line):
                for rule_id, title, rx, sev in PII_RULES:
                    if ("phi" if rule_id.startswith("phi.") else "pii") not in scope:
                        continue
                    m = rx.search(line)
                    if not m:
                        continue
                    val = m.group(0)
                    if rule_id == "pii.card" and (not luhn(val) or re.sub(r"\D", "", val) in TEST_CARDS):
                        continue
                    if rule_id == "pii.email" and (EMAIL_ALLOW.search(val) or ext in (".lock", ".json") or is_doc):
                        continue
                    if rule_id == "pii.ssn" and PLACEHOLDER.search(line):
                        continue
                    add(rule_id, "pii", sev, title, "Personal data pattern found in source.", rel, lineno, line.replace(val, redact(val)).strip(), None, "pattern", val, ctxl(lineno))
            if "code_security" in scope and not is_doc and not is_test and SEC_TRIGGER.search(line):
                for rule_id, title, rx, sev in SEC_RULES:
                    if rx.search(line):
                        add(rule_id, "security", sev, title, "Pattern commonly associated with insecure behaviour.", rel, lineno, line.strip())
            if finfo["parsed"] and not is_test and len(routes) < 500 and ROUTE_RE.search(line):
                routes.append({"file": rel, "line": lineno})
            if finfo["parsed"]:
                dm = DEF_RE.match(line)
                if dm:
                    if dm.group(1) and len(finfo["functions"]) < 60:
                        finfo["functions"].append(dm.group(1))
                    elif dm.group(2) and len(finfo["classes"]) < 60:
                        finfo["classes"].append(dm.group(2))
            # imports / models / hosts
            if ext == ".py":
                m = PY_IMPORT.match(line)
                if m:
                    imports.append((rel, m.group(1) or m.group(2)))
                    if len(finfo["imports"]) < 60:
                        finfo["imports"].append(m.group(1) or m.group(2))
            elif ext in (".js", ".jsx", ".ts", ".tsx", ".mjs"):
                for m in JS_IMPORT.finditer(line):
                    imports.append((rel, m.group(1)))
                    if len(finfo["imports"]) < 60:
                        finfo["imports"].append(m.group(1))
            if not is_doc:
                if MODEL_TRIGGER.search(line):
                    for m in MODEL_RE.finditer(line):
                        model_uses.append((rel, m.group(1), lineno))
                if "http" in line:
                    for m in URL_RE.finditer(line):
                        host = m.group(1).lower()
                        if any(host.startswith(h) or h in host for h in LOCAL_HOSTS):
                            continue
                        host_uses.append((rel, host))
                        if m.group(0).startswith("http://") and "code_security" in scope:
                            add("sec.insecure-http", "security", "low", "Plain HTTP URL", "External call uses unencrypted HTTP.", rel, lineno, line.strip())
            # control evidence by content (one combined pre-check, then per-control detail)
            if ctrl_union is not None and ctrl_union.search(line):
                for c in controls:
                    pats, _ = frameworks.compiled_patterns(c)
                    if pats and len(evidence[c["id"]]) < 5 and not (is_doc and c["type"] == "negative"):
                        if any(p.search(line) for p in pats):
                            evidence[c["id"]].append({"file": rel, "line": lineno})

    # --- AI inventory
    ai_components, providers, models = {}, {}, {}
    for rel, mod in imports:
        key, meta = _lookup_pkg(mod)
        if meta:
            ai_components.setdefault(meta[1], {"name": meta[1], "category": meta[0], "provider": meta[2], "files": set()})["files"].add(rel)
    for comp in components:
        key, meta = _lookup_pkg(comp["name"])
        if meta:
            e = ai_components.setdefault(meta[1], {"name": meta[1], "category": meta[0], "provider": meta[2], "files": set()})
            e["files"].add(comp["manifest"])
            e["version"] = comp.get("version", "")
    for rel, model, lineno in model_uses:
        key = model.lower()
        e = models.setdefault(key, {"name": model, "provider": model_provider(model), "files": set(), "first_seen": {"file": rel, "line": lineno}})
        e["files"].add(rel)
    for e in ai_components.values():
        providers.setdefault(e["provider"], {"name": e["provider"], "files": set()})["files"].update(e["files"])
    for m in models.values():
        providers.setdefault(m["provider"], {"name": m["provider"], "files": set()})["files"].update(m["files"])

    for name, m in (models.items() if "ai_inventory" in scope else []):
        f = m["first_seen"]
        findings.append(
            {
                "rule_id": "ai.model-usage", "category": "ai_governance", "severity": "info",
                "title": f"AI model referenced: {m['name']}",
                "description": f"Model '{m['name']}' ({m['provider']}) is referenced in {len(m['files'])} file(s). Confirm it is on the approved model list.",
                "file": f["file"], "line": f["line"], "snippet": m["name"],
                "fingerprint": _fp("ai.model-usage", f["file"], m["name"]),
            }
        )
    for e in ai_components.values():
        if e["category"] in ("llm_sdk", "llm_gateway") and "ai_inventory" in scope:
            first = sorted(e["files"])[0]
            findings.append(
                {
                    "rule_id": "ai.provider-sdk", "category": "ai_governance", "severity": "info",
                    "title": f"AI provider SDK in use: {e['name']}",
                    "description": f"{e['name']} ({e['provider']}) is used. Data sent to this provider should be covered by a DPA and policy.",
                    "file": first, "line": 0, "snippet": e["name"],
                    "fingerprint": _fp("ai.provider-sdk", first, e["name"]),
                }
            )

    review_info = pii_detect.llm_review(findings)
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["file"], f["line"]))
    bp_inv = {
        "providers": [{"name": p["name"], "files": sorted(p["files"])} for p in providers.values()],
        "models": [{"name": m["name"], "first_seen": m["first_seen"]} for m in models.values()],
        "ai_components": [{"category": e["category"], "files": sorted(e["files"])} for e in ai_components.values()],
    }
    bp_ev, has_llm = bp.finish(findings, bp_inv)
    return {
        "blueprint": {"evidence": bp_ev, "has_llm": has_llm or bool(models) or any(e["category"] in ("llm_sdk", "llm_gateway", "framework") for e in ai_components.values())},
        "files_scanned": files_scanned,
        "scope": sorted(scope),
        "agents": {"pipeline": pii_detect.agent_status(), "llm_review": review_info,
                   "by_file": agent_stats[:50]},
        "files_total": len(paths),
        "findings": findings,
        "components": components,
        "ai_components": [
            {**{k: v for k, v in e.items() if k != "files"}, "files": sorted(e["files"])} for e in ai_components.values()
        ],
        "models": [
            {"name": m["name"], "provider": m["provider"], "files": sorted(m["files"]), "first_seen": m["first_seen"]}
            for m in models.values()
        ],
        "providers": [{"name": p["name"], "files": sorted(p["files"])} for p in providers.values()],
        "hosts": sorted({h for _, h in host_uses}),
        "evidence": dict(evidence),
        "imports": imports,
        "model_uses": model_uses,
        "host_uses": host_uses,
        "dir_stats": dict(dir_stats),
        "languages": dict(languages),
        "file_list": file_list,
        "routes": routes,
    }


def build_graph(repo_id: str, repo_name: str, result: dict, findings: list, controls: list) -> dict:
    nodes, edges = {}, {}

    def node(key, ntype, label, **props):
        if key not in nodes:
            nodes[key] = {"key": key, "type": ntype, "label": label, "props": props}
        return key

    def edge(src, dst, etype):
        eid = hashlib.sha1(f"{src}|{dst}|{etype}".encode()).hexdigest()[:12]
        edges.setdefault(eid, {"id": eid, "src": src, "dst": dst, "type": etype})

    repo = node(f"repo:{repo_id}", "repository", repo_name)
    for comp in result["components"]:
        pk = node(f"pkg:{comp['ecosystem']}:{comp['name'].lower()}", "package", comp["name"], version=comp.get("version", ""), ecosystem=comp["ecosystem"])
        edge(repo, pk, "depends_on")
    for rel, mod in result["imports"]:
        key, meta = _lookup_pkg(mod)
        if not meta:
            continue
        fk = node(f"file:{rel}", "file", rel)
        pk = node(f"pkg:ai:{meta[1].lower()}", "package", meta[1], category=meta[0], ecosystem="ai")
        edge(repo, fk, "contains")
        edge(fk, pk, "imports")
        prov = node(f"provider:{meta[2].lower()}", "provider", meta[2])
        edge(pk, prov, "served_by")
    for rel, model, _ in result["model_uses"]:
        fk = node(f"file:{rel}", "file", rel)
        mk = node(f"model:{model.lower()}", "model", model)
        edge(repo, fk, "contains")
        edge(fk, mk, "uses_model")
        prov = node(f"provider:{model_provider(model).lower()}", "provider", model_provider(model))
        edge(mk, prov, "served_by")
    for rel, host in result["host_uses"]:
        fk = node(f"file:{rel}", "file", rel)
        hk = node(f"host:{host}", "host", host)
        edge(repo, fk, "contains")
        edge(fk, hk, "calls")
    for f in findings:
        if f["category"] == "ai_governance":
            continue
        fk = node(f"file:{f['file']}", "file", f["file"])
        edge(repo, fk, "contains")
        fnk = node(f"finding:{f['id']}", "finding", f["title"], severity=f["severity"], category=f["category"], line=f["line"])
        edge(fnk, fk, "located_in")
    for c in controls:
        ck = node(f"control:{c['control_id']}", "control", c["title"], status=c["status"])
        for ev in c["evidence"][:10]:
            if ev.get("file") and ev["file"] != "(dependency)":
                fk = node(f"file:{ev['file']}", "file", ev["file"])
                edge(repo, fk, "contains")
                edge(ck, fk, "evidenced_by")
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def validate_git_url(url: str) -> str:
    """Only plain http(s) git URLs to public hosts (blocks file://, ssh, ext::, private IPs)."""
    import ipaddress
    import socket

    u = urlparse(url.strip())
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("git_url must be an http(s) URL")
    if u.username or u.password:
        raise ValueError("credentials in URLs are not allowed")
    try:
        for info in socket.getaddrinfo(u.hostname, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                raise ValueError("git_url resolves to a non-public address")
    except socket.gaierror:
        raise ValueError("git_url host could not be resolved")
    return url.strip()
