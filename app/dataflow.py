"""Source-to-LLM data-flow analysis (blueprint stage D, layers 1-3) for Python.

Deterministic, AST-based, intraprocedural plus one level of call summaries.
It establishes facts the blueprint asks for - "does sensitive data reach an outbound model call, and is a
masking step on the path?" - and states its own limits: it is not a complete taint engine (no aliasing across
modules, dynamic dispatch or reflection), so a negative result lowers risk but never proves absence.
"""
import ast
import re
import time

PHI_RX = re.compile(r"(?i)patient|diagnos|\bmrn\b|medical|medication|\bicd|health|clinical|symptom|\bphi\b|date_of_birth|\bdob\b|prescription")
PII_RX = re.compile(r"(?i)\bssn\b|social_security|e?mail|phone|address|first_name|last_name|full_name|\bname\b|passport|credit_card|card_number|customer|\bpii\b|user_input|user_text|user_message|\bquery\b")
SANITIZER_RX = re.compile(r"(?i)mask|redact|anonymi[sz]e|de_?identif|scrub|sanitiz|pseudonym|tokeni[sz]e|strip_pii|presidio|\banonymizer\b")
SINK_RX = re.compile(
    r"(?i)(chat\.completions\.create|completions\.create|responses\.create|messages\.create|embeddings\.create|"
    r"generate_content|generate_text|\.invoke$|\.ainvoke$|\.predict$|ChatCompletion\.create|\.chat$|ollama\.chat|"
    r"\.generate$|\.complete$|create_chat_completion)"
)
REQUEST_SRC = re.compile(r"(?i)request\.(json|form|body|get_json|args|data|query_params)|await request\.(json|body|form)")
LLM_HOSTS = re.compile(r"(?i)api\.openai\.com|api\.anthropic\.com|api\.groq\.com|generativelanguage\.googleapis\.com|openai\.azure\.com|bedrock")


def _dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        inner = _dotted(node.func)
        if inner:
            parts.append(inner + "()")
    return ".".join(reversed(parts))


def _names(node):
    return [n.id for n in ast.walk(node) if isinstance(n, ast.Name)]


class _Func:
    def __init__(self, node):
        self.node = node
        self.params = [a.arg for a in node.args.args + node.args.kwonlyargs]
        self.sink_params = set()   # params that reach a sink inside this function


def _data_class(text):
    if PHI_RX.search(text):
        return "PHI"
    if PII_RX.search(text):
        return "PII"
    return None


def analyze(rel, source):
    """Return {'flows': [...], 'barriers': [...]} for one Python file."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return {"flows": [], "barriers": []}
    deadline = time.time() + 6.0  # per-file time budget: a pathological file must never stall a scan
    funcs = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs[n.name] = _Func(n)

    flows, barriers = [], []

    def expr_taint(e, env):
        """Return (class, source_line, sanitized) when the expression carries tainted data, else None."""
        if e is None:
            return None
        if isinstance(e, ast.Call):
            fname = _dotted(e.func)
            sub = [expr_taint(a, env) for a in list(e.args) + [k.value for k in e.keywords]]
            sub += [expr_taint(e.func.value, env)] if isinstance(e.func, ast.Attribute) else []
            sub = [s for s in sub if s]
            if SANITIZER_RX.search(fname):
                if sub:
                    c, ln, _ = sub[0]
                    return (c, ln, True)
                return None
            if sub:
                return sub[0]
            if REQUEST_SRC.search(fname):
                return ("PII", getattr(e, "lineno", 0), False)
            return None
        if isinstance(e, ast.Name):
            if e.id in env:
                return env[e.id]
            c = _data_class(e.id)
            return (c, getattr(e, "lineno", 0), False) if c else None
        if isinstance(e, ast.Subscript):
            key = e.slice
            keytext = key.value if isinstance(key, ast.Constant) and isinstance(key.value, str) else ""
            t = expr_taint(e.value, env)
            if t:
                return t
            c = _data_class(keytext) or _data_class(_dotted(e.value))
            return (c, getattr(e, "lineno", 0), False) if c else None
        if isinstance(e, ast.Attribute):
            if REQUEST_SRC.search(_dotted(e)):
                return ("PII", getattr(e, "lineno", 0), False)
            t = expr_taint(e.value, env)
            if t:
                return t
            c = _data_class(e.attr)
            return (c, getattr(e, "lineno", 0), False) if c else None
        if isinstance(e, ast.Constant):
            if isinstance(e.value, str) and len(e.value) < 400:
                if re.search(r"\b\d{3}-\d{2}-\d{4}\b|[\w.+-]+@[\w-]+\.[\w.]+", e.value):
                    return ("PII", getattr(e, "lineno", 0), False)
                if re.search(r"(?i)diagnos|patient|medical record|mrn", e.value):
                    return ("PHI", getattr(e, "lineno", 0), False)
            return None
        # containers, f-strings, binary ops, comprehensions, etc.
        best = None
        for child in ast.iter_child_nodes(e):
            t = expr_taint(child, env)
            if t:
                if t[0] == "PHI":
                    return t
                best = best or t
        return best

    def run_body(body, params, fname):
        env = {}
        for p in params:
            c = _data_class(p)
            if c:
                env[p] = (c, getattr(funcs[fname].node, "lineno", 0) if fname in funcs else 0, False)

        def visit(stmts):
            for st in stmts:
                if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                if time.time() > deadline:
                    return
                if isinstance(st, (ast.If, ast.While)):
                    heads = [st.test]
                elif isinstance(st, (ast.For, ast.AsyncFor)):
                    heads = [st.iter, st.target]
                elif isinstance(st, (ast.With, ast.AsyncWith)):
                    heads = [i.context_expr for i in st.items]
                elif isinstance(st, ast.Try) or st.__class__.__name__ == "TryStar":
                    heads = []
                else:
                    heads = [st]
                for head in heads:  # walk only the statement's own expressions; nested statements are visited below
                    for node in ast.walk(head):
                        if isinstance(node, ast.Call):
                            check_sink(node, env, fname)
                if isinstance(st, ast.Assign):
                    t = expr_taint(st.value, env)
                    for tgt in st.targets:
                        for nm in _names(tgt):
                            if t:
                                env[nm] = t
                            else:
                                env.pop(nm, None)
                elif isinstance(st, ast.AugAssign):
                    t = expr_taint(st.value, env)
                    if t:
                        for nm in _names(st.target):
                            env[nm] = t
                elif isinstance(st, ast.AnnAssign) and st.value is not None:
                    t = expr_taint(st.value, env)
                    if t:
                        for nm in _names(st.target):
                            env[nm] = t
                for field in ("body", "orelse", "finalbody"):
                    sub = getattr(st, field, None)
                    if isinstance(sub, list) and not isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        visit(sub)
                for h in getattr(st, "handlers", []) or []:
                    visit(h.body)
        visit(body)

    def check_sink(call, env, fname):
        name = _dotted(call.func)
        args = list(call.args) + [k.value for k in call.keywords]
        is_sink = bool(SINK_RX.search(name))
        via = None
        if not is_sink:
            leaf = name.split(".")[-1]
            fn = funcs.get(leaf)
            if fn and fn.sink_params:
                for i, a in enumerate(call.args):
                    if i < len(fn.params) and fn.params[i] in fn.sink_params:
                        t = expr_taint(a, env)
                        if t:
                            report(call, name, t, fname, via=leaf)
                            return
                for k in call.keywords:
                    if k.arg in fn.sink_params:
                        t = expr_taint(k.value, env)
                        if t:
                            report(call, name, t, fname, via=leaf)
                            return
            if leaf in ("post", "request", "get") and any(isinstance(a, ast.Constant) and isinstance(a.value, str) and LLM_HOSTS.search(a.value) for a in call.args):
                is_sink = True
            else:
                return
        for a in args:
            t = expr_taint(a, env)
            if t:
                report(call, name, t, fname)
                return

    def report(call, sink, taint, fname, via=None):
        cls, src_line, sanitized = taint
        item = {"file": rel, "source_line": src_line, "sink_line": getattr(call, "lineno", 0), "sink": sink,
                "data_class": cls, "function": fname, "via": via}
        (barriers if sanitized else flows).append(item)

    # pass 1: which parameters reach a sink inside each function (call summaries)
    for name, fn in funcs.items():
        env = {p: ("PII", fn.node.lineno, False) for p in fn.params if p not in ("self", "cls")}
        for node in ast.walk(fn.node):
            if isinstance(node, ast.Call) and SINK_RX.search(_dotted(node.func)):
                for a in list(node.args) + [k.value for k in node.keywords]:
                    t = expr_taint(a, env)
                    if t:
                        for nm in _names(a):
                            if nm in fn.params:
                                fn.sink_params.add(nm)
    # pass 2: real analysis
    for name, fn in funcs.items():
        run_body(fn.node.body, fn.params, name)
    run_body([s for s in tree.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))], [], "<module>")
    seen, uf, ub = set(), [], []
    for f in flows:
        k = (f["file"], f["sink_line"], f["data_class"])
        if k not in seen:
            seen.add(k)
            uf.append(f)
    for b in barriers:
        k = (b["file"], b["sink_line"])
        if k not in seen:
            seen.add(k)
            ub.append(b)
    return {"flows": uf, "barriers": ub}
