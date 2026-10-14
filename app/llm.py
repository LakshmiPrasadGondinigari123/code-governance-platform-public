"""Optional LLM explanations via Groq (OpenAI-compatible). Falls back to deterministic text."""
import os
import time

import httpx

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODELS_URL = "https://api.groq.com/openai/v1/models"
_MODEL = {}
_SKIP = ("whisper", "tts", "guard", "embed", "orpheus", "playai", "prompt-guard", "safeguard")
_PREFER = ("llama-3.3-70b", "llama-3.1-70b", "gpt-oss-120b", "llama-3.1-8b", "gpt-oss-20b", "llama", "qwen", "gemma", "mixtral")


def resolve_model(key: str, force: bool = False) -> str:
    """GROQ_MODEL wins; otherwise ask Groq which chat models this key can use and pick the best known family."""
    env = os.getenv("GROQ_MODEL")
    if env:
        return env
    if _MODEL.get("m") and not force:
        return _MODEL["m"]
    ids = []
    try:
        r = httpx.get(GROQ_MODELS_URL, headers={"Authorization": f"Bearer {key}"}, timeout=15)
        ids = [m["id"] for m in r.json().get("data", []) if m.get("active", True)]
    except Exception:
        pass
    chat = [i for i in ids if not any(s in i.lower() for s in _SKIP)]
    pick = next((i for pref in _PREFER for i in chat if pref in i.lower()), chat[0] if chat else "llama-3.1-8b-instant")
    _MODEL["m"] = pick
    return pick
CALLS = []  # in-memory call log shown on System Health (never fabricated)


def _log(ok, provider, model, latency_ms, in_t=None, out_t=None):
    CALLS.append({"ok": ok, "provider": provider, "model": model, "latency_ms": latency_ms, "input_tokens": in_t,
                  "output_tokens": out_t, "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    del CALLS[:-200]


def status() -> dict:
    key = bool(os.getenv("GROQ_API_KEY"))
    return {
        "provider": "groq",
        "configured": key,
        "model": os.getenv("GROQ_MODEL") or _MODEL.get("m") or "auto (resolved on first use)",
        "mode": "llm" if key else "deterministic-fallback",
    }


def explain(system: str, prompt: str, fallback: str, evidence_refs=None, temperature: float = 0.2, max_tokens: int = 700) -> dict:
    refs = evidence_refs or []
    key = os.getenv("GROQ_API_KEY")
    if not key:
        return {"status": "fallback", "content": fallback, "provider": None, "model": None,
                "detail": "GROQ_API_KEY not configured; returning rule-based explanation.",
                "input_tokens": None, "output_tokens": None, "latency_ms": 0, "evidence_refs": refs}
    model = resolve_model(key)
    t0 = time.time()
    try:
        r = httpx.post(
            GROQ_URL,
            headers={"Authorization": f"Bearer {key}"},
            json={
                "model": model,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
            },
            timeout=30,
        )
        if r.status_code in (400, 404) and not os.getenv("GROQ_MODEL") and not _MODEL.get("retried"):
            _MODEL["retried"] = True
            model = resolve_model(key, force=True)
            r = httpx.post(GROQ_URL, headers={"Authorization": f"Bearer {key}"},
                           json={"model": model, "temperature": temperature, "max_tokens": max_tokens,
                                 "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]}, timeout=30)
            _MODEL.pop("retried", None)
        if r.status_code >= 400:
            msg = ""
            try:
                msg = (r.json().get("error") or {}).get("message", "")[:200]
            except Exception:
                msg = r.text[:200]
            _log(False, "groq", model, int((time.time() - t0) * 1000))
            return {"status": "fallback", "content": fallback, "provider": "groq", "model": model,
                    "detail": f"Groq returned HTTP {r.status_code}: {msg}", "input_tokens": None, "output_tokens": None,
                    "latency_ms": int((time.time() - t0) * 1000), "evidence_refs": refs}
        data = r.json()
        usage = data.get("usage", {})
        _log(True, "groq", model, int((time.time() - t0) * 1000), usage.get("prompt_tokens"), usage.get("completion_tokens"))
        return {
            "status": "ok",
            "content": data["choices"][0]["message"]["content"],
            "provider": "groq", "model": model, "detail": None,
            "input_tokens": usage.get("prompt_tokens"), "output_tokens": usage.get("completion_tokens"),
            "latency_ms": int((time.time() - t0) * 1000), "evidence_refs": refs,
        }
    except Exception as exc:  # network, auth, quota
        _log(False, "groq", model, int((time.time() - t0) * 1000))
        return {"status": "fallback", "content": fallback, "provider": "groq", "model": model,
                "detail": f"LLM call failed ({type(exc).__name__}); returning rule-based explanation.",
                "input_tokens": None, "output_tokens": None,
                "latency_ms": int((time.time() - t0) * 1000), "evidence_refs": refs}
