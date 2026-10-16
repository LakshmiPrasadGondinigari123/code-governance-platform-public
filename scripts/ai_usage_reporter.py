"""AI usage reporter: send what your application really does with AI models to the governance platform.

Standard library only. Create a runtime key in the platform (AI Usage -> Credentials), then:

    from ai_usage_reporter import AIUsageReporter
    rep = AIUsageReporter("https://your-platform.example", runtime_key="...", application_id="support-bot", environment="prod")
    rep.llm_call(provider="OpenAI", model="gpt-4o", prompt_tokens=412, completion_tokens=96, latency_ms=830)
    rep.tool_call("lookup_patient")

Every event is checked against your approved providers, models, tools and hosts the moment it arrives.
No prompt text is sent unless you pass `preview=`, which is cut to 500 characters.
"""
import json
import time
import urllib.request
import uuid
from typing import Optional


class AIUsageReporter:
    def __init__(self, base_url: str, runtime_key: str, application_id: str, environment: str = "prod", timeout: float = 5.0):
        self.base = base_url.rstrip("/")
        self.key = runtime_key
        self.app = application_id
        self.env = environment
        self.timeout = timeout

    def _send(self, body: dict) -> dict:
        req = urllib.request.Request(self.base + "/runtime/events", data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "X-Runtime-Key": self.key})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read().decode())

    def _base(self, event_type: str, **extra) -> dict:
        return {"event_id": uuid.uuid4().hex, "event_type": event_type, "application_id": self.app, "environment": self.env, **extra}

    def llm_call(self, provider: str, model: str, prompt_tokens: Optional[int] = None, completion_tokens: Optional[int] = None,
                 latency_ms: Optional[int] = None, host: Optional[str] = None, preview: Optional[str] = None) -> dict:
        meta = {k: v for k, v in {"total_tokens": (prompt_tokens or 0) + (completion_tokens or 0) or None,
                                  "prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens, "latency_ms": latency_ms}.items() if v is not None}
        body = self._base("llm_call", provider=provider, model=model, response_metadata=meta)
        if host:
            body["network_metadata"] = {"host": host}
        if preview:
            body["content_preview"] = preview[:500]
        return self._send(body)

    def tool_call(self, tool_name: str, host: Optional[str] = None) -> dict:
        body = self._base("tool_call", tool_name=tool_name)
        if host:
            body["network_metadata"] = {"host": host}
        return self._send(body)

    def timed(self, provider: str, model: str):
        """Context manager: `with rep.timed('OpenAI', 'gpt-4o'): call_the_model()` reports the call and its duration."""
        rep = self

        class _T:
            def __enter__(self):
                self.t0 = time.time()
                return self

            def __exit__(self, *exc):
                rep.llm_call(provider, model, latency_ms=int((time.time() - self.t0) * 1000))
                return False
        return _T()