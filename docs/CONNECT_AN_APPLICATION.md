# Connect a real application (live AI usage)

The platform checks code at rest. To also see what an application does at run time, send it usage events.

1. Sign in as an administrator, open **AI Usage -> Credentials** and create a runtime key for your application.
2. Copy `scripts/ai_usage_reporter.py` next to your application and call it wherever the application calls a model or a tool
   (see the example at the top of the file).
3. Open **AI Usage**. Events appear within a second, are checked against the approved lists, and the runtime governance
   checks on **Governance Controls** start showing real results instead of "nothing to approve".

Only metadata is sent: provider, model, token counts, latency, tool names and the outside host. Prompt text is never sent
unless you pass `preview=`, and then it is cut to 500 characters.