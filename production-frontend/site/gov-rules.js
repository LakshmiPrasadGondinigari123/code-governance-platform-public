/* Plain-language labels on every page + "Laws & standards check" on Governance Controls.
   Reads the platform's own scan results (read-only) and evaluates them against public governance rules. */
(function () {
  'use strict';
  var API = 'https://backend-production-471b.up.railway.app';
  function token() { try { return localStorage.getItem('cgp_token'); } catch (e) { return null; } }

  /* ------------------------------------------------------------------ plain language */
  var EXACT = {
    'presidio': 'Personal-data scanner', 'semgrep': 'Code-safety scanner', 'gitleaks': 'Password & key scanner',
    'syft': 'Software inventory scanner', 'url': 'Web-link scanner', 'governance': 'Governance check',
    'STATIC': 'Found in code', 'RUNTIME': 'Seen while running',
    'Error': 'High', 'Warning': 'Medium', 'Info': 'Low', 'ERROR': 'High', 'WARNING': 'Medium', 'INFO': 'Low',
    'DETECTION SIGNALS': 'THINGS FOUND', 'GOVERNANCE FINDINGS': 'ISSUES THAT MATTER', 'Show raw signals': 'Show technical details',
    'Contextual': 'Possibly sensitive — a person should confirm', 'CONTEXTUAL': 'Possibly sensitive — a person should confirm',
    'Confirmed sensitive': 'Confirmed sensitive data', 'Suppressed': 'Ignored (not a real risk)',
    'PHI': 'Health information', 'PII': 'Personal information', 'DETECTED': 'Found in the code', 'Detected': 'Found in the code',
    'Governance Findings': 'Issues that matter', 'Open': 'Open'
  };
  var ENT = {
    PERSON: "Person's name", DATE_OF_BIRTH: 'Date of birth', MEDICAL_DIAGNOSIS: 'Medical diagnosis', LOCATION: 'Address or place',
    PHONE_NUMBER: 'Phone number', EMAIL_ADDRESS: 'Email address', US_SSN: 'Social Security number', CREDIT_CARD: 'Card number',
    IP_ADDRESS: 'Internet (IP) address', MEDICAL_RECORD_NUMBER: 'Medical record number', DATE_TIME: 'Date', NRP: 'Nationality or group',
    URL: 'Web link', US_DRIVER_LICENSE: "Driver's licence number", US_PASSPORT: 'Passport number', IBAN_CODE: 'Bank account number',
    MEDICATION: 'Medication', HEALTH_CONDITION: 'Health condition', INSURANCE_ID: 'Insurance number'
  };
  var LOWER = { 'detection signals': 'Things found', 'governance findings': 'Issues that matter', 'show raw signals': 'Show technical details', 'suppressed': 'Ignored (not a real risk)', 'all detector': 'All scanners', 'all signal bucket': 'All kinds', 'all ai reviewed': 'All review states', 'all governance confidence': 'All confidence levels', 'all evidence state': 'All evidence types', 'all governance status': 'All review results' };
  var INTRO = 'Everything the scans found in your code that could affect privacy, security or AI rules. ' +
    'Items marked "needs review" should be checked by a person; a scan result alone is not proof of a violation.';

  function nice(s) { return s.toLowerCase().replace(/_/g, ' ').replace(/^./, function (c) { return c.toUpperCase(); }); }
  function simplify(text) {
    var t = text.trim();
    if (!t) return null;
    if (Object.prototype.hasOwnProperty.call(EXACT, t)) return text.replace(t, EXACT[t]);
    var m = /^([A-Z][A-Z_]+) — (PHI|PII)$/.exec(t);
    if (m) return text.replace(t, (ENT[m[1]] || nice(m[1])) + ' — ' + (m[2] === 'PHI' ? 'health information' : 'personal information'));
    if (/^[A-Z][A-Z_]{3,}$/.test(t) && ENT[t]) return text.replace(t, ENT[t]);
    var m2 = /^\u2014 (PHI|PII)$/.exec(t);
    if (m2) return text.replace(t, '\u2014 ' + (m2[1] === 'PHI' ? 'health information' : 'personal information'));
    var lk = LOWER[t.toLowerCase()];
    if (lk && lk !== t) return text.replace(t, lk);
    if (t.indexOf('Evidence-first governance findings across every scanned repository') === 0) return text.replace(t, INTRO);
    if (t === 'Evidence: DETECTED') return text.replace(t, 'Evidence: found in the code');
    return null;
  }
  var busy = false;
  function walk(root) {
    var w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null), n, list = [];
    while ((n = w.nextNode())) {
      var p = n.parentNode;
      if (!p || /^(SCRIPT|STYLE|TEXTAREA|INPUT|CODE|PRE)$/.test(p.nodeName)) continue;
      if (p.closest && p.closest('#gov-rules-panel')) continue;
      list.push(n);
    }
    list.forEach(function (node) {
      var r = simplify(node.nodeValue);
      if (r !== null && r !== node.nodeValue) node.nodeValue = r;
    });
  }

  /* ------------------------------------------------------------------ rule library */
  var STD = {
    GDPR: 'GDPR', HIPAA: 'HIPAA', AIACT: 'EU AI Act', NIST: 'NIST AI RMF', ISO: 'ISO/IEC 42001', OWASP: 'OWASP LLM Top 10'
  };
  var RULES = [
    {
      id: 'R01', area: 'Privacy & health data', title: 'No real personal data is stored in the code',
      refs: [['GDPR', 'Art. 5(1)(c) data minimisation; Art. 25'], ['HIPAA', '§164.502(b) minimum necessary']],
      why: 'Personal data copied into source code is copied to every developer machine, backup and build. It cannot be protected or deleted properly.',
      test: function (d) { return d.noScan ? null : d.pii; },
      steps: ['Replace real names, phone numbers and e-mails in test files with made-up values.', 'Move any real records to a protected database, not the code repository.', 'Add a check to your build that blocks commits containing personal data, then rescan.'],
      example: '# before\n"phone": "+1-202-555-0101"\n# after (synthetic value)\n"phone": "+1-000-000-0000"\n\n# pip install faker\nfrom faker import Faker\nf = Faker()\npatient = {"name": f.name(), "phone": f.phone_number()}'
    },
    {
      id: 'R02', area: 'Privacy & health data', title: 'No health information is stored in the code',
      refs: [['HIPAA', '§164.514(b) de-identification; §164.312(a)(1) access control'], ['GDPR', 'Art. 9 special-category data']],
      why: 'Health details (diagnoses, medications, dates of birth tied to a person) are the most heavily regulated kind of data. Having them in a code repository is a reportable risk.',
      test: function (d) { return d.noScan ? null : d.phi; },
      steps: ['Remove real patient records from the repository and from its history.', 'Keep only fully synthetic or de-identified sample data in tests.', 'If real data is required, store it in an access-controlled, encrypted data store and load it at run time.', 'Record who confirmed the data is not real in the review step of this platform.'],
      example: '# remove a file from every commit in history\ngit filter-repo --path patient_records.json --invert-paths\n\n# keep only de-identified samples\n{"patient_id": "SAMPLE-001", "age_band": "30-39", "condition": "type 2 diabetes"}'
    },
    {
      id: 'R03', area: 'Privacy & health data', title: 'Personal or health data is not sent to an outside AI service',
      refs: [['GDPR', 'Art. 28 processors; Art. 44 transfers'], ['HIPAA', '§164.502(e) business associates'], ['OWASP', 'LLM02 sensitive information disclosure']],
      why: 'Anything placed in a prompt leaves your organisation. Without a signed data-processing agreement, that is an unlawful disclosure.',
      test: function (d) {
        if (d.noScan) return null;
        if (!d.isAI) return [];
        return d.pii.concat(d.phi).length ? d.pii.concat(d.phi) : [];
      },
      steps: ['Mask or remove personal data before building any prompt.', 'Use only AI providers that have a signed data-processing agreement (and a BAA for health data).', 'Log what is sent so it can be audited.'],
      example: 'import re\ndef mask(text):\n    text = re.sub(r"\\b\\d{3}-\\d{2}-\\d{4}\\b", "[SSN]", text)\n    text = re.sub(r"[\\w.+-]+@[\\w-]+\\.[\\w.]+", "[EMAIL]", text)\n    return text\n\nprompt = mask(user_text)  # send only the masked text'
    },
    {
      id: 'R04', area: 'Security', title: 'No passwords, keys or tokens are stored in the code',
      refs: [['OWASP', 'LLM02 sensitive information disclosure'], ['GDPR', 'Art. 32 security of processing'], ['HIPAA', '§164.312(a)(1) access control'], ['ISO', 'A.7 / A.8 controls']],
      why: 'A leaked key gives direct access to systems and models, and stays valid in git history until it is revoked.',
      test: function (d) { return d.noScan ? null : d.secrets; },
      steps: ['Revoke and replace every exposed key immediately.', 'Load keys from environment variables or a secrets manager.', 'Add a secret scanner to your pre-commit hook so this cannot happen again.'],
      example: '# before\nclient = OpenAI(api_key="sk-...")\n# after\nimport os\nclient = OpenAI(api_key=os.environ["OPENAI_API_KEY"])\n\n# .pre-commit-config.yaml\nrepos:\n  - repo: https://github.com/gitleaks/gitleaks\n    rev: v8.18.4\n    hooks: [{id: gitleaks}]'
    },
    {
      id: 'R05', area: 'Security', title: 'The code does not run unsafe commands built from text',
      refs: [['OWASP', 'LLM05 improper output handling'], ['AIACT', 'Art. 15 robustness and cybersecurity']],
      why: 'If model output or user input reaches eval(), exec() or a shell, an attacker can take over the server.',
      test: function (d) { return d.noScan ? null : d.unsafe; },
      steps: ['Remove eval/exec and shell=True.', 'Parse structured output (JSON) and map it to a fixed list of allowed actions.', 'Reject anything outside that list.'],
      example: 'import json\nALLOWED = {"search": search, "summarise": summarise}\ncmd = json.loads(model_output)\nfn = ALLOWED[cmd["action"]]   # KeyError = rejected\nfn(**cmd["args"])'
    },
    {
      id: 'R06', area: 'Security', title: 'All connections are encrypted',
      refs: [['HIPAA', '§164.312(e)(1) transmission security'], ['GDPR', 'Art. 32 security of processing']],
      why: 'Plain http:// links send data (and passwords) across the network in readable form.',
      test: function (d) { return d.noScan ? null : d.http; },
      steps: ['Change every http:// address to https://.', 'Keep certificate checking switched on (never verify=False).'],
      example: '# before\nrequests.get("http://api.example.org/data", verify=False)\n# after\nrequests.get("https://api.example.org/data")'
    },
    {
      id: 'R07', area: 'Security', title: 'Other code-security warnings are resolved',
      refs: [['OWASP', 'LLM05 / LLM06'], ['NIST', 'MANAGE'], ['AIACT', 'Art. 15']],
      why: 'Open code-safety warnings are known weaknesses that have not been decided on.',
      test: function (d) { return d.noScan ? null : d.codeOther; },
      steps: ['Open each warning and either fix it or record why it is acceptable.', 'Rescan to confirm it is closed.'],
      example: '# Each warning shows file and line. Fix, then rescan from Repositories & Scans.'
    },
    {
      id: 'R08', area: 'Software supply chain', title: 'A list of software components (SBOM) exists',
      refs: [['OWASP', 'LLM03 supply chain'], ['AIACT', 'Art. 15'], ['ISO', 'A.10 third-party relationships']],
      why: 'Without an inventory nobody can answer which libraries and AI packages the application depends on, or whether one is vulnerable.',
      test: function (d) { return d.noScan ? null : (d.components > 0 ? [] : [{ note: 'No dependency list was found in this repository.' }]); },
      steps: ['Commit a requirements.txt / package.json / pyproject.toml with pinned versions.', 'Export an SBOM in your build (CycloneDX).', 'Rescan so the inventory is recorded.'],
      example: '# requirements.txt\nfastapi==0.110.0\npydantic==2.7.0\n\n# build step\npip install cyclonedx-bom\ncyclonedx-py requirements -o sbom.json'
    },
    {
      id: 'R09', area: 'AI governance', title: 'Every AI provider and model in use is documented and approved',
      refs: [['AIACT', 'Art. 13 transparency'], ['GDPR', 'Art. 28 processors'], ['ISO', '6.1 / A.10'], ['NIST', 'GOVERN']],
      why: 'Each AI provider is a separate data-processing relationship with its own contract, location and risks.',
      test: function (d) { return d.noScan ? null : (d.providers.length || d.models.length ? d.providers.concat(d.models).map(function (x) { return { note: x }; }) : []); },
      steps: ['List each provider and model, who owns it and what data it receives.', 'Confirm a data-processing agreement is signed.', 'Add the approved ones to the approved list in AI Usage.'],
      example: 'AI register entry\n- Provider: <name>\n- Model: <model>\n- Data sent: <describe>\n- Contract / DPA: <link>\n- Approved by: <person>, <date>'
    },
    {
      id: 'R10', area: 'AI governance', title: 'A person can stop or approve risky AI actions',
      refs: [['AIACT', 'Art. 14 human oversight'], ['OWASP', 'LLM06 excessive agency'], ['NIST', 'GOVERN / MANAGE']],
      why: 'AI agents that can run tools or change data should never act without limits and a human check for destructive steps.',
      test: function (d) { return d.noScan ? null : (d.agents.length || d.tools.length || d.mcp.length ? d.agents.concat(d.tools, d.mcp).map(function (x) { return { note: x }; }) : []); },
      steps: ['Limit each agent to a short list of approved tools.', 'Require a human approval step for anything that deletes, pays or sends data.', 'Log every tool call.'],
      example: 'APPROVED_TOOLS = {"search_records"}\ndef call_tool(name, args):\n    if name not in APPROVED_TOOLS:\n        raise PermissionError(name)\n    if name in NEEDS_APPROVAL:\n        require_human_approval(name, args)'
    },
    {
      id: 'R11', area: 'AI governance', title: 'Protection against prompt-injection is in place',
      refs: [['OWASP', 'LLM01 prompt injection'], ['AIACT', 'Art. 15'], ['NIST', 'MEASURE']],
      why: 'Text from users or documents can try to override the AI’s instructions.',
      test: function (d) { return d.noScan ? null : (d.isAI ? (d.guardrails ? [] : [{ note: 'AI is used and no input/output safety library was found.' }]) : []); },
      steps: ['Keep system instructions separate from user text.', 'Check and filter model input and output (for example Guardrails or a moderation step).', 'Test with known prompt-injection examples before release.'],
      example: 'messages = [\n  {"role": "system", "content": POLICY},\n  {"role": "user", "content": sanitize(user_text)},\n]\nreply = check_output(llm(messages))'
    },
    {
      id: 'R12', area: 'AI governance', title: 'Data used by the AI (documents, vector stores) is documented',
      refs: [['AIACT', 'Art. 10 data governance'], ['GDPR', 'Art. 5 principles'], ['ISO', 'A.7 data for AI systems']],
      why: 'AI answers are only as safe as the data behind them. You need to know what data feeds the AI and who may see it.',
      test: function (d) { return d.noScan ? null : (d.rag.length ? d.rag.map(function (x) { return { note: x }; }) : []); },
      steps: ['List the data sources behind the AI (files, databases, vector stores).', 'Mark which contain personal or health data and who may access them.', 'Apply the same access rules to the AI as to the source data.'],
      example: 'Data source register\n- Source: <name / path>\n- Contains personal data: yes/no\n- Who can access: <roles>\n- Retention: <period>'
    },
    {
      id: 'R13', area: 'Risk & accountability', title: 'A risk assessment is recorded for this application',
      refs: [['AIACT', 'Art. 9 risk management'], ['GDPR', 'Art. 35 impact assessment'], ['NIST', 'GOVERN / MAP'], ['ISO', '6.1 risk assessment'], ['HIPAA', '§164.308(a)(1) risk analysis']],
      why: 'Laws expect a written risk assessment for systems that handle personal or health data or use AI. A scan cannot prove one exists.',
      test: function (d) { return d.noScan ? null : ((d.isAI || d.phi.length || d.pii.length) ? [{ note: 'Personal data or AI use detected — an owner must confirm a risk assessment exists.' }] : []); },
      steps: ['Write down what the system does, the data it handles and the harms that could result.', 'Name an owner and a review date.', 'Attach the document as owner-confirmed evidence on the Reviews page.'],
      example: 'Risk assessment (1 page)\n1. Purpose\n2. Data used\n3. Risks (privacy, safety, bias, security)\n4. Controls in place\n5. Residual risk and owner sign-off'
    },
    {
      id: 'R14', area: 'Operations', title: 'The release gate is clear (no blocking issues)',
      refs: [['NIST', 'MANAGE'], ['ISO', '8 operation'], ['AIACT', 'Art. 9']],
      why: 'The release gate stops code with serious open problems from being shipped.',
      test: function (d) { return d.noScan ? null : (d.ciBlock ? [{ note: 'The release gate is blocking this repository.' }] : []); },
      steps: ['Resolve or formally accept the issues listed above.', 'Rescan; the gate clears automatically.'],
      example: '# in CI\ncurl -s -H "Authorization: Bearer $TOKEN" $API/scans/$SCAN_ID/ci-gate'
    },
    {
      id: 'R15', area: 'Operations', title: 'AI usage is logged and cost is limited',
      refs: [['AIACT', 'Art. 12 record-keeping'], ['OWASP', 'LLM10 unbounded consumption'], ['NIST', 'MEASURE']],
      why: 'Without logs you cannot investigate an incident; without limits one bug can run up cost or overload the service.',
      test: function (d) { return d.noScan ? null : (d.isAI ? (d.runtime ? [] : [{ note: 'No live AI traffic has been connected yet, so this cannot be confirmed.' }]) : []); },
      steps: ['Connect the application in AI Usage so calls are recorded.', 'Set rate limits and token budgets per user.'],
      example: 'limiter = RateLimiter(max_calls=60, per_seconds=60)\nif not limiter.allow(user_id):\n    raise TooManyRequests()'
    }
  ];

  /* ------------------------------------------------------------------ data */
  function api(path) {
    return fetch(API + path, { headers: { Authorization: 'Bearer ' + token() } }).then(function (r) {
      if (!r.ok) throw new Error(path + ' ' + r.status);
      return r.json();
    });
  }
  function loc(f) { return (f.path || f.file || '') + (f.line ? ':' + f.line : ''); }
  function gather() {
    return api('/scans').then(function (res) {
      var list = (res.scans || res.items || res || []).filter(function (s) { return s.status === 'completed'; });
      var latest = {};
      list.forEach(function (s) {
        var k = s.repo_ref || s.scan_id;
        if (!latest[k] || String(s.scanned_at) > String(latest[k].scanned_at)) latest[k] = s;
      });
      var picks = Object.keys(latest).map(function (k) { return latest[k]; });
      return Promise.all(picks.map(function (s) { return api('/scans/' + encodeURIComponent(s.scan_id)).catch(function () { return null; }); }));
    }).then(function (docs) {
      docs = docs.filter(Boolean);
      var d = { noScan: docs.length === 0, repos: docs.length, pii: [], phi: [], secrets: [], unsafe: [], codeOther: [], http: [],
        components: 0, providers: [], models: [], agents: [], tools: [], mcp: [], rag: [], isAI: false, guardrails: false,
        ciBlock: false, runtime: false };
      docs.forEach(function (s) {
        var repo = (s.repo_ref || '').replace(/^https?:\/\/github\.com\//, '');
        function tag(f, extra) { return Object.assign({ where: loc(f), repo: repo }, extra || {}); }
        (((s.presidio || {}).findings) || []).forEach(function (f) {
          if (f.classification === 'SUPPRESSED' || f.doc_context) return;
          var item = tag(f, { note: ENT[f.entity_type] || nice(String(f.entity_type || 'data')) });
          if (String(f.data_category).toUpperCase() === 'PHI') d.phi.push(item); else d.pii.push(item);
        });
        (((s.gitleaks || {}).findings) || []).forEach(function (f) { d.secrets.push(tag(f, { note: 'A password or key' })); });
        (((s.semgrep || {}).findings) || []).forEach(function (f) {
          var rid = String(f.rule_id || f.check_id || f.rule || '') + ' ' + String(f.message || f.title || '');
          var it = tag(f, { note: String(f.message || f.title || f.rule_id || 'Code warning').slice(0, 120) });
          if (/eval|exec|shell|subprocess|pickle|deserial|yaml\.load|command.?injection/i.test(rid)) d.unsafe.push(it); else d.codeOther.push(it);
        });
        (((s.url_signals || {}).signals) || []).forEach(function (f) {
          var u = String(f.url || f.matched_url || f.value || '');
          if (/^http:\/\//i.test(u) && f.classification !== 'NOT_A_URL') d.http.push(tag(f, { note: 'Unencrypted web address' }));
        });
        d.components += Number((s.syft || {}).component_count || ((s.syft || {}).components || []).length || 0);
        var ai = s.ai_signatures || {};
        Object.keys(ai.providers_found || {}).forEach(function (k) { d.providers.push('Provider: ' + k); });
        Object.keys(ai.models_found || {}).forEach(function (k) { d.models.push('Model: ' + k); });
        (ai.agents_found || []).forEach(function (a) { d.agents.push('Agent: ' + (a.name || a.file || a)); });
        (ai.tools_found || []).forEach(function (a) { d.tools.push('Tool: ' + (a.name || a.file || a)); });
        (ai.mcp_found || []).forEach(function (a) { d.mcp.push('MCP server: ' + (a.name || a.file || a)); });
        (ai.rag_found || []).forEach(function (a) { d.rag.push('Data source: ' + (a.name || a.file || a)); });
        (ai.vector_stores_found ? Object.keys(ai.vector_stores_found) : []).forEach(function (k) { d.rag.push('Vector store: ' + k); });
        if (/guardrail|nemo|llm.?guard|moderation/i.test(Object.keys(ai.frameworks_found || {}).join(' '))) d.guardrails = true;
        if (ai.is_ai_application || s.is_ai_application || d.providers.length || d.models.length) d.isAI = true;
        var c = (((s.controls || {}).controls) || {});
        if (c.ci_block) d.ciBlock = true;
      });
      return api('/runtime/events?limit=1').then(function (r) { d.runtime = !!((r.items || r.events || []).length); return d; }).catch(function () { return d; });
    });
  }

  /* ------------------------------------------------------------------ evaluate + render */
  function evaluate(d) {
    return RULES.map(function (r) {
      var found = r.test(d);
      var status = found === null ? 'NOT_CHECKED' : (found.length ? 'REVIEW' : 'PASS');
      return { rule: r, status: status, items: found || [] };
    });
  }
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  var LABEL = { PASS: 'PASS', REVIEW: 'NEEDS REVIEW', NOT_CHECKED: 'NOT CHECKED YET' };
  var COLOR = { PASS: ['#bbf7d0', '#052e16', '#14532d'], REVIEW: ['#fde68a', '#422006', '#713f12'], NOT_CHECKED: ['#cbd5e1', '#1e293b', '#334155'] };
  function chip(st) { var c = COLOR[st]; return '<span style="display:inline-block;padding:2px 10px;border-radius:999px;font-size:11px;font-weight:700;color:' + c[0] + ';background:' + c[1] + ';border:1px solid ' + c[2] + '">' + LABEL[st] + '</span>'; }
  function std(r) { return r.refs.map(function (x) { return '<span style="display:inline-block;margin:2px 4px 2px 0;padding:1px 8px;border-radius:6px;font-size:11px;border:1px solid var(--border,#26334a);color:var(--muted-foreground,#94a3b8)" title="' + esc(x[1]) + '">' + esc(STD[x[0]]) + ' · ' + esc(x[1]) + '</span>'; }).join('');
  }
  var CSS = '#gov-rules-panel{margin:20px 0;border:1px solid var(--border,#26334a);border-radius:12px;background:var(--card,#101827);color:var(--foreground,#e5e7eb);padding:20px;font-size:14px}' +
    '#gov-rules-panel h3{margin:0 0 4px;font-size:18px;font-weight:700}#gov-rules-panel .sub{color:var(--muted-foreground,#94a3b8);font-size:13px}' +
    '#gov-rules-panel .sum{display:flex;gap:12px;flex-wrap:wrap;margin:14px 0}#gov-rules-panel .k{border:1px solid var(--border,#26334a);border-radius:10px;padding:10px 16px;min-width:130px}' +
    '#gov-rules-panel .k b{display:block;font-size:24px}#gov-rules-panel details{border-top:1px solid var(--border,#26334a)}' +
    '#gov-rules-panel summary{cursor:pointer;list-style:none;padding:12px 4px;display:flex;gap:12px;align-items:flex-start}#gov-rules-panel summary::-webkit-details-marker{display:none}' +
    '#gov-rules-panel .body{padding:0 4px 16px 4px}#gov-rules-panel pre{background:rgba(0,0,0,.25);border:1px solid var(--border,#26334a);border-radius:8px;padding:10px;overflow:auto;font-size:12.5px;white-space:pre-wrap}' +
    '#gov-rules-panel ol,#gov-rules-panel ul{margin:6px 0 6px 20px;padding:0}#gov-rules-panel .area{margin:18px 0 4px;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted-foreground,#94a3b8);font-weight:700}' +
    '#gov-rules-panel button{border:1px solid var(--border,#26334a);background:transparent;color:inherit;border-radius:8px;padding:4px 10px;font-size:12px;cursor:pointer}';

  function render(results, d) {
    var pass = results.filter(function (r) { return r.status === 'PASS'; }).length;
    var rev = results.filter(function (r) { return r.status === 'REVIEW'; }).length;
    var nc = results.filter(function (r) { return r.status === 'NOT_CHECKED'; }).length;
    var byArea = {};
    results.forEach(function (r) { (byArea[r.rule.area] = byArea[r.rule.area] || []).push(r); });
    var html = '<style>' + CSS + '</style>' +
      '<h3>Laws &amp; standards check</h3>' +
      '<div class="sub">Your latest scan of ' + d.repos + ' repositor' + (d.repos === 1 ? 'y' : 'ies') + ' is checked against rules taken from GDPR, HIPAA, the EU AI Act, NIST AI RMF, ISO/IEC 42001 and the OWASP LLM Top 10. ' +
      'Each rule says in plain words what is wrong, why it matters and how to fix it. This is guidance, not legal advice.</div>' +
      '<div class="sum"><div class="k"><b>' + pass + '</b>Passed</div><div class="k"><b>' + rev + '</b>Need review</div><div class="k"><b>' + nc + '</b>Not checked yet</div><div class="k"><b>' + results.length + '</b>Rules</div></div>';
    if (rev) {
      html += '<div class="sub" style="margin-bottom:8px"><b>Types of issues we are facing:</b> ' + Object.keys(byArea).map(function (a) {
        var n = byArea[a].filter(function (r) { return r.status === 'REVIEW'; }).length; return n ? esc(a) + ' (' + n + ')' : '';
      }).filter(Boolean).join(' · ') + '</div>';
    }
    Object.keys(byArea).forEach(function (a) {
      html += '<div class="area">' + esc(a) + '</div>';
      byArea[a].forEach(function (res) {
        var r = res.rule;
        html += '<details' + (res.status === 'REVIEW' ? '' : '') + '><summary>' + chip(res.status) + '<div><b>' + esc(r.title) + '</b><div>' + std(r) + '</div></div></summary><div class="body">';
        if (res.status === 'NOT_CHECKED') {
          html += '<p>There is no scan data yet for this rule. Run a scan from Repositories &amp; Scans and this check fills in automatically.</p>';
        } else if (res.status === 'PASS') {
          html += '<p>No issue found for this rule in the latest scans.</p><p class="sub">' + esc(r.why) + '</p>';
        } else {
          html += '<p><b>What we found:</b> ' + res.items.length + ' item' + (res.items.length === 1 ? '' : 's') + '.</p><ul>' +
            res.items.slice(0, 6).map(function (it) { return '<li>' + esc(it.note || '') + (it.where ? ' — <code>' + esc(it.where) + '</code>' : '') + (it.repo ? ' <span class="sub">(' + esc(it.repo) + ')</span>' : '') + '</li>'; }).join('') +
            (res.items.length > 6 ? '<li class="sub">…and ' + (res.items.length - 6) + ' more</li>' : '') + '</ul>' +
            '<p><b>Why it matters:</b> ' + esc(r.why) + '</p>' +
            '<p><b>What to do:</b></p><ol>' + r.steps.map(function (s) { return '<li>' + esc(s) + '</li>'; }).join('') + '</ol>' +
            '<p><b>Suggested fix you can copy:</b> <button data-copy="' + esc(r.id) + '">Copy</button></p><pre data-fix="' + esc(r.id) + '">' + esc(r.example) + '</pre>';
        }
        html += '</div></details>';
      });
    });
    return html;
  }

  var panel = null, started = false;
  function mount(html) {
    var main = document.querySelector('main');
    if (!main) return false;
    if (!panel) { panel = document.createElement('section'); panel.id = 'gov-rules-panel'; }
    panel.innerHTML = html;
    if (!panel.isConnected) {
      var anchor = null;
      var els = main.querySelectorAll('div,section');
      for (var i = 0; i < els.length; i++) {
        if (els[i].children.length >= 4 && /EVIDENCE COVERAGE/i.test(els[i].textContent || '') && els[i].textContent.length < 600) { anchor = els[i]; break; }
      }
      if (anchor) anchor.insertAdjacentElement('afterend', panel); else main.insertBefore(panel, main.children[1] || null);
    }
    return true;
  }
  function runRules() {
    if (location.pathname.replace(/\/$/, '') !== '/controls' || !token()) return;
    if (started && panel && panel.isConnected) return;
    started = true;
    gather().then(function (d) {
      var html = render(evaluate(d), d);
      var tries = 0;
      (function put() { if (!mount(html) && tries++ < 40) setTimeout(put, 250); })();
    }).catch(function (e) {
      started = false;
      mount('<style>' + CSS + '</style><h3>Laws &amp; standards check</h3><div class="sub">Could not load scan data right now (' + esc(e.message) + '). It will retry automatically.</div>');
    });
  }
  document.addEventListener('click', function (e) {
    var b = e.target.closest && e.target.closest('button[data-copy]');
    if (!b) return;
    var pre = document.querySelector('pre[data-fix="' + b.getAttribute('data-copy') + '"]');
    if (pre && navigator.clipboard) navigator.clipboard.writeText(pre.textContent).then(function () { b.textContent = 'Copied'; setTimeout(function () { b.textContent = 'Copy'; }, 1500); });
  });

  /* ------------------------------------------------------------------ boot */
  var timer = null;
  function tick() {
    if (busy) return; busy = true;
    try { walk(document.body); runRules(); } finally { busy = false; }
  }
  function schedule() { if (timer) return; timer = setTimeout(function () { timer = null; tick(); }, 150); }
  function boot() {
    tick();
    new MutationObserver(schedule).observe(document.body, { childList: true, subtree: true, characterData: true });
    setInterval(function () { started = started && panel && panel.isConnected; runRules(); }, 15000);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
