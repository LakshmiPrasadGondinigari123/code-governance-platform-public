# Production frontend (snapshot of the live site)

Copy of what is deployed at https://frontend-production-4985.up.railway.app on 2026-10-13.

- `site/` and `html/` - captured Next.js static export of the original UI (one change: Overview tab renamed Dashboard, equal-size architecture arrows).
- `site/gov-rules.js` - plain-language labels on every page and the "Laws & standards check" on Governance Controls.
- `detail.html` - finding and scan pages in plain language (the original page chunks were lost when Railway removed old builds).
- `serve.py` + `Dockerfile` - static server with security headers.

Deploy: `railway up --service frontend` from this folder.
