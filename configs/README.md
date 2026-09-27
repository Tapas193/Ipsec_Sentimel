# Configuration files for IPsec Sentinel.

| File | Purpose |
| --- | --- |
| `backend.env.example` | Backend-only environment overrides (can be sourced or passed to compose). |

The primary configuration reference lives in `.env.example` at the repository
root. Anything placed here overrides or documents more specific deployment
settings (for example, production-oriented backend vars) without polluting the
root file with secrets.