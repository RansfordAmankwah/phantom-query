# Phantom Query (PHQ)

**A controlled AI interface for operational databases.**

Ask your database a question in plain English. Phantom Query proposes the SQL, a safety layer validates it, and nothing executes until you explicitly say so.

🔗 **Live:** [phantom-query.pages.dev](https://phantom-query.pages.dev)

---

## What this is

Phantom Query is not a BI dashboard, an autonomous data agent, or a SQL IDE. It's a deliberately narrow product built around one workflow:

```
Natural language question
        ↓
   AI proposes SQL
        ↓
  Safety validator (AST-parsed, read-only enforced)
        ↓
   Human reviews & approves
        ↓
      Executes
        ↓
Results as tables, charts, or exports
```

The target user isn't a data analyst — it's a non-technical person on a small team (ops, finance, product) who currently has to interrupt a developer every time they need a number out of the database. The pitch to that developer's manager is simple: **the AI never gets uncontrolled access to production data.**

---

## Core safety invariants

These are non-negotiable and enforced at multiple independent layers:

1. **Nothing executes without explicit user action.** The AI proposes; a human clicks Run. Retries produce a new proposal, never a silent re-execution.
2. **Every query passes through AST-based validation** (`sqlglot`) before execution — rejects anything but a single `SELECT`, rejects stacked statements, auto-injects `LIMIT` unless the query is aggregate-only.
3. **Every live database session is forced read-only** at the connection level (`SET default_transaction_read_only = on`), independent of the validator — defense in depth.
4. **Every connection/chat/history query is scoped by `user_id` and `workspace_id`** at the database-query level, never trusted from a client payload.
5. **Credentials are Fernet-encrypted at rest.** Passwords are bcrypt-hashed directly (not via `passlib`, which is broken against modern bcrypt).

---

## Feature overview

- **Natural language → SQL** for PostgreSQL and MySQL, with conversational multi-turn chat per database connection
- **SQL preview and manual execution** — the generated query is always shown before running
- **Charts, table views, and Excel/CSV export** of results
- **AI-generated result summaries** (opt-in)
- **Workspaces** — personal and team, with full data isolation between them
- **Role-based access control** — Owner / Admin / Member, enforced centrally in `permissions.py`
- **Per-connection access restriction** — mark a connection "Restricted" so only explicitly granted members can see it (404, not 403 — a restricted connection is invisible, not merely denied)
- **Full audit log** — every meaningful mutation (connections, folders, chats, membership changes, auth events, query execution) is recorded and viewable by admins/owners
- **Saved queries and folders** for organizing connections
- **Mobile-responsive** — collapsible sidebar and icon-first header on narrow viewports

---

## Tech stack

**Backend**
- FastAPI + SQLAlchemy
- PostgreSQL (Neon) for application data
- `psycopg2` / `PyMySQL` for target database connections
- `sqlglot` for SQL AST parsing and validation
- Google Gemini (`gemini-3.5-flash-lite`) for NL→SQL generation
- `bcrypt` (direct) + `python-jose` for auth
- `slowapi` for rate limiting
- Alembic for migrations

**Frontend**
- React + TypeScript + Vite
- Tailwind CSS v4
- Recharts for data visualization
- `lucide-react` for icons

**Infrastructure**
- Backend: [Render](https://render.com) (Docker, defined in `render.yaml`)
- Frontend: [Cloudflare Pages](https://pages.cloudflare.com)
- Database: [Neon](https://neon.tech) (serverless Postgres)

---

## Repository structure

```
phantom-query/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app assembly
│   │   ├── config.py            # Settings, validate_settings()
│   │   ├── security.py          # Fernet encryption, bcrypt, JWT
│   │   ├── permissions.py       # Single source of truth for role/access logic
│   │   ├── dependencies.py      # get_current_user_id, etc.
│   │   ├── db/
│   │   │   ├── models.py            # SQLAlchemy models
│   │   │   ├── connection_manager.py # CRUD + pooling for target DBs
│   │   │   ├── connection_access.py  # Per-connection grant logic
│   │   │   ├── introspector.py       # Schema introspection
│   │   │   ├── workspaces.py         # Workspace/membership service
│   │   │   ├── audit.py              # Audit log writes/reads
│   │   │   └── dialects/             # postgres.py, mysql.py adapters
│   │   ├── services/
│   │   │   ├── nl_to_sql.py       # Gemini calls: generate_sql, retry_sql
│   │   │   ├── validator.py       # SQL safety gate (sqlglot AST)
│   │   │   ├── explainer.py       # Query explanation
│   │   │   └── summarizer.py      # Result summarization
│   │   └── routers/               # auth, connections, query, chats, workspaces, audit, etc.
│   ├── alembic/                  # Migrations
│   ├── tests/                    # pytest suite (147 tests)
│   ├── Dockerfile
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── App.tsx               # Top-level state, view routing
│   │   ├── components/
│   │   │   ├── AppHeader.tsx
│   │   │   ├── Sidebar.tsx
│   │   │   ├── ChatThread.tsx
│   │   │   ├── Dashboard.tsx
│   │   │   ├── SettingsPage.tsx
│   │   │   ├── ConnectionForm.tsx
│   │   │   ├── ChartView.tsx
│   │   │   └── ...
│   │   ├── api/client.ts         # Fetch wrapper, reads VITE_API_URL
│   │   ├── utils/                # chartDetection.ts, export.ts
│   │   └── type.ts               # Types mirroring backend schemas
│   ├── .env.production
│   └── vite.config.ts
│
└── README.md
```

---

## Local development

### Prerequisites
- Python 3.13
- Node.js 18+
- A PostgreSQL instance (Neon works well) for app data
- A Gemini API key ([aistudio.google.com](https://aistudio.google.com))

### Backend

```bash
cd backend
python -m venv venv
venv\Scripts\Activate.ps1        # Windows
# source venv/bin/activate       # macOS/Linux

pip install -r requirements.txt
```

Create `backend/.env`:
```
APP_DATABASE_URL=sqlite:///./phantom_query.db
JWT_SECRET_KEY=<generate: python -c "import secrets; print(secrets.token_hex(32))">
CREDENTIAL_ENCRYPTION_KEY=<generate: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">
GEMINI_API_KEY=<your key>
```

Run migrations and start the server:
```bash
alembic upgrade head
python -m uvicorn app.main:app --reload --port 8000 --no-access-log
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

The frontend reads `VITE_API_URL` at build time, falling back to `http://localhost:8000` in development — no configuration needed for local dev.

### Tests

```bash
cd backend
python -m pytest tests/ -q
```

147 tests covering the SQL validator, the full role/permission system, per-connection access restriction, per-user rate limiting and the SSRF host guard.

---

## Deployment

Already live at the URLs above. To deploy your own instance:

1. **Backend → Render**: in the Render dashboard choose **New → Blueprint** and point it at this repo. `render.yaml` defines a Docker web service built from `backend/Dockerfile`, with `/api/health` as its health check. Render prompts once for the secrets: `APP_DATABASE_URL`, `JWT_SECRET_KEY`, `CREDENTIAL_ENCRYPTION_KEY`, `GEMINI_API_KEY`. Migrations (`alembic upgrade head`) run on container start.
2. **Frontend → Cloudflare Pages**: connect the repo, root directory `frontend`, build command `npm run build`, output directory `dist`. Set `VITE_API_URL` to your Render URL (e.g. `https://phantom-query-api.onrender.com`), then **redeploy**: Vite bakes it in at build time.
3. Set `ALLOWED_ORIGINS` in `render.yaml` (or the Render dashboard) to your Cloudflare Pages URL.

> **`CREDENTIAL_ENCRYPTION_KEY` is not rotatable by just changing it.** Every saved database password is Fernet-encrypted with it. Moving hosts or redeploying with a different key makes every stored connection undecryptable. Copy it exactly.

Before pointing users at a new host, check it end to end against the new URL directly: `GET /api/health`, sign in, then run one query on an existing saved connection, which proves the encryption key decrypts stored credentials.

---

## Known limitations

- No automated test coverage yet for auth flows, chat endpoints, or connection CRUD (validator, roles, and access control are covered).
- Query visibility controls (Public/Private/Shared per chat) are designed but not built.
- No organization-level usage dashboard yet.
- Local-only databases (`localhost`) are unreachable from the deployed cloud instance by design — the backend runs on Render's infrastructure, not the user's machine. A desktop build is a considered future direction, not yet started.

---

