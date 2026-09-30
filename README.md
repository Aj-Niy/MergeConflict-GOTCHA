<p align="center">
  <img src="https://img.shields.io/badge/GOTCHA-Semantic_Trust_Verification-4f46e5?style=for-the-badge&logo=shield&logoColor=white" alt="GOTCHA" />
</p>

<h1 align="center">GOTCHA 2.0</h1>

<p align="center">
  <strong>Repository Trust Verification & Semantic Security Audit Platform</strong>
</p>

<p align="center">
  <strong>GOTCHA</strong> is a production-grade repository trust verification platform that audits AI tools, agent skills, MCP servers, and software packages by comparing natural-language documentation claims against static code behavior, secrets, dependency CVEs, and deterministic threat paths.
</p>

<p align="center">
  <em>"Don't just scan the code. Verify the claim."</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/TypeScript-5.7-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript" />
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Celery-5.6-37814A?style=flat-square&logo=celery&logoColor=white" alt="Celery" />
  <img src="https://img.shields.io/badge/PostgreSQL-16-336791?style=flat-square&logo=postgresql&logoColor=white" alt="PostgreSQL" />
  <img src="https://img.shields.io/badge/Ed25519-Signed_Attestation-blueviolet?style=flat-square" alt="Ed25519" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License" />
</p>

---

## 1. Full System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CLIENT LAYER                                  │
│  React 19 + TypeScript + Vite                                       │
│  TanStack Router/Query, Radix UI, Tailwind, Lucide, Recharts         │
│  Pages: Dashboard, Scan Report, Batch View, Policy Builder,          │
│         Attestation Viewer, History, Settings                        │
└───────────────────────────────┬─────────────────────────────────────┘
                                 │ REST (JSON) / JWT
┌───────────────────────────────▼─────────────────────────────────────┐
│                         API LAYER (FastAPI)                          │
│  /scan            POST   — submit single repo                        │
│  /scan/batch      POST   — submit multiple repos / org                │
│  /scan/{id}       GET    — auth'd / IDOR protected                   │
│  /scan/history    GET    — paginated history                         │
│  /policy          CRUD   — manage zero-trust security policies       │
│  /attestation/{id}/verify GET — Ed25519 signature check              │
│  /auth/*                 — JWT issue/login/register                  │
└───────────────────────────────┬─────────────────────────────────────┘
                                 │
┌───────────────────────────────▼─────────────────────────────────────┐
│                    ORCHESTRATION & PERSISTENCE                       │
│  Celery + Redis task queue + PostgreSQL / SQLite fallback            │
│  SQLAlchemy 2.0 ORM + Alembic migrations                            │
└───────────────────────────────┬─────────────────────────────────────┘
                                 │
        ┌────────────────────────┼─────────────────────────┐
        ▼                        ▼                          ▼
┌───────────────┐      ┌──────────────────┐      ┌────────────────────┐
│ INTAKE         │      │ SECURITY ANALYSIS │      │ CLAIM EXTRACTION    │
│ Tarball Fetch │─────▶│ (Python + JS/TS) │      │ (Bounded LLM /     │
│ & Traversal   │      │ Secrets Scan     │      │ Heuristic Fallback)│
│ Guard         │      │ Dependency Scan  │      └──────────┬─────────┘
└───────────────┘      │ (OSV.dev API)    │                 │
                        └─────────┬────────┘                 │
                                  │                          │
                                  ▼                          ▼
                        ┌───────────────────────────────────────────┐
                        │   CLAIM ↔ BEHAVIOR CORRELATION            │
                        │   MATCH / PARTIAL / MISMATCH / UNDISCLOSED│
                        └─────────────────┬─────────────────────────┘
                                          ▼
                        ┌───────────────────────────────────────────┐
                        │  DETERMINISTIC THREAT RULE ENGINE         │
                        │  Co-occurrence pattern threat paths       │
                        └─────────────────┬─────────────────────────┘
                                          ▼
                        ┌───────────────────────────────────────────┐
                        │  5-DIMENSIONAL WEIGHTED RISK ENGINE       │
                        │  Score (0-100) + Category + Evidence IDs  │
                        └─────────────────┬─────────────────────────┘
                                          ▼
                        ┌───────────────────────────────────────────┐
                        │  AI EXPLANATION LAYER                     │
                        │  Structured evidence synthesis & fixes    │
                        └─────────────────┬─────────────────────────┘
                                          ▼
                        ┌───────────────────────────────────────────┐
                        │  SECURITY POLICY ENGINE (Zero-Trust)      │
                        │  → ALLOW / WARN / RESTRICT / BLOCK        │
                        └─────────────────┬─────────────────────────┘
                                          ▼
                        ┌───────────────────────────────────────────┐
                        │  Ed25519 CRYPTOGRAPHIC ATTESTATION        │
                        │  Canonical SHA-256 Hash + Signature       │
                        └───────────────────────────────────────────┘
```

---

## 2. Key Components & Implementation

| Component | Implementation | Why & How |
|---|---|---|
| **Python Static Analysis** | Built-in `ast` module | Emits standard `Finding` objects for network, filesystem, environment, shell, subprocess, eval/exec, pickle.loads, dynamic imports, ctypes |
| **JS/TS Static Analysis** | Lexical & pattern AST visitor | Emits identical `Finding` contract for `child_process`, `fs`, `net`, `http`/`axios`/`fetch`, `process.env`, `eval`/`new Function()` |
| **Secrets Scanning** | `detect-secrets` + custom regex plugins | Detects OpenAI, AWS, GitHub, Slack, Stripe, JWT, and Private Keys; redacts values (`first 3...last 3` chars) before storage |
| **Dependency Scanning** | Manifest parser + OSV.dev REST API | Parses `requirements.txt`, `pyproject.toml`, `package.json`, queries `api.osv.dev/v1/querybatch` for CVEs (no API key required) |
| **Claim Extraction** | Bounded LLM with Heuristic Fallback | Fixed taxonomy (`Filesystem`, `Network`, `Environment`, `Database`, `Shell`, `Subprocess`) with prompt injection defense; falls back to deterministic heuristic if no LLM API key |
| **Threat Rules Engine** | Deterministic Python rules | Co-occurrence patterns (e.g., Environment + Network in same file = Candidate Exfiltration Path, Secret + Network = Credential Exfil Risk, Undisclosed Shell = Stealth Command Execution) |
| **5D Risk Model** | Weighted formula | `Code Safety` (0.25), `Secret Exposure` (0.20), `Dependency Security` (0.20), `Capability Risk` (0.15), `Claim-Behavior Gap` (0.20) |
| **Attestation** | Ed25519 (`cryptography` library) | Canonical JSON payload → SHA-256 hash → Ed25519 signature; verified via `/attestation/{id}/verify` |
| **Policy Engine** | Zero-Trust rule evaluator | Evaluates capabilities deterministically to output `ALLOW`, `WARN`, `RESTRICT`, or `BLOCK` |
| **Task Queue** | Celery + Redis | Async background worker pipeline + synchronous fallback execution |
| **Database** | PostgreSQL / SQLite + Alembic | Full migrations support via Alembic |

---

## 3. Getting Started

### Local Development

#### 1. Clone & Setup Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate        # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Run migrations
alembic upgrade head

# Run tests
pytest tests -v

# Start FastAPI server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### 2. Setup Frontend
```bash
cd frontend
npm install
npm run dev
```

The frontend will run at `http://localhost:5173` and backend API at `http://localhost:8000`.

---

### Docker Compose (Full Stack)

To run the complete production-like stack (PostgreSQL, Redis, Celery Worker, FastAPI API, and Frontend):

```bash
docker-compose up --build
```

---

## 4. API Endpoints

- `POST /api/scan`: Submit single repository URL for trust analysis
- `POST /api/scan/batch`: Submit multi-repository / org batch scan
- `GET /api/scan/{id}`: Get detailed scan report with 5D risk breakdown, findings, and attestation
- `GET /api/scan/history`: Paginated scan audit history
- `GET /api/scan/analytics`: Aggregate trust and risk statistics
- `GET /api/policy`: List security policies
- `POST /api/policy`: Create custom security policy
- `GET /api/attestation/{id}/verify`: Verify Ed25519 digital signature
- `POST /api/auth/register` & `POST /api/auth/login`: JWT authentication
- `GET /health`: Healthcheck

---

## 5. License
Released under the [MIT License](LICENSE).
