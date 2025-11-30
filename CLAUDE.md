# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FortiGate Sniffer to PCAP Converter - A full-stack web application that converts FortiGate network sniffer output files to Wireshark-compatible PCAP format. Features user authentication, file upload/management, and real-time conversion.

## Tech Stack

- **Backend:** FastAPI, SQLModel (SQLite), JWT auth (python-jose), bcrypt
- **Frontend:** React 19, Vite, React Router DOM
- **Server:** Uvicorn

## Commands

### Backend
```bash
# Install dependencies
pip install -r requirements.txt

# Run development server
uvicorn fastapi_app.main:app --reload

# Production
uvicorn fastapi_app.main:app --host 0.0.0.0 --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev        # Development (localhost:5173, proxies to :8000)
npm run build      # Production build to frontend/dist/
npm run lint       # ESLint check
```

### Full Stack Development
```bash
# Terminal 1: Backend on :8000
uvicorn fastapi_app.main:app --reload

# Terminal 2: Frontend on :5173
cd frontend && npm run dev
```

## Architecture

```
fastapi_app/
├── core/           # Config, database, security (JWT/bcrypt)
├── models/         # SQLModel ORM (User, Conversion)
├── schemas/        # Pydantic validation
├── routers/        # API endpoints (auth, conversion, frontend)
├── services/       # Business logic (Convert2Pcap)
├── sniftran/       # Core conversion library (parser → assembler → writer)
└── utils/          # Runtime dirs (pcap_conversion_files/, _logs/)

frontend/src/
├── context/        # AuthContext (login, signup, logout state)
├── pages/          # Login, Signup, Dashboard
└── components/     # Layout, FileUpload, FileList
```

## Key Data Flows

**Authentication:** User signup/login → bcrypt hash → JWT token (30min) → stored in cookies

**Conversion Pipeline:**
1. Upload sniffer file → stored in Conversion.data (bytes)
2. Convert → sniftran parses → assembles packets → writes PCAPNG
3. Result stored in Conversion.data_converted
4. Download via /conversions/{id}/download/pcap

## API Endpoints

- `POST /token` - Login (OAuth2 form)
- `POST /signup` - Register user
- `POST /upload` - Upload sniffer files (requires auth)
- `GET /conversions` - List user's conversions
- `POST /convert/{id}` - Convert to PCAP
- `GET /conversions/{id}/download/original|pcap` - Download files
- `DELETE /conversions/{id}` - Delete conversion
- `PUT /conversions/{id}` - Rename conversion

## Database Models

**User:** id, email (unique), hashed_password, first_name, conversions (relationship)

**Conversion:** id, content (filename), data (bytes), date_created, data_converted (bytes, nullable), user_id (FK)

## Important Notes

- Dual-mode frontend: React SPA (production) with Jinja2 fallback (legacy)
- Temp files during conversion stored in `fastapi_app/utils/pcap_conversion_files/`
- Vite dev proxy routes `/api`, `/upload`, `/convert`, `/download`, etc. to backend
- File uploads sanitized to alphanumeric + `._-` characters only
