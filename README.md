# FortiGate Sniffer to PCAP Converter

A web application that converts FortiGate network sniffer output files to Wireshark-compatible PCAPNG format.

## Features

- User authentication (signup/login with JWT)
- Upload FortiGate sniffer text files
- Convert to PCAPNG format
- Download original or converted files
- Manage conversion history

## Tech Stack

- **Backend:** FastAPI, SQLModel, SQLite, JWT authentication
- **Frontend:** React 19, Vite, React Router
- **Conversion:** Custom sniftran library (parser → assembler → PCAPNG writer)

## Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+

### Installation

```bash
# Clone repository
git clone <repository-url>
cd sniffer_to_pcap_fastapi

# Backend setup
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/Mac
pip install -r requirements.txt

# Frontend setup
cd frontend
npm install
npm run build
cd ..
```

### Running

```bash
# Start server
uvicorn fastapi_app.main:app --reload

# Access at http://localhost:8000
```

### Development Mode

Run backend and frontend separately for hot reload:

```bash
# Terminal 1: Backend
uvicorn fastapi_app.main:app --reload

# Terminal 2: Frontend (with proxy to backend)
cd frontend
npm run dev

# Access at http://localhost:5173
```

## API Documentation

Once running, visit:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Usage

1. Create an account at `/signup`
2. Login at `/login`
3. Upload FortiGate sniffer files from the dashboard
4. Click "Convert" to generate PCAPNG
5. Download the converted file for use in Wireshark

## Project Structure

```
├── fastapi_app/
│   ├── core/           # Config, database, security
│   ├── models/         # SQLModel ORM models
│   ├── schemas/        # Pydantic validation schemas
│   ├── routers/        # API endpoints
│   ├── services/       # Conversion business logic
│   └── sniftran/       # Sniffer to PCAP conversion library
├── frontend/
│   └── src/
│       ├── context/    # React auth context
│       ├── pages/      # Login, Signup, Dashboard
│       └── components/ # Reusable UI components
└── requirements.txt
```

## License

MIT
