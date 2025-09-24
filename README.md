# Find-a-Campsite — Redis Login System

Single-file Python CLI that uses **Redis** (key–value) to manage:
login, password (hashed), first name, security question, and security answer (hashed).

## Features
- Create Account · Login · Forgot Password · Load Users from CSV · List Security Questions
- Users stored as Redis **HASH** (`user:<login>`). Questions stored as **LIST** (`sec_questions`).
- Passwords and security answers are hashed with **bcrypt** (no plaintext secrets).

## Setup
1. Create `.env` from `.env.example` and set `REDIS_URL`.
   - Use `redis://...` for non-TLS, or `rediss://...` for TLS endpoints (Redis Cloud supports either, depending on your plan).
2. Install deps:
   ```bash
   pip install -r requirements.txt
## Run
python -m venv .venv
# Git Bash:
source .venv/Scripts/activate
# or CMD:
.venv\Scripts\activate.bat
pip install -r requirements.txt
copy .env.example .env  # set REDIS_URL
python app.py

## CSV Import
Header must be:
username,password,firstname
