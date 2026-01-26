# Example-App-Server

## Overview
Reference app server that selects a backend and verifies tokens.

## Endpoints
- `POST /select-backend` -> selects backendId based on backendIds from app.
- `POST /verify` -> calls backend `/api/v1/app/decodeToken` with apiSecret.

## Env
- `UA_BACKEND_URL` (default `http://localhost:3001`)
- `UA_BACKEND_ID` (optional, preferred backend for selection)
- `UA_API_SECRET` (required)
- `UA_BACKEND_BLACKLIST` (comma-separated)

## Run
```bash
cd Example-App-Server
npm install
npm run dev
```
