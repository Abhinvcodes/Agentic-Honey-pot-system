# Agentic Honeypot API (GUVI Hackathon) — Problem Statement 2

This project implements an **Agentic Honey-Pot** system that:
- Detects scam/fraud intent in incoming messages
- Activates an autonomous AI agent to engage scammers (multi-turn) without revealing detection
- Extracts scam intelligence (UPI IDs, phone numbers, phishing links, etc.)
- Returns structured JSON responses via a REST API  
- Sends a **mandatory final callback** to the GUVI evaluation endpoint after engagement completes

## Features
- REST API with `x-api-key` authentication
- Multi-turn conversation support using `sessionId` + `conversationHistory`
- Scam intent detection using Groq LLM
- Agentic engagement (human-like persona)
- Structured intelligence extraction (JSON mode)
- Engagement metrics (`engagementDurationSeconds`, `totalMessagesExchanged`)

## Tech Stack
- Python 3.10+
- FastAPI + Uvicorn
- Groq LLM API (Python SDK)
- python-dotenv (for `.env`)

## Setup
```bash
python -m venv venv
source venv/bin/activate
pip install fastapi uvicorn groq python-dotenv requests
```
## .env
GROQ_API_KEY=YOUR_GROQ_KEY
API_SECRET_KEY=test-key-12345
GUVI_CALLBACK_ENDPOINT=https://hackathon.guvi.in/api/updateHoneyPotFinalResult

## Run server
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
## Test (single message)
```bash
bash single_msg_send_cmd.txt
```

## Test (simulated conversation)
```bash
for i in 0 1 2 3; do
  echo "STEP $((i+1))"
  jq -c ".[$i].request" simulated_conversation.json | \
    curl -s -X POST http://localhost:8000/api/honeypot \
      -H "Content-Type: application/json" \
      -H "x-api-key: test-key-12345" \
      --data-binary @- | jq .
done
```
