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
