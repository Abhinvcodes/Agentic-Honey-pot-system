# =============================================================================
# IMPORTS
# =============================================================================
import os
import json
import requests
from datetime import datetime

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from groq import (
    Groq,
    BadRequestError,
    RateLimitError,
    APIConnectionError,
    AuthenticationError,
)

from models import IncomingRequest

# =============================================================================
# CONFIGURATION
# =============================================================================
load_dotenv()

app = FastAPI()

API_SECRET_KEY = os.getenv("API_SECRET_KEY")
GUVI_CALLBACK_ENDPOINT = os.getenv("GUVI_CALLBACK_ENDPOINT")

# In-memory session store (replace with Redis for production)
sessions = {}

# Debug storage for last request
last_request_debug = {"body": None, "headers": None, "error": None}


# Middleware to capture raw request for debugging
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request


class DebugMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        global last_request_debug
        if request.url.path == "/api/honeypot":
            try:
                body = await request.body()
                last_request_debug = {
                    "body": body.decode() if body else None,
                    "headers": dict(request.headers),
                    "error": None,
                    "path": str(request.url.path),
                    "method": request.method,
                }
            except Exception as e:
                last_request_debug["error"] = str(e)

        response = await call_next(request)
        return response


app.add_middleware(DebugMiddleware)


# =============================================================================
# AUTHENTICATION
# =============================================================================
def validate_api_key(x_api_key: str = Header(None)):
    if x_api_key != API_SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


# =============================================================================
# SESSION MANAGEMENT
# =============================================================================
def get_or_create_session(session_id: str) -> dict:
    if session_id not in sessions:
        sessions[session_id] = {
            "created_at": datetime.now(),
            "conversation": [],
            "extracted_intel": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": [],
            },
            "scam_detected": False,
            "agent_notes": "",
            "callback_sent": False,
        }
    return sessions[session_id]


def should_trigger_callback(session: dict) -> bool:
    """
    Decide if engagement is "complete" and we should send final callback.
    Criteria:
    - Scam detected
    - Has some intel OR 5+ messages exchanged
    - Callback not already sent
    """
    if session["callback_sent"]:
        return False

    if not session["scam_detected"]:
        return False

    total_msgs = len(session["conversation"])
    has_intel = any(
        len(v) > 0 for v in session["extracted_intel"].values() if isinstance(v, list)
    )

    # Trigger if we have intel and 5+ messages, OR 10+ messages regardless
    return (total_msgs >= 5 and has_intel) or total_msgs >= 10


# =============================================================================
# AI FUNCTIONS
# =============================================================================
def detect_scam_intent(text: str) -> tuple[bool, str]:
    """
    Quick scam detection using Groq.
    Returns (is_scam: bool, reason: str)
    """
    client = Groq(api_key=os.getenv("GROQ_API_KEY"))
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": "You are a fraud detection expert. Analyze the message and determine if it contains scam intent. Reply with ONLY 'SCAM' or 'NOT_SCAM' followed by a brief reason.",
                },
                {"role": "user", "content": text},
            ],
            temperature=0.1,
            max_tokens=100,
        )
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=f"Groq auth error: {e}")
    except BadRequestError as e:
        raise HTTPException(status_code=400, detail=f"Groq bad request: {e}")
    except RateLimitError as e:
        raise HTTPException(status_code=429, detail=f"Groq rate limited: {e}")
    except APIConnectionError as e:
        raise HTTPException(status_code=503, detail=f"Groq connection error: {e}")

    result = response.choices[0].message.content.strip()

    # Check for NOT_SCAM first (more specific match)
    if result.upper().startswith("NOT_SCAM") or "NOT_SCAM" in result.upper():
        is_scam = False
        reason = result.replace("NOT_SCAM", "").replace("not_scam", "").strip(" :\n-")
    elif result.upper().startswith("SCAM") or "SCAM" in result.upper():
        is_scam = True
        reason = result.replace("SCAM", "").replace("scam", "").strip(" :\n-")
    else:
        is_scam = False
        reason = result

    return is_scam, reason if reason else "Analysis complete"


def extract_intelligence(scammer_text: str, existing_intel: dict) -> dict:
    """
    Use Groq to extract structured intelligence from scammer's messages.
    """
    client = Groq(api_key=os.getenv("GROQ_API_KEY"))

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Extract scam intelligence from the text.\n"
                        "Return ONLY valid JSON.\n"
                        "All keys must exist and each value must be an array of strings (use [] if none):\n"
                        "bankAccounts, upiIds, phishingLinks, phoneNumbers, suspiciousKeywords.\n"
                        "Do not include extra keys or any explanation."
                    ),
                },
                {"role": "user", "content": scammer_text},
            ],
            temperature=0,
            max_tokens=300,
            response_format={"type": "json_object"},
        )
    except (AuthenticationError, BadRequestError, RateLimitError, APIConnectionError):
        # On error, return existing intel unchanged
        return existing_intel

    raw = response.choices[0].message.content or "{}"

    try:
        intel = json.loads(raw)
    except json.JSONDecodeError:
        return existing_intel

    # Merge new intel with existing
    for k in [
        "bankAccounts",
        "upiIds",
        "phishingLinks",
        "phoneNumbers",
        "suspiciousKeywords",
    ]:
        existing_intel.setdefault(k, [])
        new_items = intel.get(k, []) or []
        if not isinstance(new_items, list):
            continue
        for item in new_items:
            if isinstance(item, str) and item and item not in existing_intel[k]:
                existing_intel[k].append(item)

    return existing_intel


def generate_agent_reply(
    latest_scammer_message: str, conversation_history: list[dict]
) -> str:
    """
    AI Agent responds like a confused/concerned victim.
    Returns agent's reply text only.
    """
    client = Groq(api_key=os.getenv("GROQ_API_KEY"))

    messages = [
        {
            "role": "system",
            "content": """You are a victim receiving a scam message. 
Your goal: respond naturally (confused, concerned) to keep the scammer talking.
NEVER reveal that you know it's a scam. 
Ask clarifying questions that make them reveal more details (bank, link, phone, UPI ID).
Keep replies short and human-like (1-3 sentences max).""",
        }
    ]

    ROLE_MAP = {"scammer": "user", "user": "assistant"}

    # Add prior history (last 5 messages for context)
    for msg in conversation_history[-5:]:
        sender = msg.get("sender")
        text = msg.get("text")
        if not sender or not text:
            continue
        messages.append({"role": ROLE_MAP.get(sender, "user"), "content": text})

    # Add latest scammer message
    messages.append({"role": "user", "content": latest_scammer_message})

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=messages,
            temperature=0.7,
            max_tokens=150,
        )
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=f"Groq auth error: {e}")
    except BadRequestError as e:
        raise HTTPException(status_code=400, detail=f"Groq bad request: {e}")
    except RateLimitError as e:
        raise HTTPException(status_code=429, detail=f"Groq rate limited: {e}")
    except APIConnectionError as e:
        raise HTTPException(status_code=503, detail=f"Groq connection error: {e}")

    return response.choices[0].message.content.strip()


# =============================================================================
# CALLBACK
# =============================================================================
def send_guvi_callback(session_id: str, session: dict):
    """
    Send final results to GUVI evaluation endpoint.
    MANDATORY for scoring!
    """
    # Calculate engagement duration
    engagement_seconds = int((datetime.now() - session["created_at"]).total_seconds())

    payload = {
        "sessionId": session_id,
        "status": "success",
        "scamDetected": session["scam_detected"],
        "engagementMetrics": {
            "engagementDurationSeconds": engagement_seconds,
            "totalMessagesExchanged": len(session["conversation"]),
        },
        "extractedIntelligence": session["extracted_intel"],
        "agentNotes": session["agent_notes"],
    }

    try:
        response = requests.post(
            GUVI_CALLBACK_ENDPOINT,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"},
        )
        print(f"✅ Callback sent for session {session_id}: {response.status_code}")
        print(f"   Response: {response.text[:200]}")
        session["callback_sent"] = True
    except Exception as e:
        print(f"❌ Callback failed for session {session_id}: {e}")


# =============================================================================
# API ROUTES
# =============================================================================
@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.get("/api/debug/last-request")
async def get_last_request():
    """View the last request received - useful for debugging deployed API"""
    return last_request_debug


@app.post("/api/honeypot")
async def honeypot_endpoint(
    request: IncomingRequest,
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(None),
):
    """
    Main honeypot endpoint.

    Flow:
    1. Validate API key
    2. Detect scam intent
    3. If scam: generate agent reply, extract intel in background
    4. Return ONLY {status, reply}
    5. Send full report to GUVI callback when engagement complete
    """
    # Validate API key
    validate_api_key(x_api_key)

    # Get or create session
    session = get_or_create_session(request.sessionId)

    # Add incoming message to conversation
    session["conversation"].append(
        {
            "sender": "scammer",
            "text": request.message.text,
            "timestamp": request.message.timestamp or datetime.now().isoformat() + "Z",
        }
    )

    # Detect scam intent (on every message to catch evolving scams)
    if not session["scam_detected"]:
        is_scam, reason = detect_scam_intent(request.message.text)
        session["scam_detected"] = is_scam
        session["agent_notes"] = reason

    # If not scam, return simple response
    if not session["scam_detected"]:
        return JSONResponse(
            {"status": "success", "reply": "Hello! How can I help you today?"}
        )

    # === SCAM DETECTED - Engage the scammer ===

    # Extract intelligence from scammer's message (updates session in place)
    session["extracted_intel"] = extract_intelligence(
        request.message.text, session["extracted_intel"]
    )

    # Generate agent reply to keep scammer engaged
    agent_reply_text = generate_agent_reply(
        request.message.text, session["conversation"]
    )

    # Add agent reply to conversation history
    session["conversation"].append(
        {
            "sender": "user",
            "text": agent_reply_text,
            "timestamp": datetime.now().isoformat() + "Z",
        }
    )

    # Check if we should send the final callback to GUVI
    if should_trigger_callback(session):
        background_tasks.add_task(send_guvi_callback, request.sessionId, session)

    # Return ONLY the simple response format
    return JSONResponse({"status": "success", "reply": agent_reply_text})
