# =============================================================================
# IMPORTS
# =============================================================================
import os
import json
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

API_SECRET_KEY = os.getenv("API_SECRET_KEY", "test-key-12345")

# In-memory session store (replace with Redis for production)
sessions = {}


# =============================================================================
# AUTHENTICATION
# =============================================================================
def validate_api_key(x_api_key: str = Header(None)):
    if x_api_key != API_SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


# =============================================================================
# SESSION MANAGEMENT
# =============================================================================
def get_or_create_session(session_id: str):
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
        }
    return sessions[session_id]


def should_trigger_callback(session: dict) -> bool:
    """
    Decide if engagement is "complete" and we should send final callback.
    Criteria: scam detected + we have intel + 5+ messages exchanged.
    """
    if not session["scam_detected"]:
        return False

    total_msgs = len(session["conversation"])
    has_intel = any(session["extracted_intel"].values())

    return total_msgs >= 5 and has_intel


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
    is_scam = "SCAM" in result.upper()
    reason = result.replace("SCAM", "").replace("NOT_SCAM", "").strip()

    return is_scam, reason


def extract_intelligence(scammer_text: str, existing_intel: dict) -> dict:
    """
    Use Groq to extract structured intelligence from scammer's messages.
    """
    client = Groq()

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
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=f"Groq auth error: {e}")
    except BadRequestError as e:
        raise HTTPException(status_code=400, detail=f"Groq bad request: {e}")
    except RateLimitError as e:
        raise HTTPException(status_code=429, detail=f"Groq rate limited: {e}")
    except APIConnectionError as e:
        raise HTTPException(status_code=503, detail=f"Groq connection error: {e}")

    raw = response.choices[0].message.content or "{}"

    # Parse JSON safely
    try:
        intel = json.loads(raw)
    except json.JSONDecodeError:
        return existing_intel

    # Ensure keys exist
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


def agent_reply(
    latest_scammer_message: str, conversation_history: list[dict], extracted_intel: dict
) -> tuple[str, dict]:
    """
    AI Agent responds like a confused/concerned victim.
    Also extracts intelligence from the scammer's message.
    Returns (agent_response_text, updated_extracted_intel)
    """
    client = Groq()

    # Build conversation for Groq
    messages = [
        {
            "role": "system",
            "content": """You are a victim receiving a scam message. 
            Your goal: respond naturally (confused, concerned) to keep the scammer talking.
            NEVER reveal that you know it's a scam. Ask clarifying questions that make them reveal more details (bank, link, phone, UPI ID).
            Keep replies short and human-like (1-3 sentences max).""",
        }
    ]

    ROLE_MAP = {
        "scammer": "user",
        "user": "assistant",
    }

    # Add prior history
    for msg in conversation_history[-5:]:
        sender = msg.get("sender")
        text = msg.get("text")
        if not sender or not text:
            continue
        messages.append({"role": ROLE_MAP.get(sender, "user"), "content": text})

    # Add latest scammer message
    messages.append({"role": "user", "content": latest_scammer_message})

    # Get agent response
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

    agent_text = response.choices[0].message.content.strip()

    # Extract intelligence from scammer's message using Groq
    intelligence = extract_intelligence(latest_scammer_message, extracted_intel)

    return agent_text, intelligence


# =============================================================================
# CALLBACK
# =============================================================================
def send_guvi_callback(session_id: str, session: dict):
    """
    Send final results to GUVI evaluation endpoint.
    MANDATORY for scoring!
    """
    import requests

    payload = {
        "sessionId": session_id,
        "scamDetected": session["scam_detected"],
        "totalMessagesExchanged": len(session["conversation"]),
        "extractedIntelligence": session["extracted_intel"],
        "agentNotes": session["agent_notes"],
    }

    try:
        response = requests.post(
            os.getenv("GUVI_CALLBACK_ENDPOINT"), json=payload, timeout=5
        )
        print(f"Callback sent: {response.status_code}")
    except Exception as e:
        print(f"Callback failed: {e}")


# =============================================================================
# API ROUTES
# =============================================================================
@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.post("/api/honeypot")
async def honeypot_endpoint(
    request: IncomingRequest,
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(None),
):
    """
    Main honeypot endpoint.
    - Validate API key
    - Detect scam intent
    - If scam: activate agent
    - Extract intelligence
    - Return response
    - Trigger callback if engagement complete
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
            "timestamp": request.message.timestamp,
        }
    )

    # Detect scam intent on first message
    if not session["scam_detected"]:
        is_scam, reason = detect_scam_intent(request.message.text)
        session["scam_detected"] = is_scam
        session["agent_notes"] = reason

    # If not scam, return early
    if not session["scam_detected"]:
        return JSONResponse(
            {
                "status": "success",
                "scamDetected": False,
                "engagementMetrics": {
                    "engagementDurationSeconds": 0,
                    "totalMessagesExchanged": len(session["conversation"]),
                },
                "extractedIntelligence": None,
                "agentNotes": "No scam detected",
            }
        )

    # Scam detected → activate agent
    agent_text, updated_intel = agent_reply(
        request.message.text, session["conversation"], session["extracted_intel"]
    )

    session["extracted_intel"] = updated_intel

    # Add agent reply to conversation
    session["conversation"].append(
        {
            "sender": "user",
            "text": agent_text,
            "timestamp": datetime.now().isoformat() + "Z",
        }
    )

    # Calculate engagement duration
    engagement_seconds = int((datetime.now() - session["created_at"]).total_seconds())

    # Build response
    response = {
        "status": "success",
        "scamDetected": True,
        "engagementMetrics": {
            "engagementDurationSeconds": engagement_seconds,
            "totalMessagesExchanged": len(session["conversation"]),
        },
        "extractedIntelligence": session["extracted_intel"],
        "agentNotes": session["agent_notes"],
        "agentReply": agent_text,
    }

    # Check if we should trigger the mandatory callback
    if should_trigger_callback(session):
        background_tasks.add_task(send_guvi_callback, request.sessionId, session)

    return JSONResponse(response)
