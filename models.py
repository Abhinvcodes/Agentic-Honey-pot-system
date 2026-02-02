from pydantic import BaseModel, field_validator
from typing import Optional, List


class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[str] = None


class Metadata(BaseModel):
    channel: Optional[str] = None  # Accept any string, validate manually if needed
    language: Optional[str] = None
    locale: Optional[str] = None

    @field_validator("channel", mode="before")
    @classmethod
    def normalize_channel(cls, v):
        if v is None:
            return None
        # Normalize to expected format
        channel_map = {
            "sms": "SMS",
            "whatsapp": "WhatsApp",
            "email": "Email",
            "chat": "Chat",
        }
        return channel_map.get(v.lower(), v) if isinstance(v, str) else v

    class Config:
        extra = "ignore"


class IncomingRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[Message]] = []
    metadata: Optional[Metadata] = None

    class Config:
        extra = "ignore"


class ExtractedIntelligence(BaseModel):
    bankAccounts: Optional[List[str]] = []
    upiIds: Optional[List[str]] = []
    phishingLinks: Optional[List[str]] = []
    phoneNumbers: Optional[List[str]] = []
    suspiciousKeywords: Optional[List[str]] = []


class EngagementMetrics(BaseModel):
    engagementDurationSeconds: int
    totalMessagesExchanged: int


class APIResponse(BaseModel):
    status: str  # "success" or "error"
    scamDetected: bool
    engagementMetrics: Optional[EngagementMetrics] = None
    extractedIntelligence: Optional[ExtractedIntelligence] = None
    agentNotes: Optional[str] = None
    message: Optional[str] = None  # for error responses
