from pydantic import BaseModel
from typing import Optional, List, Dict, Any


class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[str] = None


class Metadata(BaseModel):
    platform: Optional[str] = None
    reportedCount: Optional[int] = None


class IncomingRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[Message]] = []
    metadata: Optional[Metadata] = None


class ExtractedIntelligence(BaseModel):
    bankAccounts: Optional[List[str]] = None
    upiIds: Optional[List[str]] = None
    phishingLinks: Optional[List[str]] = None
    phoneNumbers: Optional[List[str]] = None
    suspiciousKeywords: Optional[List[str]] = None


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
