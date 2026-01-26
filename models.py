from pydantic import BaseModel
from typing import Optional, List, Dict


class Message(BaseModel):
    sender: str  # "scammer" or "user"
    text: str
    timestamp: str


class IncomingRequest(BaseModel):
    sessionId: str
    message: Message  # latest message
    conversationHistory: Optional[List[Message]] = None
    metadata: Optional[Dict] = None


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
