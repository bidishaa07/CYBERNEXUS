from datetime import datetime
from pydantic import BaseModel, Field, HttpUrl

class ScanRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)

class ReportRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)
    reason: str = Field(min_length=3, max_length=255)
    details: str = Field(default="", max_length=2000)

class ReportOut(ReportRequest):
    id: int
    status: str
    created_at: datetime
    class Config: from_attributes = True
