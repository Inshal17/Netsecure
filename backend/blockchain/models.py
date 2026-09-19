from typing import Any, Optional

from pydantic import BaseModel, Field


class AnchorRequest(BaseModel):
    record_type: str = Field(
        ...,
        description="ANALYSIS, FINDING, REPORT, TRAINING_MAPPING or REMEDIATION",
    )
    analysis_id: str
    device_id: Optional[str] = None
    vendor: Optional[str] = None
    framework: Optional[str] = None
    payload: Any
    actor: str = "system"


class AnchorResponse(BaseModel):
    record_id: str
    analysis_id: str
    hash: str
    hash_algorithm: str
    previous_hash: str
    transaction_id: str
    status: str


class VerificationRequest(BaseModel):
    record_type: str = Field(
        ...,
        description="ANALYSIS, FINDING, REPORT, TRAINING_MAPPING or REMEDIATION",
    )
    analysis_id: str
    device_id: Optional[str] = None
    vendor: Optional[str] = None
    framework: Optional[str] = None
    payload: Any
    actor: str = "system"
    previous_hash: str = ""


class VerificationResponse(BaseModel):
    record_id: str
    supplied_hash: str
    blockchain_hash: str
    verified: bool
    status: str