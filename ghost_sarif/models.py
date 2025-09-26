"""Data models for Ghost API responses and SARIF format."""

from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    """SARIF severity levels."""
    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"
    INFO = "info"


class GhostSeverity(str, Enum):
    """Ghost severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Ghost API Models
class GhostFinding(BaseModel):
    """Ghost security finding model."""
    id: str
    title: str
    description: str
    severity: GhostSeverity
    category: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    code_snippet: Optional[str] = None
    remediation: Optional[str] = None
    references: Optional[List[str]] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    status: Optional[str] = None
    confidence: Optional[str] = None


class GhostScan(BaseModel):
    """Ghost scan model."""
    id: str
    name: str
    status: str
    created_at: str
    updated_at: str
    findings: List[GhostFinding] = []


class GhostApiResponse(BaseModel):
    """Generic Ghost API response model."""
    success: bool
    data: Optional[Dict[str, Any]] = None
    message: Optional[str] = None
    error: Optional[str] = None


# SARIF Models
class SarifMessage(BaseModel):
    """SARIF message model."""
    text: str
    markdown: Optional[str] = None


class SarifLocation(BaseModel):
    """SARIF location model."""
    physicalLocation: Optional[Dict[str, Any]] = None


class SarifPhysicalLocation(BaseModel):
    """SARIF physical location model."""
    artifactLocation: Dict[str, str]
    region: Optional[Dict[str, Any]] = None


class SarifRegion(BaseModel):
    """SARIF region model."""
    startLine: Optional[int] = None
    startColumn: Optional[int] = None
    endLine: Optional[int] = None
    endColumn: Optional[int] = None
    snippet: Optional[Dict[str, str]] = None


class SarifRule(BaseModel):
    """SARIF rule model."""
    id: str
    name: Optional[str] = None
    shortDescription: Optional[SarifMessage] = None
    fullDescription: Optional[SarifMessage] = None
    help: Optional[SarifMessage] = None
    helpUri: Optional[str] = None
    properties: Optional[Dict[str, Any]] = None


class SarifResult(BaseModel):
    """SARIF result model."""
    ruleId: str
    ruleIndex: Optional[int] = None
    level: Optional[SeverityLevel] = None
    message: SarifMessage
    locations: Optional[List[SarifLocation]] = None
    properties: Optional[Dict[str, Any]] = None


class SarifTool(BaseModel):
    """SARIF tool model."""
    driver: Dict[str, Any]


class SarifRun(BaseModel):
    """SARIF run model."""
    tool: SarifTool
    results: List[SarifResult] = []
    properties: Optional[Dict[str, Any]] = None


class SarifReport(BaseModel):
    """SARIF report model."""
    version: str = "2.1.0"
    schema: str = Field(
        default="https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        alias="$schema"
    )
    runs: List[SarifRun]

    class Config:
        allow_population_by_field_name = True
