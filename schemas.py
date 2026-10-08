from dataclasses import dataclass, field
from typing import Any


@dataclass
class ParsedEmail:
    """
    Common representation of a parsed email.
    """

    subject: str
    body: str
    sender: str
    recipients: list[str]
    headers: dict[str, str]
    received_lines: list[str]
    origin_ip: str | None = None
    attachments: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class EngineResult:
    """
    Common result returned by each threat detection engine.
    """

    engine_name: str
    score: float
    verdict: str
    evidence: list[str] = field(default_factory=list)