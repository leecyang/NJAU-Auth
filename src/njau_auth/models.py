from dataclasses import dataclass
from enum import Enum
from typing import Any


class PageState(str, Enum):
    PASSWORD = "PASSWORD"
    SMS = "SMS"
    AUTHENTICATED = "AUTHENTICATED"
    ERROR = "ERROR"
    WAITING = "WAITING"


@dataclass(slots=True)
class SMSChallenge:
    attempt: int
    expires_at: float
    message: str


@dataclass(slots=True)
class LoginResult:
    final_url: str
    token: str | None
    cookies: list[dict[str, Any]]
    storage_state: dict[str, Any]

