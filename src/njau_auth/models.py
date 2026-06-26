from dataclasses import dataclass
from enum import Enum
from typing import Any


class PageState(str, Enum):
    LOGIN = "LOGIN"
    PASSWORD = "PASSWORD"
    SMS = "SMS"
    AUTHENTICATED = "AUTHENTICATED"
    CAPTCHA = "CAPTCHA"
    ERROR = "ERROR"
    WAITING = "WAITING"


@dataclass(slots=True)
class SMSChallenge:
    attempt: int
    expires_at: float
    message: str


@dataclass(slots=True)
class CaptchaChallenge:
    image: bytes
    content_type: str
    attempt: int
    message: str


@dataclass(slots=True)
class LoginResult:
    final_url: str
    token: str | None
    cookies: dict[str, str]
    storage_state: dict[str, Any]
    html: str = ""


@dataclass(slots=True)
class LoginPage:
    url: str
    action: str
    execution: str
    pwd_encrypt_salt: str
    fields: dict[str, str]
