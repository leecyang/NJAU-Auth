import re

from njau_auth.models import PageState


def is_student_id(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9A-Za-z]{4,32}", value or ""))


def classify_sms_page_state(
    *,
    url: str,
    token: str | None,
    input_visible: bool,
    error_text: str,
    success_url_contains: str,
) -> PageState:
    if success_url_contains and success_url_contains in url and token:
        return PageState.AUTHENTICATED
    if error_text.strip():
        return PageState.ERROR
    if input_visible:
        return PageState.SMS
    return PageState.WAITING


def normalize_cas_error(text: str) -> str:
    value = " ".join((text or "").split())
    return value.strip()

