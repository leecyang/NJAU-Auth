import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin

from njau_auth.exceptions import CASFormError
from njau_auth.models import LoginPage, PageState


def is_student_id(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9A-Za-z]{4,32}", value or ""))


def normalize_cas_error(text: str) -> str:
    value = re.sub(r"<[^>]+>", "", text or "")
    return " ".join(value.split()).strip()


def classify_sms_page_state(
    *,
    url: str,
    token: str | None = None,
    input_visible: bool = False,
    error_text: str = "",
    success_url_contains: str = "",
) -> PageState:
    if success_url_contains and success_url_contains in url:
        return PageState.AUTHENTICATED
    if token:
        return PageState.AUTHENTICATED
    if error_text.strip():
        return PageState.ERROR
    if input_visible:
        return PageState.SMS
    return PageState.WAITING


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: dict[str, dict[str, Any]] = {}
        self._current_form_id: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {key: value or "" for key, value in attrs}
        if tag.lower() == "form":
            form_id = attr.get("id") or f"__form_{len(self.forms)}"
            self._current_form_id = form_id
            self.forms[form_id] = {
                "attrs": attr,
                "inputs": {},
            }
            return

        if tag.lower() == "input" and self._current_form_id:
            name = attr.get("name") or attr.get("id")
            if name:
                self.forms[self._current_form_id]["inputs"][name] = attr.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current_form_id = None


def parse_forms(html: str) -> dict[str, dict[str, Any]]:
    parser = _FormParser()
    parser.feed(html)
    return parser.forms


def extract_login_page(html: str, url: str, *, base_url: str) -> LoginPage:
    forms = parse_forms(html)
    form = forms.get("pwdFromId")
    if not form:
        raise CASFormError("pwdFromId form was not found")

    fields = dict(form["inputs"])
    execution = fields.get("execution", "")
    pwd_encrypt_salt = fields.get("pwdEncryptSalt", "")
    if not execution:
        raise CASFormError("execution field was not found")
    if not pwd_encrypt_salt:
        raise CASFormError("pwdEncryptSalt field was not found")

    action = form["attrs"].get("action") or "/authserver/login"
    return LoginPage(
        url=url,
        action=urljoin(base_url, action),
        execution=execution,
        pwd_encrypt_salt=pwd_encrypt_salt,
        fields=fields,
    )


def extract_error_text(html: str) -> str:
    patterns = [
        r'id=["\']showErrorTip["\'][^>]*>(.*?)</',
        r'class=["\'][^"\']*(?:form-error|error|el-message)[^"\']*["\'][^>]*>(.*?)</',
    ]
    for pattern in patterns:
        match = re.search(pattern, html, re.I | re.S)
        if match:
            text = normalize_cas_error(match.group(1))
            if text:
                return text
    return ""


def has_sms_challenge(html: str, url: str) -> bool:
    needles = [
        "dynamicCode",
        "getDynamicCode",
        "短信验证码",
        "reAuthCheck",
        "reAuthLoginView",
    ]
    return any(needle in html or needle in url for needle in needles)


def has_captcha_challenge(html: str, error_text: str = "") -> bool:
    if "sliderCaptchaDiv" in html:
        return True
    if "captchaDiv" in html and "getCaptcha.htl" in html:
        return True
    return any(word in error_text for word in ["验证码", "图形动态码", "滑块"])

