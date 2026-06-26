import inspect
import re
from typing import Any, Awaitable, Callable
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from .exceptions import CaptchaRequiredError, InvalidCredentialsError, NJAUAuthError
from .models import LoginResult, SMSChallenge
from .utils.crypto import DEFAULT_AES_IV, encrypt_password
from .utils.parse import (
    extract_error_text,
    extract_login_page,
    has_captcha_challenge,
    has_sms_challenge,
    is_student_id,
)

DEFAULT_BASE_URL = "https://authserver.njau.edu.cn"
DEFAULT_SERVICE_URL = "http://jw3.njau.edu.cn/"
DEFAULT_SUCCESS_URL_CONTAINS = "jw"
DEFAULT_TOKEN_STORAGE_KEY = None
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

SMSCallback = Callable[[SMSChallenge], str | Awaitable[str]]


async def _default_sms_callback(challenge: SMSChallenge) -> str:
    print(challenge.message)
    return input("Please enter SMS code: ").strip()


class NJAUAuthClient:
    """Pure HTTP NJAU CAS client."""

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        service_url: str = DEFAULT_SERVICE_URL,
        success_url_contains: str = DEFAULT_SUCCESS_URL_CONTAINS,
        token_storage_key: str | None = DEFAULT_TOKEN_STORAGE_KEY,
        timeout: float = 30.0,
        headers: dict[str, str] | None = None,
        aes_iv: str = DEFAULT_AES_IV,
    ):
        self.base_url = base_url.rstrip("/")
        self.service_url = service_url
        self.success_url_contains = success_url_contains
        self.token_storage_key = token_storage_key
        self.timeout = timeout
        self.aes_iv = aes_iv
        self._headers = {
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            **(headers or {}),
        }
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "NJAUAuthClient":
        await self.open()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("Client is not open. Call open() first.")
        return self._client

    async def open(self) -> None:
        if self._client is not None:
            return
        self._client = httpx.AsyncClient(
            headers=self._headers,
            follow_redirects=True,
            timeout=self.timeout,
        )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def get_cookies(self) -> dict[str, str]:
        return dict(self.client.cookies)

    def load_cookies(self, cookies: dict[str, str]) -> None:
        self.client.cookies.update(cookies)

    async def resume(self) -> LoginResult | None:
        await self.open()
        response = await self.client.get(self.login_url)
        if self._is_success(response):
            return self._result(response)
        return None

    async def login(
        self,
        student_id: str,
        password: str,
        *,
        sms_callback: SMSCallback | None = None,
        captcha: str = "",
        clear_existing_state: bool = True,
    ) -> LoginResult:
        if not is_student_id(student_id):
            raise ValueError("student_id must be 4-32 letters or digits")
        if not password:
            raise ValueError("password must not be empty")

        await self.open()
        if clear_existing_state:
            self.client.cookies.clear()

        login_response = await self.client.get(self.login_url)
        login_response.raise_for_status()
        page = extract_login_page(
            login_response.text,
            str(login_response.url),
            base_url=self.base_url,
        )
        encrypted = encrypt_password(password, page.pwd_encrypt_salt, iv=self.aes_iv)

        data = {
            "username": student_id,
            "password": encrypted,
            "captcha": captcha,
            "_eventId": page.fields.get("_eventId", "submit"),
            "cllt": "userNameLogin",
            "dllt": page.fields.get("dllt", "generalLogin"),
            "lt": page.fields.get("lt", ""),
            "execution": page.execution,
        }
        response = await self.client.post(
            self._with_service(page.action),
            data=data,
            headers={
                "Origin": self.base_url,
                "Referer": str(login_response.url),
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        return await self._handle_login_response(
            response,
            sms_callback=sms_callback or _default_sms_callback,
        )

    async def _handle_login_response(
        self,
        response: httpx.Response,
        *,
        sms_callback: SMSCallback,
    ) -> LoginResult:
        if self._is_success(response):
            return self._result(response)

        error_text = extract_error_text(response.text)
        if has_captcha_challenge(response.text, error_text):
            raise CaptchaRequiredError(error_text or "CAS requires captcha verification")
        if self._is_invalid_credentials(error_text):
            raise InvalidCredentialsError(error_text)
        if has_sms_challenge(response.text, str(response.url)):
            response = await self._complete_sms(response, sms_callback)
            if self._is_success(response):
                return self._result(response)
            error_text = extract_error_text(response.text)
            raise NJAUAuthError("CAS_SMS_FAILED", error_text or "SMS verification failed")
        if error_text:
            raise NJAUAuthError("CAS_LOGIN_FAILED", error_text)
        raise NJAUAuthError("CAS_LOGIN_FAILED", "CAS login did not reach the target service")

    async def _complete_sms(
        self,
        response: httpx.Response,
        sms_callback: SMSCallback,
    ) -> httpx.Response:
        send_message = await self._try_send_sms_code(response)
        for attempt in range(1, 4):
            code = await self._call_sms_callback(
                sms_callback,
                SMSChallenge(
                    attempt=attempt,
                    expires_at=0,
                    message=send_message or "Enter the 6-digit SMS code sent by NJAU CAS",
                ),
            )
            if not code.isdigit() or len(code) != 6:
                raise ValueError("SMS code must be exactly 6 digits")

            data = self._sms_form_data(response.text)
            data["dynamicCode"] = code
            submit_url = self._sms_submit_url(response)
            response = await self.client.post(
                submit_url,
                data=data,
                headers={
                    "Origin": self.base_url,
                    "Referer": str(response.url),
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            if self._is_success(response):
                return response
            error_text = extract_error_text(response.text)
            if attempt == 3 or not has_sms_challenge(response.text, str(response.url)):
                raise NJAUAuthError("CAS_SMS_FAILED", error_text or "SMS verification failed")
        return response

    async def _try_send_sms_code(self, response: httpx.Response) -> str:
        candidates = self._sms_send_candidates(response)
        last_error = ""
        for url, data in candidates:
            try:
                sent = await self.client.post(
                    url,
                    data=data,
                    headers={
                        "Origin": self.base_url,
                        "Referer": str(response.url),
                        "X-Requested-With": "XMLHttpRequest",
                    },
                )
                if sent.status_code >= 400:
                    continue
                payload = self._json_or_text(sent)
                if isinstance(payload, dict):
                    message = str(payload.get("message") or payload.get("msg") or payload.get("info") or "")
                    code = str(payload.get("code") or "")
                    if code.lower() in {"success", "ok", "200"} or payload.get("success") is True:
                        return message
                    last_error = message or code
                elif "success" in payload.lower() or "已发送" in payload:
                    return payload
            except httpx.HTTPError as exc:
                last_error = str(exc)
        if last_error:
            return last_error
        return "SMS send endpoint was not confirmed; enter the code if it was sent"

    def _sms_send_candidates(self, response: httpx.Response) -> list[tuple[str, dict[str, str]]]:
        html = response.text
        candidates: list[tuple[str, dict[str, str]]] = []
        for match in set(
            re_match
            for re_match in re.findall(r'["\']([^"\']*dynamicCode[^"\']*?\.htl)["\']', html)
        ):
            candidates.append((httpx.URL(str(response.url)).join(match).__str__(), {}))
        candidates.extend(
            [
                (f"{self.base_url}/authserver/reAuth/getDynamicCode.htl", {}),
                (f"{self.base_url}/authserver/reAuth/sendDynamicCode.htl", {}),
                (f"{self.base_url}/authserver/dynamicCode/getDynamicCode.htl", {}),
            ]
        )
        return candidates

    def _sms_form_data(self, html: str) -> dict[str, str]:
        from .utils.parse import parse_forms

        forms = parse_forms(html)
        form = forms.get("pwdFromId") or forms.get("phoneFromId") or next(iter(forms.values()), None)
        fields = dict(form["inputs"]) if form else {}
        fields.setdefault("_eventId", "submit")
        fields.setdefault("cllt", "userNameLogin")
        fields.setdefault("dllt", "generalLogin")
        fields.setdefault("lt", "")
        return fields

    def _sms_submit_url(self, response: httpx.Response) -> str:
        from .utils.parse import parse_forms

        forms = parse_forms(response.text)
        form = forms.get("pwdFromId") or forms.get("phoneFromId") or next(iter(forms.values()), None)
        action = form["attrs"].get("action") if form else "/authserver/login"
        return self._with_service(httpx.URL(str(response.url)).join(action or "/authserver/login").__str__())

    def _is_success(self, response: httpx.Response) -> bool:
        url = str(response.url)
        if "authserver.njau.edu.cn" not in url and self.success_url_contains in url:
            return True
        return "xsMain.jsp" in url or "ticket=ST-" in url

    def _result(self, response: httpx.Response) -> LoginResult:
        return LoginResult(
            final_url=str(response.url),
            token=None,
            cookies=self.get_cookies(),
            storage_state={"cookies": self.get_cookies()},
            html=response.text,
        )

    def _with_service(self, url: str) -> str:
        parsed = urlparse(url)
        query = parsed.query
        if "service=" not in query:
            query = f"{query}&{urlencode({'service': self.service_url})}" if query else urlencode({"service": self.service_url})
        return urlunparse(parsed._replace(query=query))

    @property
    def login_url(self) -> str:
        return f"{self.base_url}/authserver/login?{urlencode({'service': self.service_url})}"

    @staticmethod
    def _json_or_text(response: httpx.Response) -> Any:
        try:
            return response.json()
        except ValueError:
            return response.text

    @staticmethod
    def _is_invalid_credentials(error_text: str) -> bool:
        return any(word in error_text for word in ["用户名", "密码错误", "账号", "凭证错误"])

    @staticmethod
    async def _call_sms_callback(callback: SMSCallback, challenge: SMSChallenge) -> str:
        value = callback(challenge)
        if inspect.isawaitable(value):
            value = await value
        return str(value).strip()
