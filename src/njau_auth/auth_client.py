import asyncio
import inspect
import time
from pathlib import Path
from typing import Any, Awaitable, Callable

from playwright.async_api import (
    Browser,
    BrowserContext,
    Error as PlaywrightError,
    Page,
    Playwright,
    TimeoutError as PlaywrightTimeoutError,
    async_playwright,
)

from .exceptions import CaptchaRequiredError, InvalidCredentialsError, NJAUAuthError
from .models import LoginResult, PageState, SMSChallenge
from .utils import classify_sms_page_state, is_student_id, normalize_cas_error

SMS_INPUT_SELECTOR = (
    '#dynamicCode, input[name="dynamicCode"], input[placeholder*="短信验证码"], '
    '#smsCode, #verifyCode, input[name="smsCode"]'
)
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
DEFAULT_SERVICE_URL = "https://libyy.njau.edu.cn/student/studentIndex"
DEFAULT_SUCCESS_URL_CONTAINS = "/student/studentIndex"
DEFAULT_TOKEN_STORAGE_KEY = "reflushToken"

SMS_TTL_SECONDS = 5 * 60

SMSCallback = Callable[[SMSChallenge], str | Awaitable[str]]


async def _default_sms_callback(challenge: SMSChallenge) -> str:
    print(challenge.message)
    return await asyncio.to_thread(input, "Please enter SMS code: ")


class NJAUAuthClient:
    """Browser-based NJAU CAS client.

    NJAU CAS password encryption is produced by JavaScript served on the login
    page. This client drives that page with Playwright instead of reimplementing
    the encrypted password algorithm locally.
    """

    def __init__(
        self,
        *,
        service_url: str = DEFAULT_SERVICE_URL,
        success_url_contains: str = DEFAULT_SUCCESS_URL_CONTAINS,
        token_storage_key: str | None = DEFAULT_TOKEN_STORAGE_KEY,
        headless: bool = True,
        timeout_ms: int = 180_000,
        user_data_dir: str | Path | None = None,
        storage_state: dict[str, Any] | str | Path | None = None,
        user_agent: str = DEFAULT_USER_AGENT,
        browser_launch_options: dict[str, Any] | None = None,
    ):
        self.service_url = service_url
        self.success_url_contains = success_url_contains
        self.token_storage_key = token_storage_key
        self.headless = headless
        self.timeout_ms = timeout_ms
        self.user_data_dir = Path(user_data_dir) if user_data_dir else None
        self.storage_state = storage_state
        self.user_agent = user_agent
        self.browser_launch_options = browser_launch_options or {}

        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._context: BrowserContext | None = None

    async def __aenter__(self) -> "NJAUAuthClient":
        await self.open()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    @property
    def context(self) -> BrowserContext:
        if self._context is None:
            raise RuntimeError("Client is not open. Call open() first.")
        return self._context

    async def open(self) -> None:
        if self._context is not None:
            return

        self._playwright = await async_playwright().start()
        launch_options = {"headless": self.headless, **self.browser_launch_options}

        if self.user_data_dir is not None:
            self.user_data_dir.mkdir(parents=True, exist_ok=True)
            self._context = await self._playwright.chromium.launch_persistent_context(
                str(self.user_data_dir),
                viewport={"width": 1365, "height": 768},
                user_agent=self.user_agent,
                **launch_options,
            )
            return

        self._browser = await self._playwright.chromium.launch(**launch_options)
        context_options: dict[str, Any] = {
            "viewport": {"width": 1365, "height": 768},
            "user_agent": self.user_agent,
        }
        if self.storage_state is not None:
            context_options["storage_state"] = self.storage_state
        self._context = await self._browser.new_context(**context_options)

    async def close(self) -> None:
        if self._context is not None:
            await self._context.close()
            self._context = None
        if self._browser is not None:
            await self._browser.close()
            self._browser = None
        if self._playwright is not None:
            await self._playwright.stop()
            self._playwright = None

    async def login(
        self,
        student_id: str,
        password: str,
        *,
        sms_callback: SMSCallback | None = None,
        clear_existing_state: bool = True,
    ) -> LoginResult:
        if not is_student_id(student_id):
            raise ValueError("student_id must be 4-32 letters or digits")
        if not password:
            raise ValueError("password must not be empty")

        await self.open()
        if clear_existing_state:
            await self.context.clear_cookies()

        page = await self._main_page()
        await self._goto_service(page)

        entry_state = await self.wait_for_cas_entry(page)
        if entry_state is PageState.PASSWORD:
            await self.submit_password(page, student_id, password)
            await self.wait_after_password(page, sms_callback or _default_sms_callback)
        elif entry_state is PageState.SMS:
            await self.handle_sms(page, sms_callback or _default_sms_callback)

        token = await self.wait_for_token_or_success(page)
        cookies = await self.context.cookies()
        storage_state = await self.context.storage_state()
        return LoginResult(
            final_url=page.url,
            token=token,
            cookies=cookies,
            storage_state=storage_state,
        )

    async def resume(self) -> LoginResult | None:
        await self.open()
        page = await self._main_page()
        await self._goto_service(page)
        token = await self._read_token(page)
        if self._is_success_url(page.url) and (token or self.token_storage_key is None):
            return LoginResult(
                final_url=page.url,
                token=token,
                cookies=await self.context.cookies(),
                storage_state=await self.context.storage_state(),
            )
        return None

    async def _main_page(self) -> Page:
        pages = self.context.pages
        return pages[0] if pages else await self.context.new_page()

    async def _goto_service(self, page: Page) -> None:
        try:
            await page.goto(
                self.service_url,
                wait_until="domcontentloaded",
                timeout=60_000,
            )
        except PlaywrightError as error:
            if not self._is_aborted_navigation(error):
                raise

    async def wait_for_cas_entry(self, page: Page) -> PageState:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            token = await self._read_token(page)
            if self._is_success_url(page.url) and (token or self.token_storage_key is None):
                return PageState.AUTHENTICATED
            if await self._visible(page, SMS_INPUT_SELECTOR):
                return PageState.SMS
            if "authserver.njau.edu.cn" in page.url and await page.locator("#pwdEncryptSalt").count():
                return PageState.PASSWORD
            await page.wait_for_timeout(200)
        raise NJAUAuthError("CAS_LOGIN_PAGE_NOT_FOUND", "CAS login page was not reached")

    async def submit_password(self, page: Page, student_id: str, password: str) -> None:
        if await self._visible(page, "#pwdFromId #captcha") or await self._visible(page, "#sliderCaptchaDiv > *"):
            raise CaptchaRequiredError("CAS requires captcha or slider verification")

        await page.wait_for_function(
            "() => typeof window.encryptPassword === 'function'",
            timeout=15_000,
        )
        await page.evaluate(
            """({ account, secret }) => {
                const username = document.querySelector("#pwdFromId #username");
                const passwordInput = document.querySelector("#pwdFromId #password");
                const saltPassword = document.querySelector("#pwdFromId #saltPassword");
                const salt = document.querySelector("#pwdFromId #pwdEncryptSalt")?.value;
                const form = document.querySelector("#pwdFromId");
                if (!username || !passwordInput || !saltPassword || !salt || !form || !window.encryptPassword) {
                    throw new Error("CAS password form is incomplete");
                }
                username.value = account;
                passwordInput.value = secret;
                saltPassword.value = window.encryptPassword(secret, salt);
                passwordInput.disabled = true;
                form.submit();
            }""",
            {"account": student_id, "secret": password},
        )

    async def wait_after_password(self, page: Page, sms_callback: SMSCallback) -> None:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self._is_success_url(page.url):
                return
            if await self._visible(page, SMS_INPUT_SELECTOR):
                await self.handle_sms(page, sms_callback)
                return
            if "reAuthCheck" in page.url or "reAuthLoginView" in page.url:
                await self.wait_for_sms_input(page)
                await self.handle_sms(page, sms_callback)
                return
            if "authserver.njau.edu.cn" in page.url:
                if await self._visible(page, "#pwdFromId #captcha") or await self._visible(page, "#sliderCaptchaDiv > *"):
                    raise CaptchaRequiredError("CAS requires captcha or slider verification")
                error_text = normalize_cas_error(
                    await self._text_content(page, "#showErrorTip, .error, .el-message")
                )
                if error_text:
                    raise InvalidCredentialsError("Invalid student id or CAS password")
            await page.wait_for_timeout(200)
        raise NJAUAuthError("CAS_LOGIN_TIMEOUT", "CAS login timed out")

    async def wait_for_sms_input(self, page: Page) -> None:
        try:
            await page.locator(SMS_INPUT_SELECTOR).filter(visible=True).first.wait_for(
                state="visible",
                timeout=15_000,
            )
        except PlaywrightTimeoutError as error:
            raise NJAUAuthError(
                "CAS_SMS_FORM_NOT_FOUND",
                "CAS reached SMS verification but the input was not visible",
                str(error),
            ) from error

    async def handle_sms(self, page: Page, sms_callback: SMSCallback) -> None:
        await self.wait_for_sms_input(page)
        send = page.locator("#getDynamicCode")
        if await self._visible(page, "#getDynamicCode"):
            await send.click(timeout=5_000)

        expires_at = time.time() + SMS_TTL_SECONDS
        for attempt in range(1, 4):
            challenge = SMSChallenge(
                attempt=attempt,
                expires_at=expires_at,
                message="Enter the 6-digit SMS code sent by NJAU CAS",
            )
            code = await self._call_sms_callback(sms_callback, challenge)
            if not code:
                raise NJAUAuthError("CAS_SMS_EMPTY", "SMS code callback returned empty code")
            if not code.isdigit() or len(code) != 6:
                raise ValueError("SMS code must be exactly 6 digits")

            previous_error = (await self._sms_observation(page))[1]
            input_box = page.locator(SMS_INPUT_SELECTOR).filter(visible=True).first
            await input_box.fill(code, timeout=5_000)
            submit = page.locator("button.auth_login_btn.submit_btn:visible").first
            try:
                if await self._locator_visible(submit):
                    await submit.click(timeout=5_000)
                else:
                    await input_box.press("Enter", timeout=5_000)
            except PlaywrightError as error:
                if not self._is_aborted_navigation(error) and not await self._wait_for_authentication(page, 5):
                    raise

            outcome, error_text = await self._wait_for_sms_submission_outcome(
                page,
                previous_error,
            )
            if outcome is PageState.AUTHENTICATED:
                return
            if attempt == 3:
                raise NJAUAuthError("CAS_SMS_ATTEMPTS_EXCEEDED", error_text or "SMS verification failed")

    async def wait_for_token_or_success(self, page: Page) -> str | None:
        deadline = time.monotonic() + self.timeout_ms / 1000
        while time.monotonic() < deadline:
            token = await self._read_token(page)
            if self._is_success_url(page.url) and (token or self.token_storage_key is None):
                return token
            await page.wait_for_timeout(500)
        raise NJAUAuthError("CAS_TOKEN_NOT_FOUND", "CAS completed but no service token was found")

    async def _sms_observation(self, page: Page) -> tuple[PageState, str]:
        token = await self._read_token(page)
        input_visible = await self._visible(page, SMS_INPUT_SELECTOR)
        error_text = normalize_cas_error(
            await self._text_content(page, "#showErrorTip, .error, .el-message")
        )
        state = classify_sms_page_state(
            url=page.url,
            token=token,
            input_visible=input_visible,
            error_text=error_text,
            success_url_contains=self.success_url_contains,
        )
        return state, error_text

    async def _wait_for_authentication(self, page: Page, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            state, _ = await self._sms_observation(page)
            if state is PageState.AUTHENTICATED:
                return True
            await page.wait_for_timeout(200)
        return False

    async def _wait_for_sms_submission_outcome(
        self,
        page: Page,
        previous_error: str,
    ) -> tuple[PageState, str]:
        started_at = time.monotonic()
        deadline = started_at + 60
        while time.monotonic() < deadline:
            state, error_text = await self._sms_observation(page)
            if state is PageState.AUTHENTICATED:
                return state, ""
            if state is PageState.ERROR and (
                error_text != previous_error or time.monotonic() - started_at >= 1.5
            ):
                return state, error_text
            await page.wait_for_timeout(200)
        raise NJAUAuthError("CAS_SMS_VERIFICATION_TIMEOUT", "SMS verification timed out")

    async def _read_token(self, page: Page) -> str | None:
        if self.token_storage_key is None:
            return None
        if not self._is_success_url(page.url):
            return None
        return await page.evaluate(
            "(key) => window.localStorage.getItem(key)",
            self.token_storage_key,
        )

    def _is_success_url(self, url: str) -> bool:
        return bool(self.success_url_contains and self.success_url_contains in url)

    @staticmethod
    def _is_aborted_navigation(error: Exception) -> bool:
        message = str(error)
        return "net::ERR_ABORTED" in message or "Navigation interrupted by another one" in message

    @staticmethod
    async def _visible(page: Page, selector: str) -> bool:
        try:
            return await page.locator(selector).first.is_visible(timeout=500)
        except PlaywrightError:
            return False

    @staticmethod
    async def _locator_visible(locator: Any) -> bool:
        try:
            return await locator.is_visible(timeout=500)
        except PlaywrightError:
            return False

    @staticmethod
    async def _text_content(page: Page, selector: str) -> str:
        try:
            return await page.locator(selector).first.text_content(timeout=500) or ""
        except PlaywrightError:
            return ""

    @staticmethod
    async def _call_sms_callback(callback: SMSCallback, challenge: SMSChallenge) -> str:
        value = callback(challenge)
        if inspect.isawaitable(value):
            value = await value
        return str(value).strip()
