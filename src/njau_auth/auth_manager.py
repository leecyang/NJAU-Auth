import json
from pathlib import Path
from typing import Any, Protocol

from .auth_client import (
    DEFAULT_SERVICE_URL,
    DEFAULT_SUCCESS_URL_CONTAINS,
    DEFAULT_TOKEN_STORAGE_KEY,
    NJAUAuthClient,
    SMSCallback,
)
from .models import LoginResult


class AuthStorage(Protocol):
    async def load_state(self, student_id: str) -> dict[str, Any] | None:
        ...

    async def save_state(self, student_id: str, state: dict[str, Any]) -> None:
        ...

    async def clear_state(self, student_id: str) -> None:
        ...


class JsonFileAuthStorage:
    def __init__(self, path: str | Path = "auth_session.json"):
        self.path = Path(path)
        self._data: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            self._data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self._data = {}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self._data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    async def load_state(self, student_id: str) -> dict[str, Any] | None:
        value = self._data.get("storage_state", {}).get(student_id)
        return value if isinstance(value, dict) else None

    async def save_state(self, student_id: str, state: dict[str, Any]) -> None:
        self._data.setdefault("storage_state", {})[student_id] = state
        self._save()

    async def clear_state(self, student_id: str) -> None:
        self._data.get("storage_state", {}).pop(student_id, None)
        self._save()


class NJAUAuthManager:
    def __init__(
        self,
        student_id: str,
        password: str,
        *,
        sms_callback: SMSCallback | None = None,
        storage: AuthStorage | None = None,
        service_url: str = DEFAULT_SERVICE_URL,
        success_url_contains: str = DEFAULT_SUCCESS_URL_CONTAINS,
        token_storage_key: str | None = DEFAULT_TOKEN_STORAGE_KEY,
        headless: bool = True,
        timeout_ms: int = 180_000,
        user_data_dir: str | Path | None = None,
        browser_launch_options: dict[str, Any] | None = None,
    ):
        self.student_id = student_id
        self.password = password
        self.sms_callback = sms_callback
        self.storage = storage or JsonFileAuthStorage()
        self.service_url = service_url
        self.success_url_contains = success_url_contains
        self.token_storage_key = token_storage_key
        self.headless = headless
        self.timeout_ms = timeout_ms
        self.user_data_dir = user_data_dir
        self.browser_launch_options = browser_launch_options or {}
        self._client: NJAUAuthClient | None = None

    async def __aenter__(self) -> "NJAUAuthManager":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None

    async def login(self, *, force_refresh: bool = False) -> LoginResult:
        storage_state = None
        if not force_refresh and self.user_data_dir is None:
            storage_state = await self.storage.load_state(self.student_id)

        self._client = NJAUAuthClient(
            service_url=self.service_url,
            success_url_contains=self.success_url_contains,
            token_storage_key=self.token_storage_key,
            headless=self.headless,
            timeout_ms=self.timeout_ms,
            user_data_dir=self.user_data_dir,
            storage_state=storage_state,
            browser_launch_options=self.browser_launch_options,
        )

        if not force_refresh and storage_state is not None:
            resumed = await self._client.resume()
            if resumed is not None:
                return resumed
            await self._client.close()
            self._client = None
            storage_state = None

        if self._client is None:
            self._client = NJAUAuthClient(
                service_url=self.service_url,
                success_url_contains=self.success_url_contains,
                token_storage_key=self.token_storage_key,
                headless=self.headless,
                timeout_ms=self.timeout_ms,
                user_data_dir=self.user_data_dir,
                storage_state=storage_state,
                browser_launch_options=self.browser_launch_options,
            )

        result = await self._client.login(
            self.student_id,
            self.password,
            sms_callback=self.sms_callback,
            clear_existing_state=force_refresh,
        )
        if self.user_data_dir is None:
            await self.storage.save_state(self.student_id, result.storage_state)
        return result
