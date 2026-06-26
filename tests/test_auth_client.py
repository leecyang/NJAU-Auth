import asyncio
from urllib.parse import parse_qs

import httpx
import pytest

from njau_auth import CaptchaRequiredError
from njau_auth.auth_client import NJAUAuthClient
from njau_auth.cli import _parser


def login_page(execution="exec-1", salt="abcdefghijklmnop", extra=""):
    return f"""
    <html><body>
      {extra}
      <form id="pwdFromId" action="/authserver/login">
        <input id="username" name="username" value="">
        <input id="saltPassword" name="password" type="hidden">
        <input id="_eventId" name="_eventId" value="submit">
        <input id="cllt" name="cllt" value="userNameLogin">
        <input id="dllt" name="dllt" value="generalLogin">
        <input id="lt" name="lt" value="">
        <input id="pwdEncryptSalt" value="{salt}">
        <input id="execution" name="execution" value="{execution}">
      </form>
    </body></html>
    """


def response(request, status_code=200, text="", headers=None, url=None, content=None):
    response_request = httpx.Request(request.method, url) if url else request
    return httpx.Response(
        status_code,
        text=text if content is None else None,
        content=content,
        headers=headers,
        request=response_request,
        extensions={"network_stream": None},
    )


def run(coro):
    return asyncio.run(coro)


def test_login_retries_captcha_error_with_fresh_login_page():
    posts = []
    login_gets = 0
    captcha_gets = 0

    async def handler(request):
        nonlocal login_gets, captcha_gets
        path = request.url.path
        if path.endswith("/checkNeedCaptcha.htl"):
            return response(request, text='{"isNeed": true}', headers={"content-type": "application/json"})
        if path.endswith("/getCaptcha.htl"):
            captcha_gets += 1
            return response(request, content=b"jpeg", headers={"content-type": "image/jpeg"})
        if path.endswith("/authserver/login") and request.method == "GET":
            login_gets += 1
            return response(request, text=login_page(execution=f"exec-{login_gets}"))
        if path.endswith("/authserver/login") and request.method == "POST":
            body = request.content.decode()
            posts.append(parse_qs(body))
            if len(posts) == 1:
                return response(
                    request,
                    status_code=401,
                    text='<span id="showErrorTip">图形动态码错误</span>',
                )
            return httpx.Response(
                302,
                headers={"location": "http://jw3.njau.edu.cn/"},
                request=request,
            )
        if str(request.url) == "http://jw3.njau.edu.cn/":
            return response(request, text="ok")
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    codes = iter(["bad1", "good"])

    async def captcha_callback(challenge):
        return next(codes)

    async def scenario():
        client = NJAUAuthClient(transport=httpx.MockTransport(handler))
        async with client:
            result = await client.login(
                "2023000000",
                "password",
                captcha_callback=captcha_callback,
            )
        return result

    result = run(scenario())
    assert result.final_url == "http://jw3.njau.edu.cn/"
    assert login_gets == 2
    assert captcha_gets == 2
    assert posts[0]["execution"] == ["exec-1"]
    assert posts[0]["captcha"] == ["bad1"]
    assert posts[1]["execution"] == ["exec-2"]
    assert posts[1]["captcha"] == ["good"]


def test_slider_captcha_raises_without_ocr_attempt():
    async def handler(request):
        if request.url.path.endswith("/authserver/login") and request.method == "GET":
            return response(request, text=login_page(extra='<script src="/authserver/common/toSliderCaptcha.htl"></script>'))
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    async def scenario():
        client = NJAUAuthClient(transport=httpx.MockTransport(handler))
        async with client:
            await client.login("2023000000", "password")

    with pytest.raises(CaptchaRequiredError, match="slider captcha"):
        run(scenario())


def test_cli_accepts_captcha_options():
    args = _parser().parse_args(
        [
            "--student-id",
            "2023000000",
            "--captcha-image-dir",
            "captchas",
            "--captcha-code",
            "abcd",
        ]
    )
    assert args.captcha_image_dir == "captchas"
    assert args.captcha_code == "abcd"


def test_reauth_sms_send_candidate_uses_reauth_endpoint():
    html = """
    <script>
    var reAuthParams = {
      "reAuthType": "3",
      "reAuthUserId": "2023000000",
      "service": "http://jw3.njau.edu.cn/",
      "isMultifactor": "true"
    };
    </script>
    """
    request = httpx.Request("GET", "https://authserver.njau.edu.cn/authserver/reAuthCheck/reAuthLoginView.do")
    resp = httpx.Response(200, text=html, request=request)
    client = NJAUAuthClient()
    candidates = client._sms_send_candidates(resp)
    assert candidates[0] == (
        "https://authserver.njau.edu.cn/authserver/dynamicCode/getDynamicCodeByReauth.do",
        {"userName": "2023000000", "authCodeTypeName": "reAuthDynamicCodeType"},
    )
