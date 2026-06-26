from njau_auth.models import PageState
from njau_auth.utils import (
    aes_128_cbc_pkcs7_base64,
    classify_sms_page_state,
    encrypt_password_with_fixed_key,
    is_student_id,
    normalize_cas_error,
)
from njau_auth.utils.parse import extract_login_page
from njau_auth.utils.parse import parse_need_captcha_response


def test_is_student_id_accepts_letters_and_digits():
    assert is_student_id("2023000000") is True
    assert is_student_id("A1234567") is True


def test_is_student_id_rejects_bad_values():
    assert is_student_id("") is False
    assert is_student_id("123") is False
    assert is_student_id("2023-000") is False


def test_classify_authenticated_when_success_url_and_token():
    assert (
        classify_sms_page_state(
            url="https://libyy.njau.edu.cn/student/studentIndex",
            token="token",
            input_visible=False,
            error_text="",
            success_url_contains="/student/studentIndex",
        )
        is PageState.AUTHENTICATED
    )


def test_classify_error_before_waiting():
    assert (
        classify_sms_page_state(
            url="https://authserver.njau.edu.cn/authserver/reAuthLoginView",
            token=None,
            input_visible=True,
            error_text=" 验证码错误 ",
            success_url_contains="/student/studentIndex",
        )
        is PageState.ERROR
    )


def test_classify_sms_waiting():
    assert (
        classify_sms_page_state(
            url="https://authserver.njau.edu.cn/authserver/reAuthLoginView",
            token=None,
            input_visible=True,
            error_text="",
            success_url_contains="/student/studentIndex",
        )
        is PageState.SMS
    )


def test_normalize_cas_error_collapses_whitespace():
    assert normalize_cas_error("  用户名或\n密码错误\t") == "用户名或 密码错误"


def test_extract_login_page_from_pwd_form():
    html = """
    <form id="pwdFromId" action="/authserver/login">
      <input id="username" name="username" value="">
      <input id="saltPassword" name="password" type="hidden">
      <input id="_eventId" name="_eventId" value="submit">
      <input id="cllt" name="cllt" value="userNameLogin">
      <input id="dllt" name="dllt" value="generalLogin">
      <input id="lt" name="lt" value="">
      <input id="pwdEncryptSalt" value="abcdefghijklmnop">
      <input id="execution" name="execution" value="exec-token">
    </form>
    """
    page = extract_login_page(
        html,
        "https://authserver.njau.edu.cn/authserver/login",
        base_url="https://authserver.njau.edu.cn",
    )
    assert page.action == "https://authserver.njau.edu.cn/authserver/login"
    assert page.execution == "exec-token"
    assert page.pwd_encrypt_salt == "abcdefghijklmnop"


def test_aes_128_cbc_pkcs7_base64_is_deterministic_for_fixed_inputs():
    encrypted = aes_128_cbc_pkcs7_base64(
        "salt-password",
        key="gfsdiR2u0wBytBq7",
        iv="HDbk7NdBpFPpFrZR",
    )
    assert encrypted == "CrlQs5cBatFsWRtEppXJjg=="


def test_fixed_key_compatibility_helper_uses_salt_plus_password():
    encrypted = encrypt_password_with_fixed_key(
        "password",
        "salt-",
        key="gfsdiR2u0wBytBq7",
        iv="HDbk7NdBpFPpFrZR",
    )
    assert encrypted == "CrlQs5cBatFsWRtEppXJjg=="


def test_parse_need_captcha_response():
    assert parse_need_captcha_response({"isNeed": True}) is True
    assert parse_need_captcha_response({"isNeed": False}) is False
    assert parse_need_captcha_response({}) is False
