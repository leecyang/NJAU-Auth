from njau_auth.models import PageState
from njau_auth.utils import classify_sms_page_state, is_student_id, normalize_cas_error


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

