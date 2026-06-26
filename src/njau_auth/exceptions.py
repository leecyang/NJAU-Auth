class NJAUAuthError(Exception):
    """Base exception for NJAU authentication failures."""

    def __init__(self, code: str, message: str, detail: str | None = None):
        super().__init__(message)
        self.code = code
        self.detail = detail


class InvalidCredentialsError(NJAUAuthError):
    def __init__(self, message: str = "Invalid student id or password"):
        super().__init__("CAS_INVALID_CREDENTIALS", message)


class CaptchaRequiredError(NJAUAuthError):
    def __init__(self, message: str = "CAS requires captcha verification"):
        super().__init__("CAS_CAPTCHA_REQUIRED", message)


class SMSRequiredError(NJAUAuthError):
    def __init__(self, message: str = "CAS requires SMS verification"):
        super().__init__("CAS_SMS_REQUIRED", message)


class CASFormError(NJAUAuthError):
    def __init__(self, message: str = "CAS login form is incomplete"):
        super().__init__("CAS_FORM_ERROR", message)
