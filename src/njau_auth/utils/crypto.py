import base64
import secrets

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

DEFAULT_AES_KEY = "gfsdiR2u0wBytBq7"
DEFAULT_AES_IV = "HDbk7NdBpFPpFrZR"
RANDOM_PREFIX_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"


def aes_128_cbc_pkcs7_base64(plaintext: str, key: str, iv: str = DEFAULT_AES_IV) -> str:
    key_bytes = key.encode("utf-8")
    iv_bytes = iv.encode("utf-8")
    if len(key_bytes) != 16:
        raise ValueError("AES-128-CBC key must be exactly 16 bytes")
    if len(iv_bytes) != 16:
        raise ValueError("AES-128-CBC IV must be exactly 16 bytes")
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    return base64.b64encode(ciphertext).decode("ascii")


def random_prefix(length: int = 64) -> str:
    return "".join(secrets.choice(RANDOM_PREFIX_CHARS) for _ in range(length))


def encrypt_password(password: str, pwd_encrypt_salt: str, *, iv: str = DEFAULT_AES_IV) -> str:
    """Encrypt the password in the format accepted by the current NJAU CAS page.

    The browser script calls encryptPassword(password, pwdEncryptSalt). Empirically
    the server accepts AES-CBC with the dynamic page salt as the key, any 16-byte
    IV, and a 64-character random prefix before the raw password.
    """

    return aes_128_cbc_pkcs7_base64(
        random_prefix(64) + password,
        key=pwd_encrypt_salt,
        iv=iv,
    )


def encrypt_password_with_fixed_key(
    password: str,
    pwd_encrypt_salt: str,
    *,
    key: str = DEFAULT_AES_KEY,
    iv: str = DEFAULT_AES_IV,
) -> str:
    """Compatibility helper for fixed-key deployments: AES(salt + password)."""

    return aes_128_cbc_pkcs7_base64(pwd_encrypt_salt + password, key=key, iv=iv)

