# NJAU-Auth

南京农业大学统一身份认证（CAS）登录辅助库，使用纯 HTTP 请求完成登录，不依赖 Playwright 或浏览器自动化。

当前支持：

- 使用学号和统一认证密码登录。
- 先 GET 登录页，提取 `execution` 和 `pwdEncryptSalt`。
- 使用 AES-128-CBC / PKCS7 生成提交用密码密文。
- 登录前自动检查是否需要图形验证码，必要时用 `ddddocr` 默认模型识别 80x30 四位字符验证码。
- 检测账号密码错误、验证码要求和短信二次验证。
- 通过回调提交短信验证码。
- 保存并复用 Cookie，减少重复登录。
- 默认服务地址为 `http://jw3.njau.edu.cn/`。

## Installation

```bash
pip install njau-auth
```

## Basic Usage

```python
import asyncio
from njau_auth import NJAUAuthManager


async def sms_callback(challenge):
    print(challenge.message)
    return input("SMS code: ").strip()


async def main():
    manager = NJAUAuthManager(
        student_id="2023000000",
        password="your-password",
        sms_callback=sms_callback,
    )

    async with manager:
        result = await manager.login()
        print(result.final_url)
        print(result.cookies)


asyncio.run(main())
```

## CLI

```bash
njau-auth-login --student-id 2023000000
```

如果不传 `--password`，命令会从交互式密码输入读取。

调试验证码识别时可以保存图片，或指定一次手动验证码：

```bash
njau-auth-login --student-id 2023000000 --captcha-image-dir ./captchas
njau-auth-login --student-id 2023000000 --captcha-code abcd
```

## Notes

- 默认密码密文使用当前 CAS 可接受的形态：`pwdEncryptSalt` 作为 AES key、固定 16 字节 IV、`64 位随机前缀 + 原始密码` 作为明文。
- 图形验证码默认使用 `ddddocr` 的 common.onnx 模型自动识别。
- `utils.crypto` 里保留了固定 key 的兼容函数 `encrypt_password_with_fixed_key()`，用于兼容其他部署或后续验证。
- 如果要认证其他 CAS 服务，可在 `NJAUAuthClient` 或 `NJAUAuthManager` 中传入 `service_url` 和 `success_url_contains`。
- 当统一认证要求滑块验证码，或图形验证码多次识别失败时，当前版本会抛出 `CaptchaRequiredError`。
