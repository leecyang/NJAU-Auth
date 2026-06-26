# NJAU-Auth

南京农业大学统一身份认证（CAS）登录辅助库。项目形态参考 `Golevka2001/SEU-Auth`，当前版本使用纯 HTTP 请求完成登录，不依赖 Playwright 或浏览器自动化。

当前实现参考了本地 `NJAU-Libyy` 项目中可工作的 CAS 自动化流程，支持：

- 使用学号和统一认证密码登录。
- 先 GET 登录页，提取 `execution` 和 `pwdEncryptSalt`。
- 使用 AES-128-CBC / PKCS7 生成提交用密码密文。
- 检测账号密码错误、验证码要求和短信二次验证。
- 通过回调提交短信验证码。
- 保存并复用 Cookie，减少重复登录。
- 默认服务地址为 `http://jw3.njau.edu.cn/`。

## Installation

```bash
pip install -e .
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

## Notes

- 默认密码密文使用当前 CAS 可接受的形态：`pwdEncryptSalt` 作为 AES key、固定 16 字节 IV、`64 位随机前缀 + 原始密码` 作为明文。
- `utils.crypto` 里保留了固定 key 的兼容函数 `encrypt_password_with_fixed_key()`，用于兼容其他部署或后续验证。
- 如果要认证其他 CAS 服务，可在 `NJAUAuthClient` 或 `NJAUAuthManager` 中传入 `service_url` 和 `success_url_contains`。
- 当统一认证要求图形验证码或滑块验证码时，当前版本会直接抛出 `CaptchaRequiredError`，避免误判或卡死。
