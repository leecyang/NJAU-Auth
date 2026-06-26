# NJAU-Auth

南京农业大学统一身份认证（CAS）登录辅助库。项目形态参考 `Golevka2001/SEU-Auth`，但 NJAU 的登录流程不是纯 HTTP JSON 接口：密码加密依赖登录页中的 `encryptPassword()` 与 `pwdEncryptSalt`，因此本项目使用 Playwright 驱动真实认证页面完成登录。

当前实现参考了本地 `NJAU-Libyy` 项目中可工作的 CAS 自动化流程，支持：

- 使用学号和统一认证密码登录。
- 自动调用页面内加密函数提交 `saltPassword`。
- 检测账号密码错误、验证码要求和短信二次验证。
- 通过回调提交短信验证码。
- 保存并复用 Playwright `storage_state`，减少重复登录。
- 默认面向 `https://libyy.njau.edu.cn/student/studentIndex`，登录成功后读取 `localStorage.reflushToken`。

## Installation

```bash
pip install -e .
playwright install chromium
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
        headless=True,
    )

    async with manager:
        result = await manager.login()
        print(result.final_url)
        print(result.token)


asyncio.run(main())
```

## CLI

```bash
njau-auth-login --student-id 2023000000
```

如果不传 `--password`，命令会从交互式密码输入读取。

## Notes

- 默认服务地址是南京农业大学图书馆预约系统首页，因为本项目来自 `NJAU-Libyy` 的认证需求。
- 如果要认证其他 CAS 服务，可在 `NJAUAuthClient` 或 `NJAUAuthManager` 中传入 `service_url`、`success_url_contains` 和 `token_storage_key`。
- 当统一认证要求图形验证码或滑块验证码时，当前版本会直接抛出 `CaptchaRequiredError`，避免误判或卡死。

