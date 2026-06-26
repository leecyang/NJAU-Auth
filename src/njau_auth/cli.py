import argparse
import asyncio
import getpass
from pathlib import Path

from .auth_manager import NJAUAuthManager
from .auth_client import _default_captcha_callback


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Login to NJAU CAS")
    parser.add_argument("--student-id", required=True)
    parser.add_argument("--password")
    parser.add_argument("--force-refresh", action="store_true")
    parser.add_argument("--service-url")
    parser.add_argument("--captcha-image-dir")
    parser.add_argument("--captcha-code")
    return parser


async def _run(args: argparse.Namespace) -> None:
    password = args.password or getpass.getpass("CAS password: ")

    async def sms_callback(challenge):
        print(challenge.message)
        return input("SMS code: ").strip()

    used_manual_captcha = False

    async def captcha_callback(challenge):
        nonlocal used_manual_captcha
        if args.captcha_image_dir:
            target_dir = Path(args.captcha_image_dir)
            target_dir.mkdir(parents=True, exist_ok=True)
            suffix = ".jpg" if "jpeg" in challenge.content_type.lower() else ".png"
            target = target_dir / f"captcha-{challenge.attempt}{suffix}"
            target.write_bytes(challenge.image)
            print(f"captcha_image={target}")
        if args.captcha_code and not used_manual_captcha:
            used_manual_captcha = True
            return args.captcha_code.strip()
        code = await _default_captcha_callback(challenge)
        print(f"captcha_ocr={code}")
        return code

    options = {}
    if args.service_url:
        options["service_url"] = args.service_url

    async with NJAUAuthManager(
        student_id=args.student_id,
        password=password,
        sms_callback=sms_callback,
        captcha_callback=captcha_callback,
        **options,
    ) as manager:
        result = await manager.login(force_refresh=args.force_refresh)
        print(f"final_url={result.final_url}")
        print(f"token={result.token or ''}")
        print("cookies=" + "; ".join(f"{cookie['name']}={cookie['value']}" for cookie in result.cookies))


def main() -> None:
    args = _parser().parse_args()
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
