import argparse
import asyncio
import getpass

from .auth_manager import NJAUAuthManager


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Login to NJAU CAS")
    parser.add_argument("--student-id", required=True)
    parser.add_argument("--password")
    parser.add_argument("--force-refresh", action="store_true")
    parser.add_argument("--service-url")
    return parser


async def _run(args: argparse.Namespace) -> None:
    password = args.password or getpass.getpass("CAS password: ")

    async def sms_callback(challenge):
        print(challenge.message)
        return input("SMS code: ").strip()

    options = {}
    if args.service_url:
        options["service_url"] = args.service_url

    async with NJAUAuthManager(
        student_id=args.student_id,
        password=password,
        sms_callback=sms_callback,
        **options,
    ) as manager:
        result = await manager.login(force_refresh=args.force_refresh)
        print(f"final_url={result.final_url}")
        print(f"token={result.token or ''}")
        print("cookies=" + "; ".join(f"{key}={value}" for key, value in result.cookies.items()))


def main() -> None:
    args = _parser().parse_args()
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
