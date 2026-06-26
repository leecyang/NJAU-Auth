import asyncio

from njau_auth import NJAUAuthManager


async def sms_callback(challenge):
    print(challenge.message)
    return input("SMS code: ").strip()


async def main():
    async with NJAUAuthManager(
        student_id="2023000000",
        password="your-password",
        sms_callback=sms_callback,
    ) as manager:
        result = await manager.login()
        print(result.final_url)
        print(result.token)


if __name__ == "__main__":
    asyncio.run(main())

