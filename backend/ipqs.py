import os
import httpx
from dotenv import load_dotenv

load_dotenv()

IPQS_KEY = os.getenv("IPQS_KEY")

async def lookup_ipqs(ip):

    if not IPQS_KEY:
        return {}

    url = f"https://www.ipqualityscore.com/api/json/ip/{IPQS_KEY}/{ip}"

    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(url)

    if r.status_code != 200:
        return {}

    data = r.json()

    return {
        "vpn": data.get("vpn"),
        "proxy": data.get("proxy"),
        "tor": data.get("tor"),
        "fraud_score": data.get("fraud_score"),
        "country": data.get("country_code"),
        "isp": data.get("ISP")
    }