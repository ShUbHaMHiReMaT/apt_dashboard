import os
import httpx
from dotenv import load_dotenv

load_dotenv()
IPQS_KEY = os.getenv("IPQS_KEY")

async def lookup_ipqs(ip: str):
    if not IPQS_KEY:
        return {}
    
    url = f"https://www.ipqualityscore.com/api/json/ip/{IPQS_KEY}/{ip}"
    async with httpx.AsyncClient() as client:
        r = await client.get(url)
        data = r.json()
        
        return {
            "fraud_score": data.get("fraud_score", 0),
            "country": data.get("country_code", "N/A"), # Capture country code
            "proxy": data.get("proxy", False),
            "vpn": data.get("vpn", False),
            "isp": data.get("ISP", "Unknown")
        }