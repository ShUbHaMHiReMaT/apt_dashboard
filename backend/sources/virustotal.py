import httpx
import os

VT_API = os.getenv("VT_API_KEY")

async def search_vt(ioc):
    if not VT_API:
        return {"data": [{}]}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    headers = {"x-apikey": VT_API}

    async with httpx.AsyncClient() as client:
        r = await client.get(url, headers=headers)

    if r.status_code == 200:
        return r.json() # Return full JSON for stats analysis
    else:
        return {"data": [{}]}