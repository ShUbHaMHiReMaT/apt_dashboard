import httpx

VT_API = "YOUR_API_KEY"

async def search_vt(ioc):

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    headers = {"x-apikey": VT_API}

    async with httpx.AsyncClient() as client:
        r = await client.get(url, headers=headers)

    if r.status_code == 200:
        return {"data": [r.json()["data"]]}
    else:
        return {"data": [{}]}