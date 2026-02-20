import httpx

OTX_KEY = "11b1847679ae3ee6da61ff051382986ce8c8f9609cfe22534f22d96371aa856c"

async def search_otx(ioc):

    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general"
    headers = {"X-OTX-API-KEY": OTX_KEY}

    async with httpx.AsyncClient() as client:
        r = await client.get(url, headers=headers)

    if r.status_code == 200:
        return r.json()
    else:
        return {"error": "OTX lookup failed"}