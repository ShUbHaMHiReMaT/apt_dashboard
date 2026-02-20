import httpx

async def search_threatfox(ioc):

    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = {"query": "search_ioc", "search_term": ioc}

    async with httpx.AsyncClient() as client:
        r = await client.post(url, json=payload)

    return r.json()