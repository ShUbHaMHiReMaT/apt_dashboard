from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.sources.virustotal import search_vt
from backend.sources.otx import search_otx
from backend.sources.threatfox import search_threatfox
from backend.ipqs import lookup_ipqs
from backend.attribution import analyze_results
from backend.cache import get_cached, set_cache   # caching layer

app = FastAPI()

# Serve frontend folder
app.mount("/static", StaticFiles(directory="frontend"), name="static")


@app.get("/")
def home():
    return {"message": "APT Intelligence API running"}


@app.get("/dashboard")
def dashboard():
    return FileResponse("frontend/index.html")


@app.get("/search")
async def search_ioc(ioc: str):

    # --------------------
    # 1. check cache first
    # --------------------
    cached = get_cached(ioc)
    if cached:
        return cached

    # --------------------
    # 2. gather intel
    # --------------------
    results = {}

    results["virustotal"] = await search_vt(ioc)
    results["otx"] = await search_otx(ioc)
    results["threatfox"] = await search_threatfox(ioc)
    results["ipqs"] = await lookup_ipqs(ioc)

    # --------------------
    # 3. run attribution
    # --------------------
    analysis = analyze_results(ioc, results)

    response = {
        "ioc": ioc,
        "analysis": analysis,
        "raw_results": results
    }

    # --------------------
    # 4. save to cache
    # --------------------
    set_cache(ioc, response)

    return response