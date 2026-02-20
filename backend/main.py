import os
from fastapi import FastAPI, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

# Source Imports
from backend.sources.virustotal import search_vt
from backend.ipqs import lookup_ipqs
from backend.attribution import get_attribution, calculate_risk_matrix

app = FastAPI()

# Fix path resolution for Windows and Linux
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

# Serve static files for CSS/JS if needed
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

@app.get("/")
@app.get("/dashboard")
async def serve_dashboard():
    # Resolves the 404 by serving index.html from the absolute path
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"error": f"Frontend not found at {index_path}"}

@app.get("/search")
async def search_ioc(ioc: str = Query(..., description="The IOC to analyze")):
    # 1. Fetch Intelligence Data
    vt_data = await search_vt(ioc)
    ipqs_data = await lookup_ipqs(ioc)
    
    # 2. Extract Key Metrics
    vt_attr = vt_data.get("data", {}).get("attributes", {})
    if isinstance(vt_data.get("data"), list) and len(vt_data["data"]) > 0:
        vt_attr = vt_data["data"][0].get("attributes", {})
        
    vt_malicious = vt_attr.get("last_analysis_stats", {}).get("malicious", 0)
    fraud_score = ipqs_data.get("fraud_score", 0)
    
    # 3. APT Back-tracing Logic (Pivoting from IOC to Group)
    apt_info = get_attribution(ioc, vt_data)

    # 4. Matrix Risk Logic
    risk_label, color = calculate_risk_matrix(
        vt_malicious, 
        fraud_score, 
        ipqs_data.get("proxy", False), 
        ipqs_data.get("vpn", False)
    )

    return {
        "ip_address": ioc,
        "apt_group": apt_info,
        "display_color": color,
        "results": {
            "1. country": ipqs_data.get("country", vt_attr.get("country", "Unknown")),
            "2. malicious score (vt)": f"{vt_malicious} Engines Flagged",
            "3. ipqs score": f"{fraud_score} ({risk_label})",
            "4. proxy from ipqs": "Yes" if ipqs_data.get("proxy") else "No",
            "5. vpn non vpn": "VPN" if ipqs_data.get("vpn") else "Non-VPN"
        }
    }