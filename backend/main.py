import os
from fastapi import FastAPI, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

# Import existing logic
from backend.sources.virustotal import search_vt
from backend.ipqs import lookup_ipqs
from backend.attribution import get_attribution, calculate_risk_matrix

app = FastAPI()

# Absolute pathing to prevent 404 errors
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

# Serve static files (CSS/JS) if they exist
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

@app.get("/")
@app.get("/dashboard")
async def serve_dashboard():
    """Serves the main dashboard and prevents 404s."""
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

@app.get("/search")
async def search_ioc(ioc: str = Query(...)):
    # Fetch data from both sources
    vt_data = await search_vt(ioc)
    ipqs_data = await lookup_ipqs(ioc)
    
    # Securely extract VT attributes
    data_node = vt_data.get("data", {})
    if isinstance(data_node, list) and len(data_node) > 0:
        vt_attr = data_node[0].get("attributes", {})
    else:
        vt_attr = data_node.get("attributes", {})

    vt_malicious = vt_attr.get("last_analysis_stats", {}).get("malicious", 0)
    
    # Extract missing IPQS fields
    fraud_score = ipqs_data.get("fraud_score", 0)
    is_proxy = ipqs_data.get("proxy", False)
    is_vpn = ipqs_data.get("vpn", False)
    
    # Trace APT Group (Back-tracing logic)
    apt_info = get_attribution(ioc, vt_data)
    
    # Determine Risk Level and Color for the Matrix
    verdict, color = calculate_risk_matrix(vt_malicious, fraud_score, is_proxy, is_vpn)

    return {
        "ip_address": ioc,
        "apt_group": apt_info,
        "display_color": color,
        "results": {
            "1. country": ipqs_data.get("country", vt_attr.get("country", "Unknown")),
            "2. malicious score (vt)": f"{vt_malicious} Engines Flagged",
            "3. ipqs score": f"{fraud_score} ({verdict})",
            "4. proxy from ipqs": "Yes" if is_proxy else "No",
            "5. vpn non vpn": "VPN" if is_vpn else "Non-VPN"
        }
    }