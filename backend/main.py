from fastapi import FastAPI, Query
from backend.sources.virustotal import search_vt
from backend.ipqs import lookup_ipqs
from backend.attribution import get_attribution, calculate_risk_matrix

app = FastAPI()

@app.get("/search")
async def search_ioc(ioc: str = Query(...)):
    vt_data = await search_vt(ioc)
    ipqs_data = await lookup_ipqs(ioc)
    
    # Extract VT stats
    vt_attr = vt_data.get("data", {}).get("attributes", {})
    vt_malicious = vt_attr.get("last_analysis_stats", {}).get("malicious", 0)
    
    # Extract IPQS stats
    fraud_score = ipqs_data.get("fraud_score", 0)
    proxy = ipqs_data.get("proxy", False)
    vpn = ipqs_data.get("vpn", False)
    
    # Fix: Ensure country is captured from the best available source
    country = ipqs_data.get("country") or vt_attr.get("country") or "N/A"

    # Back-tracing Logic
    apt_group = get_attribution(ioc, vt_data)
    verdict, color = calculate_risk_matrix(vt_malicious, fraud_score, proxy, vpn)

    return {
        "ip_address": ioc,
        "apt_group": apt_group,
        "display_color": color,
        "results": {
            "1. country": country,
            "2. malicious score (vt)": f"{vt_malicious} Engines",
            "3. ipqs score": f"{fraud_score} ({verdict})",
            "4. proxy from ipqs": "YES" if proxy else "NO",
            "5. vpn non vpn": "VPN" if vpn else "NON-VPN"
        }
    }