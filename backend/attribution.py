import os
import json
from backend.mitre_lookup import search_mitre_for_actor

def get_attribution(ioc, vt_data):
    """Traces an IOC back to a specific APT group."""
    # Check VT Tags first
    data = vt_data.get("data", {})
    attr = data[0].get("attributes", {}) if isinstance(data, list) and data else data.get("attributes", {})
    tags = attr.get("tags", [])
    
    for tag in tags:
        if any(keyword in tag.lower() for keyword in ["apt", "group", "lazarus", "fancy", "bear"]):
            return f"Associated with {tag.upper()}"

    # Pivot to MITRE search
    mitre_matches = search_mitre_for_actor(ioc)
    if mitre_matches:
        return f"MITRE Group: {mitre_matches[0]['name'].upper()}"
        
    return "No Known APT Association"

def calculate_risk_matrix(vt_malicious, ipqs_score, proxy, vpn):
    """Calculates risk based on the 5x5 Matrix requirements."""
    threat_points = 0
    if vt_malicious > 20: threat_points += 15
    elif vt_malicious >= 6: threat_points += 9
    if proxy: threat_points += 3
    if vpn: threat_points += 2

    # Map to Rows A-E
    row = "A" if threat_points == 0 else "B" if threat_points <= 3 else "C" if threat_points <= 9 else "D" if threat_points <= 15 else "E"
    
    # Map to Columns 1-5
    col = 1 if ipqs_score <= 20 else 2 if ipqs_score <= 40 else 3 if ipqs_score <= 60 else 4 if ipqs_score <= 80 else 5

    matrix = {
        ("A",1):("Very Low","#008000"), ("B",3):("Low","#008000"), ("C",3):("Medium","#FFD700"), 
        ("D",4):("High","#FF8C00"), ("E",5):("Very High","#FF0000")
    }
    return matrix.get((row, col), ("Medium", "#FFD700"))