import json
import os
from backend.mitre_lookup import search_mitre_for_actor

def get_attribution(ioc, vt_data):
    """
    Performs back-tracing from an IOC to an APT group.
    Pivots from VT engine detections and tags to MITRE group aliases.
    """
    # 1. Direct Tag Check (Highest Confidence)
    attributes = vt_data.get("data", {}).get("attributes", {})
    tags = attributes.get("tags", [])
    
    # Common APT naming patterns
    for tag in tags:
        tag_lower = tag.lower()
        if any(prefix in tag_lower for prefix in ["apt", "lazarus", "fancy", "bear", "panda"]):
            return f"DIRECT ATTRIBUTION: {tag.upper()}"

    # 2. MITRE Database Pivot (Back-tracing via Actor Aliases)
    # We check if the IOC appears in descriptions or associated threat actor reports
    mitre_matches = search_mitre_for_actor(ioc)
    if mitre_matches:
        return f"MITRE LINK: {mitre_matches[0]['name'].upper()}"

    # 3. Heuristic Attribution (Contextual)
    country = attributes.get("country", "Unknown")
    if attributes.get("as_owner", "").lower().startswith("hosting"):
        return "INFRASTRUCTURE: BULLETPROOF HOSTING (Likely APT Proxy)"

    return "UNCATEGORIZED: POTENTIAL TARGETED ACTIVITY"

def calculate_risk_matrix(vt_malicious, ipqs_score, proxy, vpn):
    """Implementing the 5x5 Matrix (Rows A-E, Cols 1-5)"""
    # Row Calculation (Threat Confidence)
    threat_points = 0
    if vt_malicious > 20: threat_points += 15
    elif vt_malicious >= 6: threat_points += 9  # Matching your example: Score 6 = High
    
    if proxy: threat_points += 3
    if vpn: threat_points += 2

    row = "A" if threat_points == 0 else "B" if threat_points <= 3 else "C" if threat_points <= 9 else "D" if threat_points <= 15 else "E"

    # Column Calculation (Reputation Score)
    col = 1 if ipqs_score <= 20 else 2 if ipqs_score <= 40 else 3 if ipqs_score <= 60 else 4 if ipqs_score <= 80 else 5

    matrix = {
        ("A",1):"Very Low", ("A",2):"Very Low", ("A",3):"Very Low", ("A",4):"Low", ("A",5):"Low",
        ("B",1):"Very Low", ("B",2):"Very Low", ("B",3):"Low", ("B",4):"Medium", ("B",5):"Medium",
        ("C",1):"Low", ("C",2):"Low", ("C",3):"Medium", ("C",4):"High", ("C",5):"High",
        ("D",1):"Medium", ("D",2):"Medium", ("D",3):"High", ("D",4):"Very High", ("D",5):"Very High",
        ("E",1):"High", ("E",2):"High", ("E",3):"Very High", ("E",4):"Very High", ("E",5):"Very High",
    }
    
    label = matrix.get((row, col), "Medium")
    
    # Map label to color
    colors = {"Very Low": "#008000", "Low": "#008000", "Medium": "#FFD700", "High": "#FF8C00", "Very High": "#FF0000"}
    return label, colors.get(label, "#71717a")