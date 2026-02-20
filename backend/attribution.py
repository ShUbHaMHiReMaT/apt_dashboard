import os
import json
from backend.mitre_lookup import search_mitre_for_actor

def get_attribution(ioc, vt_data):
    """
    Reverse traces an IOC to an APT group using VT tags or MITRE pivot.
    """
    # 1. Check VirusTotal tags for known APT labels
    data = vt_data.get("data", {})
    attributes = data[0].get("attributes", {}) if isinstance(data, list) and data else data.get("attributes", {})
    tags = attributes.get("tags", [])
    
    for tag in tags:
        tag_lower = tag.lower()
        if any(term in tag_lower for term in ["apt", "group", "lazarus", "fancy", "bear", "panda"]):
            return f"DIRECT ATTRIBUTION: {tag.upper()}"

    # 2. Back-trace via MITRE (Looking for the IOC in threat actor descriptions)
    mitre_matches = search_mitre_for_actor(ioc)
    if mitre_matches:
        return f"MITRE LINKED: {mitre_matches[0]['name'].upper()}"
    
    return "No Known APT Association (Generic Threat)"

def calculate_risk_matrix(vt_malicious, ipqs_score, proxy, vpn):
    """Calculates risk level based on the 5x5 matrix logic."""
    # Threat Confidence (Row A-E)
    threat_points = 0
    if vt_malicious > 20: threat_points += 10
    elif vt_malicious > 5: threat_points += 6
    if proxy: threat_points += 3
    if vpn: threat_points += 2

    if threat_points == 0: row = "A"
    elif threat_points <= 3: row = "B"
    elif threat_points <= 9: row = "C"
    elif threat_points <= 15: row = "D"
    else: row = "E"

    # Reputation Score (Column 1-5)
    if ipqs_score <= 20: col = 1
    elif ipqs_score <= 40: col = 2
    elif ipqs_score <= 60: col = 3
    elif ipqs_score <= 80: col = 4
    else: col = 5

    matrix = {
        ("A",1):("Very Low","#008000"), ("A",2):("Very Low","#008000"), ("A",3):("Very Low","#008000"), ("A",4):("Low","#008000"), ("A",5):("Low","#008000"),
        ("B",1):("Very Low","#008000"), ("B",2):("Very Low","#008000"), ("B",3):("Low","#008000"), ("B",4):("Medium","#FFD700"), ("B",5):("Medium","#FFD700"),
        ("C",1):("Low","#008000"), ("C",2):("Low","#008000"), ("C",3):("Medium","#FFD700"), ("C",4):("High","#FF8C00"), ("C",5):("High","#FF8C00"),
        ("D",1):("Medium","#FFD700"), ("D",2):("Medium","#FFD700"), ("D",3):("High","#FF8C00"), ("D",4):("Very High","#FF0000"), ("D",5):("Very High","#FF0000"),
        ("E",1):("High","#FF8C00"), ("E",2):("High","#FF8C00"), ("E",3):("Very High","#FF0000"), ("E",4):("Very High","#FF0000"), ("E",5):("Very High","#FF0000"),
    }
    return matrix.get((row, col), ("Medium", "#FFD700"))