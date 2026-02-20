import json
import os

def search_mitre_for_actor(keyword):
    """Searches the MITRE dataset for attribution links."""
    path = "backend/data/mitre_attack.json"
    if not os.path.exists(path): return []
    
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    matches = []
    keyword = keyword.lower()
    
    for obj in data.get("objects", []):
        if obj.get("type") == "intrusion-set":
            name = obj.get("name", "").lower()
            aliases = [a.lower() for a in obj.get("aliases", [])]
            description = obj.get("description", "").lower()
            
            if keyword in name or keyword in description or any(keyword in a for a in aliases):
                matches.append({
                    "name": obj.get("name"),
                    "description": obj.get("description")[:200]
                })
    return matches