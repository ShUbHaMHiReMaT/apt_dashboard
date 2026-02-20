import json
import os

def search_mitre_for_actor(keyword: str):
    # Ensure this path is correct for your local setup
    json_path = os.path.join("backend", "data", "mitre_attack.json")
    if not os.path.exists(json_path):
        return []

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    keyword = keyword.lower()
    matches = []

    for obj in data.get("objects", []):
        if obj.get("type") == "intrusion-set":
            name = obj.get("name", "").lower()
            desc = obj.get("description", "").lower()
            aliases = [a.lower() for a in obj.get("aliases", [])]

            if keyword in name or keyword in desc or any(keyword in a for a in aliases):
                matches.append({
                    "name": obj.get("name"),
                    "aliases": obj.get("aliases", []),
                    "description": obj.get("description", "")[:300]
                })
    return matches