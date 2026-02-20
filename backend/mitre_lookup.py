import json

with open("backend/data/mitre_attack.json", "r", encoding="utf-8") as f:
    MITRE_DATA = json.load(f)


def search_mitre_for_actor(keyword: str):

    keyword = keyword.lower()
    matches = []

    for obj in MITRE_DATA["objects"]:
        if obj.get("type") == "intrusion-set":
            name = obj.get("name", "").lower()
            desc = obj.get("description", "").lower()

            if keyword in name or keyword in desc:
                matches.append({
                    "name": obj.get("name"),
                    "aliases": obj.get("aliases", []),
                    "description": obj.get("description", "")[:300]
                })

    return matches