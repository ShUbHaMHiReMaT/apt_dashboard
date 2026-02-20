from backend.mitre_lookup import search_mitre_for_actor


def calculate_ip_matrix_score(vt_data, ipqs_data):

    threat_score = 0
    reputation = 50  # default neutral

    # ---------------- VT malicious votes ----------------
    votes = (
        vt_data.get("data", [{}])[0]
        .get("attributes", {})
        .get("total_votes", {})
        .get("malicious", 0)
    )

    if votes > 30:
        threat_score += 5
    elif votes > 10:
        threat_score += 3

    # use reputation if present
    rep = (
        vt_data.get("data", [{}])[0]
        .get("attributes", {})
        .get("reputation")
    )
    if rep is not None:
        reputation = max(0, min(100, rep + 50))  # normalize

    # ---------------- IPQS signals ----------------
    if ipqs_data:
        if ipqs_data.get("proxy"):
            threat_score += 3
        if ipqs_data.get("vpn"):
            threat_score += 2

    return threat_score, reputation


def matrix_label(threat_score, reputation):

    # row (threat confidence)
    if threat_score == 0:
        row = "A"
    elif threat_score <= 3:
        row = "B"
    elif threat_score <= 9:
        row = "C"
    elif threat_score <= 15:
        row = "D"
    else:
        row = "E"

    # column (IP score)
    if reputation <= 20:
        col = 1
    elif reputation <= 40:
        col = 2
    elif reputation <= 60:
        col = 3
    elif reputation <= 80:
        col = 4
    else:
        col = 5

    matrix = {
        ("A",1):"Very Low",("A",2):"Very Low",("A",3):"Very Low",("A",4):"Low",("A",5):"Low",
        ("B",1):"Very Low",("B",2):"Very Low",("B",3):"Low",("B",4):"Medium",("B",5):"Medium",
        ("C",1):"Low",("C",2):"Low",("C",3):"Medium",("C",4):"High",("C",5):"High",
        ("D",1):"Medium",("D",2):"Medium",("D",3):"High",("D",4):"Very High",("D",5):"Very High",
        ("E",1):"High",("E",2):"High",("E",3):"Very High",("E",4):"Very High",("E",5):"Very High",
    }

    return matrix[(row,col)]


def analyze_results(ioc, results):

    vt = results.get("virustotal", {})
    ipqs = results.get("ipqs", {})

    # ---------------------------
    # Extract VT data
    # ---------------------------
    vt_attr = vt.get("data", [{}])[0].get("attributes", {})

    vt_malicious = vt_attr.get("total_votes", {}).get("malicious", 0)
    country = vt_attr.get("country")

    # ---------------------------
    # Extract IPQS data
    # ---------------------------
    fraud_score = ipqs.get("fraud_score", 0)
    vpn = ipqs.get("vpn")
    proxy = ipqs.get("proxy")

    # ---------------------------
    # Convert signals to threat score (matrix row)
    # ---------------------------
    threat_score = 0

    if vt_malicious > 20:
        threat_score += 5
    elif vt_malicious > 5:
        threat_score += 3

    if fraud_score > 85:
        threat_score += 7
    elif fraud_score > 60:
        threat_score += 5
    elif fraud_score > 40:
        threat_score += 3

    if proxy:
        threat_score += 3

    if vpn:
        threat_score += 2

    # ---------------------------
    # Map threat score to row
    # ---------------------------
    if threat_score == 0:
        row = "A"
    elif threat_score <= 3:
        row = "B"
    elif threat_score <= 9:
        row = "C"
    elif threat_score <= 15:
        row = "D"
    else:
        row = "E"

    # ---------------------------
    # Convert IP risk to column
    # Use fraud score as reputation
    # ---------------------------
    reputation = fraud_score

    if reputation <= 20:
        col = 1
    elif reputation <= 40:
        col = 2
    elif reputation <= 60:
        col = 3
    elif reputation <= 80:
        col = 4
    else:
        col = 5

    # ---------------------------
    # Matrix lookup (your image logic)
    # ---------------------------
    matrix = {
        ("A",1):"Very Low",("A",2):"Very Low",("A",3):"Very Low",("A",4):"Low",("A",5):"Low",
        ("B",1):"Very Low",("B",2):"Very Low",("B",3):"Low",("B",4):"Medium",("B",5):"Medium",
        ("C",1):"Low",("C",2):"Low",("C",3):"Medium",("C",4):"High",("C",5):"High",
        ("D",1):"Medium",("D",2):"Medium",("D",3):"High",("D",4):"Very High",("D",5):"Very High",
        ("E",1):"High",("E",2):"High",("E",3):"Very High",("E",4):"Very High",("E",5):"Very High",
    }

    risk_level = matrix[(row,col)]

    # ---------------------------
    # Final output format (your requirement)
    # ---------------------------
    return {
        "ip": ioc,
        "country": country,
        "vt_malicious_score": vt_malicious,
        "ipqs_fraud_score": fraud_score,
        "proxy": proxy,
        "vpn": vpn,
        "risk_level": risk_level
    }