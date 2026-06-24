def calculate_risk_boost(counts: dict, z_score: float) -> int:
    """Calculate the combined multi-vector risk boost based on counts and frequency z-score."""
    risk_boost = 0

    # 1. Impatto Frequenza (Allows)
    if counts.get("user_allows", 0.0) >= 200:
        risk_boost += 15
    elif counts.get("user_allows", 0.0) >= 100:
        risk_boost += 8

    # 2. Impatto Richieste Negate (Denies)
    if counts.get("user_denies", 0.0) >= 10:
        risk_boost += 30
    elif counts.get("user_denies", 0.0) >= 5:
        risk_boost += 15

    # 3. Impatto Snort Alerts (Intrusione L7)
    if counts.get("snort_alerts", 0.0) >= 5:
        risk_boost += 60
    elif counts.get("snort_alerts", 0.0) >= 1:
        risk_boost += 30

    # 4. Impatto nftables Firewall Drops (Scansione Rete)
    if counts.get("nftables_drops", 0.0) >= 50:
        risk_boost += 20
    elif counts.get("nftables_drops", 0.0) >= 10:
        risk_boost += 10

    # 5. Impatto MongoDB Login Failures (Brute Force)
    if counts.get("mongo_failures", 0.0) >= 10:
        risk_boost += 40
    elif counts.get("mongo_failures", 0.0) >= 3:
        risk_boost += 20

    # 6. Impatto Anomaly Detection (Z-Score della frequenza query)
    if z_score >= 3.0:
        risk_boost += 40
    elif z_score >= 2.0:
        risk_boost += 20

    # Cap del risk boost a un massimo di 100
    return min(risk_boost, 100)
