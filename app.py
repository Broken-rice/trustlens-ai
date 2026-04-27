# ===================================================
# TRUSTLENS AI - V6 PATCH
# Replace ONLY your existing risk_signals(text) function
# with the full function below
# ===================================================

def risk_signals(text):
    t = text.lower()
    score = 0
    reasons = []
    scam_type = "General Suspicious Message"

    # ---------------------------------------------------
    # OTP FRAUD
    # ---------------------------------------------------
    if "otp" in t:
        score += 30
        reasons.append("Requests OTP")
        scam_type = "OTP Fraud"

    # ---------------------------------------------------
    # BANK / ACCOUNT IMPERSONATION
    # ---------------------------------------------------
    bank_words = [
        "bank",
        "account suspended",
        "account blocked",
        "verify account",
        "secure your account",
        "account freeze",
        "permanent account freeze"
    ]

    for word in bank_words:
        if word in t:
            score += 22
            reasons.append(f"Account security phrase: {word}")
            scam_type = "Fake Bank Alert"

    # ---------------------------------------------------
    # PHISHING LANGUAGE
    # ---------------------------------------------------
    phishing_words = [
        "click now",
        "verify now",
        "reset password",
        "confirm identity",
        "login now",
        "sign in now"
    ]

    for word in phishing_words:
        if word in t:
            score += 20
            reasons.append(f"Phishing action phrase: {word}")
            scam_type = "Phishing Scam"

    # ---------------------------------------------------
    # JOB SCAMS
    # ---------------------------------------------------
    job_words = [
        "job",
        "work from home",
        "registration fee",
        "pay fee",
        "joining fee"
    ]

    for word in job_words:
        if word in t:
            score += 25
            reasons.append(f"Fake job phrase: {word}")
            scam_type = "Fake Job Offer"

    # ---------------------------------------------------
    # INVESTMENT FRAUD
    # ---------------------------------------------------
    invest_words = [
        "investment",
        "guaranteed return",
        "double your money",
        "daily profit",
        "risk free return"
    ]

    for word in invest_words:
        if word in t:
            score += 28
            reasons.append(f"Investment scam phrase: {word}")
            scam_type = "Investment Scam"

    # ---------------------------------------------------
    # PRIZE / LOTTERY BAIT
    # ---------------------------------------------------
    prize_words = [
        "winner",
        "claim prize",
        "reward",
        "lottery",
        "congratulations you won"
    ]

    for word in prize_words:
        if word in t:
            score += 20
            reasons.append(f"Prize bait phrase: {word}")
            scam_type = "Prize Scam"

    # ---------------------------------------------------
    # URGENCY / PRESSURE TACTICS
    # ---------------------------------------------------
    urgency_words = [
        "urgent",
        "immediately",
        "now",
        "15 mins",
        "within 15 mins",
        "respond now",
        "limited time",
        "act fast",
        "failure to respond"
    ]

    for word in urgency_words:
        if word in t:
            score += 15
            reasons.append(f"Urgency pressure: {word}")

    # ---------------------------------------------------
    # SECURITY SCARE TACTICS
    # ---------------------------------------------------
    security_words = [
        "unusual sign-in",
        "sign-in detected",
        "detected from",
        "security alert",
        "unauthorized access",
        "login attempt"
    ]

    for word in security_words:
        if word in t:
            score += 22
            reasons.append(f"Security scare phrase: {word}")
            scam_type = "Phishing Scam"

    # ---------------------------------------------------
    # LINKS (normal ascii)
    # ---------------------------------------------------
    links = extract_links(text)
    if links:
        score += 20
        reasons.append("Contains clickable link")

    # ---------------------------------------------------
    # UNICODE / SPOOFED CHARACTERS
    # catches ｈｔｔｐｓ：／／ etc
    # ---------------------------------------------------
    suspicious_unicode = False

    for char in text:
        if ord(char) > 127:
            suspicious_unicode = True
            break

    if suspicious_unicode:
        score += 25
        reasons.append("Contains disguised Unicode characters")

    # ---------------------------------------------------
    # BRAND IMPERSONATION + SECURITY MESSAGE
    # ---------------------------------------------------
    brands = [
        "paypal",
        "skrill",
        "google",
        "microsoft",
        "apple",
        "amazon",
        "bank"
    ]

    for brand in brands:
        if brand in t and (
            "alert" in t or
            "security" in t or
            "verify" in t or
            "freeze" in t
        ):
            score += 25
            reasons.append(f"Possible brand impersonation: {brand}")
            scam_type = "Phishing Scam"

    # ---------------------------------------------------
    # FINAL LIMIT
    # ---------------------------------------------------
    if score > 100:
        score = 100

    return score, reasons, scam_type
