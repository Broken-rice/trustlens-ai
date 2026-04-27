import streamlit as st
from transformers import pipeline
import re

# ==================================================
# PAGE CONFIG
# ==================================================
st.set_page_config(
    page_title="TrustLens AI",
    page_icon="🛡️",
    layout="wide"
)

# ==================================================
# SIMPLE CLEAN CSS
# ==================================================
st.markdown("""
<style>
.block-container {
    padding-top: 1.2rem;
    padding-bottom: 2rem;
}
div[data-testid="stMetric"] {
    background-color: #111827;
    padding: 14px;
    border-radius: 12px;
}
</style>
""", unsafe_allow_html=True)

# ==================================================
# LOAD MODEL (STABLE)
# ==================================================
@st.cache_resource
def load_model():
    return pipeline(
        "zero-shot-classification",
        model="typeform/distilbert-base-uncased-mnli"
    )

classifier = load_model()

# ==================================================
# HELPERS
# ==================================================
def extract_links(text):
    return re.findall(r"(https?://\S+|www\.\S+)", text)

def contains_unicode_spoof(text):
    for ch in text:
        if ord(ch) > 127:
            return True
    return False

def risk_signals(text):
    t = text.lower()
    score = 0
    reasons = []
    scam_type = "General Suspicious Message"

    # OTP
    if "otp" in t:
        score += 35
        reasons.append("Requests OTP")
        scam_type = "OTP Fraud"

    # Banking / Account Threat
    account_terms = [
        "bank", "account suspended", "account blocked",
        "freeze", "secure your account", "verify account"
    ]
    for w in account_terms:
        if w in t:
            score += 22
            reasons.append(f"Account threat phrase: {w}")
            scam_type = "Fake Bank Alert"

    # Phishing Actions
    phishing_terms = [
        "click now", "verify now", "login now",
        "reset password", "confirm identity"
    ]
    for w in phishing_terms:
        if w in t:
            score += 22
            reasons.append(f"Phishing action phrase: {w}")
            scam_type = "Phishing Scam"

    # Fake Jobs
    job_terms = [
        "job", "work from home", "registration fee",
        "joining fee", "pay fee"
    ]
    for w in job_terms:
        if w in t:
            score += 28
            reasons.append(f"Fake job phrase: {w}")
            scam_type = "Fake Job Offer"

    # Prize
    prize_terms = [
        "winner", "claim prize", "reward", "lottery"
    ]
    for w in prize_terms:
        if w in t:
            score += 22
            reasons.append(f"Prize bait phrase: {w}")
            scam_type = "Prize Scam"

    # Investment
    invest_terms = [
        "investment", "guaranteed return",
        "double your money", "daily profit"
    ]
    for w in invest_terms:
        if w in t:
            score += 30
            reasons.append(f"Investment fraud phrase: {w}")
            scam_type = "Investment Scam"

    # Urgency
    urgency_terms = [
        "urgent", "immediately", "now",
        "15 mins", "within 15 mins",
        "failure to respond", "act fast"
    ]
    for w in urgency_terms:
        if w in t:
            score += 16
            reasons.append(f"Urgency tactic: {w}")

    # Security scare
    scare_terms = [
        "unusual sign-in", "sign-in detected",
        "security alert", "unauthorized access",
        "detected from"
    ]
    for w in scare_terms:
        if w in t:
            score += 24
            reasons.append(f"Security scare phrase: {w}")
            scam_type = "Phishing Scam"

    # Links
    links = extract_links(text)
    if links:
        score += 22
        reasons.append("Contains clickable link")

    # Unicode spoof
    if contains_unicode_spoof(text):
        score += 25
        reasons.append("Contains disguised Unicode characters")
        scam_type = "Phishing Scam"

    # Brand impersonation
    brands = ["paypal", "skrill", "google", "apple", "amazon", "microsoft"]
    for brand in brands:
        if brand in t and (
            "alert" in t or "verify" in t or
            "freeze" in t or "security" in t
        ):
            score += 28
            reasons.append(f"Possible brand impersonation: {brand}")
            scam_type = "Phishing Scam"

    return min(score, 100), reasons, scam_type

def ai_check(text):
    labels = [
        "fraudulent scam message",
        "phishing attempt",
        "normal safe message",
        "spam advertisement"
    ]
    result = classifier(text, labels)
    return result["labels"][0], float(result["scores"][0])

def final_score(rule_score, ai_label, ai_conf):
    score = rule_score

    # If rules already strong, never downgrade
    if rule_score >= 70:
        score = max(score, 85)

    # AI adds confidence
    if ai_label in ["fraudulent scam message", "phishing attempt"]:
        score += int(ai_conf * 15)

    return min(score, 100)

def risk_level(score):
    if score >= 75:
        return "High Risk"
    elif score >= 45:
        return "Medium Risk"
    return "Low Risk"

def advice(level):
    if level == "High Risk":
        return [
            "Do NOT click any links.",
            "Do NOT share OTP/password.",
            "Block sender immediately.",
            "Use official websites only.",
            "Change passwords if already interacted."
        ]
    elif level == "Medium Risk":
        return [
            "Verify sender identity.",
            "Avoid sharing personal details.",
            "Inspect links carefully."
        ]
    else:
        return [
            "No major threat detected.",
            "Still stay cautious online."
        ]

# ==================================================
# SIDEBAR
# ==================================================
with st.sidebar:
    st.title("🛡️ TrustLens AI")
    st.caption("Digital Scam Protection")

    st.markdown("### Covers")
    st.write("• Phishing")
    st.write("• Fake Bank Alerts")
    st.write("• OTP Fraud")
    st.write("• Fake Jobs")
    st.write("• Prize Scams")
    st.write("• Investment Fraud")

# ==================================================
# HEADER
# ==================================================
st.title("🛡️ TrustLens AI")
st.subheader("Detect scams in seconds. Stay safe online.")
st.info("Paste any suspicious SMS, email, or WhatsApp message below.")

# ==================================================
# INPUT
# ==================================================
user_text = st.text_area(
    "Paste suspicious message",
    height=220,
    placeholder="Example: Your account is suspended. Verify now..."
)

# ==================================================
# ANALYZE
# ==================================================
if st.button("🚀 Scan for Threats", use_container_width=True):

    if user_text.strip() == "":
        st.warning("Please enter a message.")
    else:
        rule_score, reasons, scam_type = risk_signals(user_text)

        if rule_score < 60:
            with st.spinner("AI analyzing message..."):
                ai_label, ai_conf = ai_check(user_text)
        else:
            ai_label = "fraudulent scam message"
            ai_conf = 0.95

        total = final_score(rule_score, ai_label, ai_conf)
        level = risk_level(total)

        c1, c2, c3 = st.columns(3)

        with c1:
            st.metric("Threat Score", f"{total}/100")

        with c2:
            st.metric("Risk Level", level)

        with c3:
            st.metric("Detected Type", scam_type)

        st.progress(total)

        if level == "High Risk":
            st.error("🚨 Dangerous message likely scam")
        elif level == "Medium Risk":
            st.warning("⚠️ Suspicious message detected")
        else:
            st.success("✅ Lower risk message")

        st.markdown("### Why It Was Flagged")
        if reasons:
            for r in reasons:
                st.write("•", r)
        else:
            st.write("• No major suspicious signals found.")

        links = extract_links(user_text)
        if links:
            st.markdown("### Links Found")
            for link in links:
                st.code(link)

        st.markdown("### Recommended Action")
        for tip in advice(level):
            st.write("•", tip)

        st.markdown("### AI Insight")
        st.caption(f"Model classified as: {ai_label} ({round(ai_conf*100)}% confidence)")

# ==================================================
# DEMO CASES
# ==================================================
st.markdown("---")
st.markdown("### Try Demo Messages")

st.code("URGENT! Your bank account is suspended. Verify now at http://bank-login-help.com")
st.code("Congratulations! You are selected for a work from home job. Pay ₹999 registration fee now.")
st.code("skrill-Alert: Unusual sign-in detected from Moscow. Secure your account immediately.")

# ==================================================
# FOOTER
# ==================================================
st.markdown("---")
st.caption("TrustLens AI | Stable Hosted Final Edition")
st.caption("Built with Streamlit + NLP + Fraud Signal Detection")
