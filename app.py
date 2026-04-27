import streamlit as st
from transformers import pipeline
import easyocr
from PIL import Image
import numpy as np
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
# STYLE
# ==================================================
st.markdown("""
<style>
.block-container {
    padding-top: 1rem;
    padding-bottom: 2rem;
}
div[data-testid="stMetric"] {
    background: #111827;
    padding: 14px;
    border-radius: 12px;
}
</style>
""", unsafe_allow_html=True)

# ==================================================
# LOAD MODELS
# ==================================================
@st.cache_resource
def load_model():
    return pipeline(
        "zero-shot-classification",
        model="typeform/distilbert-base-uncased-mnli"
    )

@st.cache_resource
def load_reader():
    return easyocr.Reader(['en'], gpu=False)

classifier = load_model()
reader = load_reader()

# ==================================================
# HELPERS
# ==================================================
def extract_links(text):
    return re.findall(r"(https?://\S+|www\.\S+)", text)

def contains_unicode_spoof(text):
    return any(ord(ch) > 127 for ch in text)

def risk_signals(text):
    t = text.lower()
    score = 0
    reasons = []
    scam_type = "General Suspicious Message"

    if "otp" in t:
        score += 35
        reasons.append("Requests OTP")
        scam_type = "OTP Fraud"

    account_terms = [
        "bank", "account suspended", "account blocked",
        "freeze", "secure your account", "verify account"
    ]
    for w in account_terms:
        if w in t:
            score += 22
            reasons.append(f"Account threat phrase: {w}")
            scam_type = "Fake Bank Alert"

    phishing_terms = [
        "click now", "verify now", "login now",
        "reset password", "confirm identity"
    ]
    for w in phishing_terms:
        if w in t:
            score += 22
            reasons.append(f"Phishing action phrase: {w}")
            scam_type = "Phishing Scam"

    job_terms = [
        "job", "work from home", "registration fee",
        "joining fee", "pay fee"
    ]
    for w in job_terms:
        if w in t:
            score += 28
            reasons.append(f"Fake job phrase: {w}")
            scam_type = "Fake Job Offer"

    prize_terms = ["winner", "claim prize", "reward", "lottery"]
    for w in prize_terms:
        if w in t:
            score += 22
            reasons.append(f"Prize bait phrase: {w}")
            scam_type = "Prize Scam"

    invest_terms = [
        "investment", "guaranteed return",
        "double your money", "daily profit"
    ]
    for w in invest_terms:
        if w in t:
            score += 30
            reasons.append(f"Investment fraud phrase: {w}")
            scam_type = "Investment Scam"

    urgency_terms = [
        "urgent", "immediately", "now",
        "15 mins", "within 15 mins",
        "failure to respond", "act fast"
    ]
    for w in urgency_terms:
        if w in t:
            score += 16
            reasons.append(f"Urgency tactic: {w}")

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

    links = extract_links(text)
    if links:
        score += 22
        reasons.append("Contains clickable link")

    if contains_unicode_spoof(text):
        score += 25
        reasons.append("Contains disguised Unicode characters")
        scam_type = "Phishing Scam"

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

    if rule_score >= 70:
        score = max(score, 85)

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
st.info("Paste suspicious text or upload screenshot below.")

# ==================================================
# INPUT SECTION
# ==================================================
left, right = st.columns(2)

with left:
    user_text = st.text_area(
        "Paste suspicious SMS / Email / WhatsApp message",
        height=250
    )

with right:
    uploaded_file = st.file_uploader(
        "Upload Screenshot",
        type=["png", "jpg", "jpeg"]
    )

# ==================================================
# OCR
# ==================================================
if uploaded_file is not None:
    image = Image.open(uploaded_file)
    st.image(image, caption="Uploaded Screenshot", use_container_width=True)

    img_array = np.array(image)

    with st.spinner("Reading text from image..."):
        results = reader.readtext(img_array)

    extracted_text = " ".join([item[1] for item in results])

    st.markdown("### Extracted Text")
    st.code(extracted_text)

    if extracted_text.strip():
        user_text = extracted_text

# ==================================================
# ANALYZE
# ==================================================
if st.button("🚀 Scan for Threats", use_container_width=True):

    if user_text.strip() == "":
        st.warning("Please enter text or upload screenshot.")
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

        a, b, c = st.columns(3)

        with a:
            st.metric("Threat Score", f"{total}/100")

        with b:
            st.metric("Risk Level", level)

        with c:
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
st.caption("TrustLens AI | Final OCR Stable Edition")
st.caption("Built with Streamlit + EasyOCR + NLP + Fraud Detection")
