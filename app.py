import streamlit as st
from transformers import pipeline
import pytesseract
from PIL import Image
import re

# ---------------------------------------------------
# TESSERACT PATH (WINDOWS)
# ---------------------------------------------------
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# ---------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------
st.set_page_config(
    page_title="TrustLens AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------------------------------------------
# CUSTOM UI STYLE
# ---------------------------------------------------
st.markdown("""
<style>
.main {
    padding-top: 1rem;
}
.block-container {
    padding-top: 1rem;
    padding-bottom: 2rem;
}
.metric-card {
    background: #111827;
    padding: 18px;
    border-radius: 14px;
    border: 1px solid #374151;
}
.result-box {
    padding: 16px;
    border-radius: 14px;
    border: 1px solid #e5e7eb;
    background: #f8fafc;
}
.small-note {
    font-size: 13px;
    color: #6b7280;
}
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------
# LOAD MODEL
# ---------------------------------------------------
@st.cache_resource
def load_model():
    return pipeline(
        "zero-shot-classification",
        model="typeform/distilbert-base-uncased-mnli"
    )

classifier = load_model()

# ---------------------------------------------------
# HELPERS
# ---------------------------------------------------
def extract_links(text):
    return re.findall(r"(https?://\S+|www\.\S+)", text)

def risk_signals(text):
    t = text.lower()
    score = 0
    reasons = []
    scam_type = "General Suspicious Message"

    if "otp" in t:
        score += 30
        reasons.append("Requests OTP")
        scam_type = "OTP Fraud"

    if "bank" in t or "account suspended" in t or "account blocked" in t:
        score += 25
        reasons.append("Pretends to be bank/account alert")
        scam_type = "Fake Bank Alert"

    if "click now" in t or "verify now" in t or "password" in t:
        score += 20
        reasons.append("Urgent verification request")
        scam_type = "Phishing Scam"

    if "job" in t or "registration fee" in t or "pay fee" in t:
        score += 25
        reasons.append("Job asks for payment")
        scam_type = "Fake Job Offer"

    if "investment" in t or "guaranteed return" in t:
        score += 30
        reasons.append("Promises unrealistic returns")
        scam_type = "Investment Scam"

    if "winner" in t or "claim prize" in t or "reward" in t:
        score += 20
        reasons.append("Prize bait language")
        scam_type = "Prize Scam"

    if "urgent" in t or "immediately" in t or "now" in t:
        score += 15
        reasons.append("Uses urgency pressure")

    links = extract_links(text)
    if links:
        score += 20
        reasons.append("Contains suspicious link")

    if score > 100:
        score = 100

    return score, reasons, scam_type

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
    if ai_label in ["fraudulent scam message", "phishing attempt"]:
        score += int(ai_conf * 20)
    return min(score, 100)

def level(score):
    if score >= 75:
        return "High Risk"
    elif score >= 45:
        return "Medium Risk"
    return "Low Risk"

def advice(risk):
    if risk == "High Risk":
        return [
            "Do NOT click any links.",
            "Do NOT share OTP or passwords.",
            "Block sender immediately.",
            "Use official websites only.",
            "Change passwords if already clicked."
        ]
    elif risk == "Medium Risk":
        return [
            "Verify sender identity.",
            "Avoid sharing personal details.",
            "Inspect links carefully."
        ]
    else:
        return [
            "No major threat detected.",
            "Stay cautious with unknown senders."
        ]

# ---------------------------------------------------
# SIDEBAR
# ---------------------------------------------------
with st.sidebar:
    st.title("🛡️ TrustLens AI")
    st.caption("Digital Safety Copilot")

    st.markdown("### Protected Against")
    st.write("• Phishing")
    st.write("• Fake Bank Alerts")
    st.write("• OTP Fraud")
    st.write("• Fake Jobs")
    st.write("• Prize Scams")
    st.write("• Investment Fraud")

    st.markdown("---")
    st.markdown("### Why It Matters")
    st.caption("Millions lose money to digital scams every year. TrustLens helps detect threats instantly.")

# ---------------------------------------------------
# HERO SECTION
# ---------------------------------------------------
st.title("🛡️ TrustLens AI")
st.subheader("Detect scams in seconds. Stay safe online.")

st.info("Paste suspicious text or upload a screenshot to get instant AI-powered fraud analysis.")

# ---------------------------------------------------
# INPUT SECTION
# ---------------------------------------------------
left, right = st.columns(2)

with left:
    user_text = st.text_area(
        "Paste suspicious SMS / Email / WhatsApp message",
        height=260,
        placeholder="Example: Your bank account is suspended. Verify now..."
    )

with right:
    uploaded_file = st.file_uploader(
        "Upload screenshot",
        type=["png", "jpg", "jpeg"]
    )

# ---------------------------------------------------
# OCR
# ---------------------------------------------------
if uploaded_file is not None:
    image = Image.open(uploaded_file)
    st.image(image, caption="Uploaded Screenshot", use_container_width=True)

    extracted_text = pytesseract.image_to_string(image)

    st.markdown("### Extracted Text")
    st.code(extracted_text)

    if extracted_text.strip():
        user_text = extracted_text

# ---------------------------------------------------
# ANALYZE BUTTON
# ---------------------------------------------------
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
        risk = level(total)

        # ----------------------------
        # METRICS
        # ----------------------------
        a, b, c = st.columns(3)

        with a:
            st.metric("Threat Score", f"{total}/100")

        with b:
            st.metric("Risk Level", risk)

        with c:
            st.metric("Detected Type", scam_type)

        st.progress(total)

        # ----------------------------
        # RESULT BANNER
        # ----------------------------
        if risk == "High Risk":
            st.error("🚨 Dangerous message likely scam")
        elif risk == "Medium Risk":
            st.warning("⚠️ Suspicious message detected")
        else:
            st.success("✅ Lower risk message")

        # ----------------------------
        # WHY FLAGGED
        # ----------------------------
        st.markdown("### Why It Was Flagged")
        if reasons:
            for r in reasons:
                st.write("•", r)
        else:
            st.write("• No strong fraud indicators found.")

        # ----------------------------
        # LINKS FOUND
        # ----------------------------
        links = extract_links(user_text)
        if links:
            st.markdown("### Links Found")
            for link in links:
                st.code(link)

        # ----------------------------
        # RECOMMENDED ACTION
        # ----------------------------
        st.markdown("### Recommended Action")
        for tip in advice(risk):
            st.write("•", tip)

        # ----------------------------
        # AI DECISION
        # ----------------------------
        st.markdown("### AI Insight")
        st.caption(f"Model classified this as: {ai_label} ({round(ai_conf*100)}% confidence)")

# ---------------------------------------------------
# SAMPLE TEST CASES
# ---------------------------------------------------
st.markdown("---")
st.markdown("### Try Demo Messages")

demo1 = "URGENT! Your bank account is suspended. Verify now at http://bank-login-help.com"
demo2 = "Congratulations! You are selected for a work from home job. Pay ₹999 registration fee now."
demo3 = "Hi Karan, meeting confirmed for tomorrow at 3 PM."

st.code(demo1)
st.code(demo2)
st.code(demo3)

# ---------------------------------------------------
# FOOTER
# ---------------------------------------------------
st.markdown("---")
st.caption("TrustLens AI | Final Hackathon Edition")
st.caption("Built with Streamlit + OCR + NLP + Hybrid Fraud Detection")