import streamlit as st
import joblib
import re

# ----------------------------
# Load model, vectorizer, and whitelist
# ----------------------------
@st.cache_resource
def load_resources():
    model = joblib.load("phishing_model.pkl")
    vectorizer = joblib.load("vectorizer.pkl")
    with open("trusted_domains.txt", "r") as f:
        trusted_domains = [line.strip().lower() for line in f if line.strip()]
    return model, vectorizer, trusted_domains

model, vectorizer, TRUSTED_DOMAINS = load_resources()

def normalize_url(url):
    url = str(url).lower()
    url = re.sub(r'^https?://', '', url)
    url = re.sub(r'^www\.', '', url)
    return url

def check_url(url):
    normalized = normalize_url(url)
    domain = normalized.split('/')[0]

    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            return "LEGITIMATE", "Trusted domain match", None

    vec = vectorizer.transform([normalized])
    prediction = model.predict(vec)[0]
    prob = model.predict_proba(vec)[0][1]
    result = "PHISHING" if prediction == 1 else "LEGITIMATE"
    return result, "ML model prediction", prob

# ----------------------------
# Streamlit UI
# ----------------------------
st.set_page_config(page_title="Phishing URL Detector", page_icon="🔍")

st.title("🔍 Phishing URL Detector")
st.write("Enter a URL below to check if it's likely phishing or legitimate.")

url_input = st.text_input("URL to check:", placeholder="https://example.com")

if st.button("Check URL"):
    if url_input.strip() == "":
        st.warning("Please enter a URL.")
    else:
        result, method, prob = check_url(url_input)

        if result == "PHISHING":
            st.error(f"⚠️ **{result}**")
        else:
            st.success(f"✅ **{result}**")

        if prob is not None:
            st.write(f"Method: {method} — Phishing probability: {prob:.2%}")
        else:
            st.write(f"Method: {method}")

st.markdown("---")
st.caption("Note: This model has known limitations with some modern major websites not well-represented in training data. See project README for details.")