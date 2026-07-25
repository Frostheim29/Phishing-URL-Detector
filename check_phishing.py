import joblib
import re

def normalize_url(url):
    url = str(url).lower()
    url = re.sub(r'^https?://', '', url)
    url = re.sub(r'^www\.', '', url)
    return url

# Load the already-trained model and vectorizer (instant, no retraining)
model = joblib.load("phishing_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# A small list of well-known, trusted domains
TRUSTED_DOMAINS = [
    "google.com", "wikipedia.org", "reddit.com", "github.com",
    "youtube.com", "facebook.com", "twitter.com", "linkedin.com",
    "microsoft.com", "apple.com", "amazon.com", "stanford.edu",
    "mit.edu", "wikipedia.com"
]

def check_url(url):
    normalized = normalize_url(url)
    domain = normalized.split('/')[0]
    
    # Check trusted domains first
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            print(f"\n{url}\n--> LEGITIMATE (trusted domain match)")
            return
    
    # Otherwise, use the ML model
    vec = vectorizer.transform([normalized])
    prediction = model.predict(vec)[0]
    prob = model.predict_proba(vec)[0][1]
    result = "PHISHING" if prediction == 1 else "LEGITIMATE"
    print(f"\n{url}\n--> {result} (phishing probability: {prob:.2%})")

# ----------------------------
# Interactive loop - user types URLs directly
# ----------------------------
print("Phishing URL Detector")
print("Type a URL to check it, or 'quit' to exit.")

while True:
    user_input = input("\nEnter a URL: ").strip()
    if user_input.lower() == "quit":
        break
    check_url(user_input)