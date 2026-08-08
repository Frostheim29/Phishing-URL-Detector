import joblib
import re
import csv
from datetime import datetime

def normalize_url(url):
    url = str(url).lower()
    url = re.sub(r'^https?://', '', url)
    url = re.sub(r'^www\.', '', url)
    return url

# Load the already-trained model and vectorizer (instant, no retraining)
model = joblib.load("phishing_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# Trusted domains
def load_trusted_domains(filepath="trusted_domains.txt"):
    with open(filepath, "r") as f:
        domains = [line.strip().lower() for line in f if line.strip()]
    return domains

TRUSTED_DOMAINS = load_trusted_domains()

def check_url(url):
    normalized = normalize_url(url)
    domain = normalized.split('/')[0]

    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            print(f"\n{url}\n--> LEGITIMATE (trusted domain match)")
            log_result(url, "LEGITIMATE", "trusted domain match")
            return

    vec = vectorizer.transform([normalized])
    prediction = model.predict(vec)[0]
    prob = model.predict_proba(vec)[0][1]
    result = "PHISHING" if prediction == 1 else "LEGITIMATE"
    print(f"\n{url}\n--> {result} (phishing probability: {prob:.2%})")
    log_result(url, result, f"{prob:.2%}")

def check_urls_from_file(filepath):
    with open(filepath, "r") as f:
        urls = [line.strip() for line in f if line.strip()]
    
    print(f"\nChecking {len(urls)} URLs from {filepath}...\n")
    for url in urls:
        check_url(url)
    print(f"\nDone checking {len(urls)} URLs.")

LOG_FILE = "check_history.csv"

def log_result(url, result, prob_or_note):
    file_exists = False
    try:
        with open(LOG_FILE, "r"):
            file_exists = True
    except FileNotFoundError:
        file_exists = False

    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp", "url", "result", "detail"])
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        writer.writerow([timestamp, url, result, prob_or_note])

# ----------------------------
# Interactive loop - user types URLs directly
# ----------------------------
print("Phishing URL Detector")
print("1. Check a single URL")
print("2. Check multiple URLs from a file")
mode = input("Choose an option (1 or 2): ").strip()

if mode == "2":
    filepath = input("Enter the filename (e.g. urls_to_check.txt): ").strip()
    check_urls_from_file(filepath)
else:
    print("\nType a URL to check it, or 'quit' to exit.\n")
    while True:
        user_input = input("Enter a URL: ").strip()
        if user_input.lower() == "quit":
            break
        check_url(user_input)
