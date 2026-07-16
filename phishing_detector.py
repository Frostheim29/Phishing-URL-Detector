import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from urllib.parse import urlparse

# ----------------------------
# 1. Sample dataset (URL, label)
# label: 1 = phishing, 0 = legitimate
# ----------------------------
data={
    "url":[
       "http://192.168.1.1/login",
        "http://secure-bank-update.com/verify",
        "https://www.google.com",
        "https://www.github.com",
        "http://paypal-account-verify.tk/login",
        "https://www.wikipedia.org",
        "http://free-gift-cardsclaim.info",
        "https://www.amazon.com",
        "http://update-your-account-now.xyz",
        "https://www.microsoft.com",
        "http://bit.ly/3xyzABC",
        "https://www.linkedin.com",
        "http://login-verify-secure.com/account",
        "https://www.python.org",
        "http://click-here-to-claim-prize.net" 
    ],
    "label":[1,1,0,0,1,0,1,0,1,0,1,0,1,0,1]
}

df=pd.DataFrame(data)

# ----------------------------
# 2. Feature extraction
# ----------------------------
def extract_features(url):
    parsed = urlparse(url)
    return {
        "url_length": len(url),
        "has_ip": 1 if any(char.isdigit() for char in parsed.netloc.split('.')[0]) else 0,
        "has_at_symbol": 1 if "@" in url else 0,
        "num_dots": url.count('.'),
        "has_https": 1 if url.startswith("https") else 0,
        "has_hyphen": 1 if "-" in parsed.netloc else 0,
        "num_digits": sum(char.isdigit() for char in url),
    }

features = df['url'].apply(extract_features).apply(pd.Series)
X=features
y=df['label']

# ----------------------------
# 3. Train/test split
# ----------------------------
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# ----------------------------
# 4. Train the model
# ----------------------------
model = LogisticRegression()
model.fit(X_train, y_train)

# ----------------------------
# 5. Evaluate
# ----------------------------
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# ----------------------------
# 6. Test on new URLs
# ----------------------------
test_urls = [
    "http://free-money-claim-now.tk",
    "https://www.reddit.com",
    "http://192.168.0.5/secure-login"
]

for url in test_urls:
    feat=pd.DataFrame([extract_features(url)])
    prediction=model.predict(feat)[0]
    result="PHISHING" if prediction==1 else "LEGITIMATE"
    print(f"{url} --> {result}")
    