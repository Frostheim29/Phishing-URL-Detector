import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
import joblib
import re

def normalize_url(url):
    url = str(url).lower()
    url = re.sub(r'^https?://', '', url)  
    url = re.sub(r'www\.', '', url)
    return url

# ----------------------------
# 1. Load dataset and filter to benign vs phishing only
# ----------------------------
df = pd.read_csv("malicious_phish.csv")
df = df[df["type"].isin(["benign", "phishing"])].copy()
df["label"] = df["type"].apply(lambda x: 1 if x == "phishing" else 0)

print("Total rows after filtering:", len(df))
print(df["label"].value_counts())
print("\n--- Sample of actual benign URLs in the dataset ---")
print(df[df["label"] == 0]["url"].sample(10, random_state=1).to_string())
print("\n--- Sample of actual phishing URLs in the dataset ---")
print(df[df["label"] == 1]["url"].sample(10, random_state=1).to_string())

X = df["url"].astype(str).apply(normalize_url)
y = df["label"]

# ----------------------------
# 2. Train/test split
# ----------------------------
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# ----------------------------
# 3. Convert URLs into character n-gram features
# ----------------------------
print("Vectorizing URLs using character n-grams...")
vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5), max_features=5000)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# ----------------------------
# 4. Train the model
# ----------------------------
print("Training model...")
model = LogisticRegression(max_iter=1000, class_weight='balanced')
model.fit(X_train_vec, y_train)

# ----------------------------
# 5. Evaluate
# ----------------------------
y_pred = model.predict(X_test_vec)
print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# ----------------------------
# 6. Save the model and vectorizer
# ----------------------------
joblib.dump(model, "phishing_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")
print("\nModel and vectorizer saved")

# ----------------------------
# 7. Try it on your own URLs!
# ----------------------------
def check_url(url):
    vec = vectorizer.transform([normalize_url(url)])
    prediction = model.predict(vec)[0]
    prob = model.predict_proba(vec)[0][1]
    result = "PHISHING" if prediction == 1 else "LEGITIMATE"
    print(f"{url} --> {result} (phishing probability: {prob:.2%})")

print("\n--- Testing on new URLs ---")
check_url("http://free-money-claim-now.tk")
check_url("https://www.reddit.com/r/technology/comments/xyz123/some_post_title")
check_url("http://paypal-secure-login-verify.xyz/account")
check_url("https://en.wikipedia.org/wiki/Machine_learning")
check_url("https://www.google.com/search?q=python+tutorial")
check_url("http://192.168.1.1/verify-account-now")