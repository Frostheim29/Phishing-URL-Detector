import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report

# ----------------------------
# 1. Load the real dataset
# ----------------------------
df = pd.read_csv("phishing.csv")

print("Shape of dataset:", df.shape)
print("Columns:", df.columns.tolist())
print("Class value counts:\n", df["class"].value_counts())

# ----------------------------
# 2. Prepare features and target
# ----------------------------
X = df.drop(columns=["Index", "class"])
y = df["class"]

# ----------------------------
# 3. Train/test split
# ----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ----------------------------
# 4. Train the model
# ----------------------------
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

# ----------------------------
# 5. Evaluate
# ----------------------------
y_pred = model.predict(X_test)
print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))