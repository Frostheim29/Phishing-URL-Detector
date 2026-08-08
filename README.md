# Phishing URL Detector
A machine learning model that classifies URLs as **phishing** or **legitimate**, trained on 500K+ real-world URLs using character-level text patterns and Logistic Regression, with a trusted-domain whitelist layer for known safe sites.

## Overview
Phishing websites trick users into revealing sensitive information by mimicking legitimate sites. This project analyzes the raw text of a URL, using overlapping 3-5 character sequences to learn patterns that distinguish phishing attempts from legitimate URLs, without relying on manually engineered rules. A whitelist layer handles well-known domains separately to compensate for gaps in the training data (see Known Limitations).

## Project Structure
- **`phishing_detector.py`** — loads the dataset, trains the model, evaluates it, and saves the trained model + vectorizer to disk (`phishing_model.pkl`, `vectorizer.pkl`). Run this first, and only when you want to retrain.
- **`check_phishing.py`** — loads the already-trained model and lets you interactively type any URL to get an instant prediction. This is the tool you actually use to check URLs day-to-day.

## Dataset
- **Source:** [Malicious URLs dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset) (Kaggle)
- **Used:** 522,214 URLs (benign vs phishing subset of the full dataset)
- **Labels:** benign (0) / phishing (1)

## Approach
1. Normalized URLs (removed `http://`, `https://`, `www.` prefixes) to prevent the model from learning superficial formatting patterns instead of real content
2. Converted URLs into numerical features using **TF-IDF character n-grams** (3-5 character sequences), capturing patterns like suspicious substrings and structure without hand-crafted rules
3. Trained a **Logistic Regression** classifier with balanced class weights to handle the imbalance between phishing and legitimate examples
4. Evaluated using accuracy, precision, recall, and F1-score on a held-out test set
5. Added a small **trusted domain whitelist** (Google, Wikipedia, GitHub, major universities, etc.) checked before the ML model, so well-known legitimate sites aren't misjudged due to dataset gaps

## Results
- **Accuracy:** 87%
- **Phishing recall:** 89% (correctly catches most phishing URLs)
- **Legitimate precision:** 97% (rarely misflags real sites)

| Metric | Legitimate (0) | Phishing (1) |
|--------|-----------------|----------------|
| Precision | 0.97 | 0.59 |
| Recall | 0.87 | 0.89 |
| F1-score | 0.92 | 0.71 |

*(These metrics reflect the ML model alone, evaluated on the held-out test set, before the whitelist layer is applied.)*

## Model Selection
Logistic Regression and Random Forest were both trained and compared on the same TF-IDF character n-gram features:

| Metric | Logistic Regression | Random Forest |
|--------|---------------------|----------------|
| Accuracy | 0.87 | 0.81 |
| Phishing Precision | 0.59 | 0.48 |
| Phishing Recall | 0.89 | 0.79 |
| Phishing F1-score | 0.71 | 0.59 |

Logistic Regression performed better across all metrics, likely because it handles high-dimensional sparse text features (like TF-IDF) more effectively than tree-based models, which tend to perform better on structured/tabular data instead. Logistic Regression was kept as the final model.

## Known Limitations
This project surfaced a real and instructive ML challenge: **dataset bias**. The training data is skewed toward older/niche websites (forums, personal blogs) as "legitimate" examples, with fewer modern major sites (e.g. Google, Wikipedia, university domains) represented. As a result, the ML model alone sometimes misjudges well-known modern URLs it hasn't seen similar examples of during training. The whitelist layer is a practical patch for this specific gap — not a substitute for better training data — and only covers a small, manually chosen list of domains.

This reflects a common real-world ML issue: a model is only as representative as the data it's trained on, not a flaw in the modeling approach itself.

## Tech Stack
- Python
- pandas
- scikit-learn (TF-IDF, Logistic Regression)
- joblib

## How to Run
```bash
pip install pandas scikit-learn joblib

# Step 1: Train the model (run once, or whenever you want to retrain)
python phishing_detector.py

# Step 2: Check URLs interactively
python check_phishing.py
```

## Future Improvements
- Expand the trusted domain whitelist or replace it with a maintained public list
- Train on a more balanced, modern dataset covering a wider range of legitimate website types
- Combine with live checks (domain age, SSL validity) for a hybrid detection approach
- Experiment with other models (Random Forest, gradient boosting) on the same n-gram features
- Build a simple web interface instead of a command-line tool

## Author
Ananya Varshney — B.Tech CSE (AI/ML), JSS University