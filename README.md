# Phishing URL Detector
A machine learning model that classifies URLs as **phishing** or **legitimate**, trained on 500K+ real-world URLs using character-level text patterns and Logistic Regression.

## Overview
Phishing websites trick users into revealing sensitive information by mimicking legitimate sites. This project analyzes the raw text of a URL, using overlapping 3-5 character sequences to learn patterns that distinguish phishing attempts from legitimate URLs, without relying on manually engineered rules.

## Dataset
- **Source:** [Malicious URLs dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset) (Kaggle)
- **Used:** 522,214 URLs (benign vs phishing subset of the full dataset)
- **Labels:** benign (0) / phishing (1)

## Approach
1. Normalized URLs (removed `http://`, `https://`, `www.` prefixes) to prevent the model from learning superficial formatting patterns instead of real content
2. Converted URLs into numerical features using **TF-IDF character n-grams** (3-5 character sequences), which capture patterns like suspicious substrings and structure without needing hand-crafted rules
3. Trained a **Logistic Regression** classifier with balanced class weights to handle the imbalance between phishing and legitimate examples
4. Evaluated using accuracy, precision, recall, and F1-score on a held-out test set

## Results
- **Accuracy:** 87%
- **Phishing recall:** 89% (correctly catches most phishing URLs)
- **Legitimate precision:** 97% (rarely misflags real sites)

| Metric | Legitimate (0) | Phishing (1) |
|--------|-----------------|----------------|
| Precision | 0.97 | 0.59 |
| Recall | 0.87 | 0.89 |
| F1-score | 0.92 | 0.71 |

## Known Limitations
This project surfaced a real and instructive ML challenge: **dataset bias**. The training data is skewed toward older/niche websites (forums, personal blogs) as "legitimate" examples, with fewer modern major sites (e.g. Google, Wikipedia) represented. As a result, the model sometimes misjudges well-known modern URLs it hasn't seen similar examples of during training, since it's inferring from character patterns alone rather than reputation or domain trust.

This reflects a common real-world ML issue: a model is only as representative as the data it's trained on, not a flaw in the modeling approach itself.

## Tech Stack
- Python
- pandas
- scikit-learn (TF-IDF, Logistic Regression)
- joblib

## How to Run
```bash
pip install pandas scikit-learn joblib
python phishing_detector.py
```

## Future Improvements
- Add a whitelist layer for well-known safe domains (Google, Wikipedia, GitHub, etc.) to compensate for dataset bias
- Train on a more balanced, modern dataset covering a wider range of legitimate website types
- Combine with live checks (domain age, SSL validity) for a hybrid detection approach
- Experiment with other models (Random Forest, gradient boosting) on the same n-gram features

## Author
Ananya Varshney — B.Tech CSE (AI/ML), JSS University