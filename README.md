# Phishing URL Detector
A machine learning model that classifies websites as **phishing** or **legitimate** based on 30 URL and website-based features, using Logistic Regression.

## Overview
Phishing websites are a major cybersecurity threat, tricking users into revealing sensitive information like passwords and financial details. This project builds a classifier that analyzes structural and behavioral features of a website (e.g. URL length, use of HTTPS, presence of IP address in URL, domain age) to predict whether it's likely to be a phishing site.

## Dataset
- **Source:** [Phishing Website Detector dataset](https://www.kaggle.com/datasets/eswarchandt/phishing-website-detector) (Kaggle)
- **Size:** 11,054 websites
- **Features:** 30 pre-extracted features including `UsingIP`, `HTTPS`, `AbnormalURL`, `DomainRegLen`, `AgeofDomain`, and more
- **Target:** `class` — `1` (legitimate) or `-1` (phishing)

## Approach
1. Loaded and explored the dataset using pandas
2. Split data into training (80%) and testing (20%) sets
3. Trained a **Logistic Regression** model using scikit-learn
4. Evaluated performance using accuracy, precision, recall, and F1-score

## Results
- **Accuracy:** 93.4%
- **Precision/Recall:** ~0.93–0.94 across both classes (balanced performance)

| Metric | Phishing (-1) | Legitimate (1) |
|--------|---------------|-----------------|
| Precision | 0.94 | 0.93 |
| Recall | 0.91 | 0.95 |
| F1-score | 0.92 | 0.94 |

## Tech Stack
- Python
- pandas
- scikit-learn

## How to Run
```bash
pip install pandas scikit-learn
python phishing_detector.py
```

## Future Improvements
- Try other algorithms (Random Forest, XGBoost) for comparison
- Build feature extraction directly from raw URLs (instead of pre-extracted features)
- Deploy as a simple web app for real-time URL checking

## Author
Ananya Varshney — B.Tech CSE (AI/ML), JSS University