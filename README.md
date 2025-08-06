# 🔍 URL Phishing Detector

A machine learning-based phishing detection system that classifies URLs as safe or malicious based on extracted features. This project leverages domain knowledge and behavior-based features to predict the likelihood of a URL being part of a phishing campaign.

## 🚀 Overview

This project aims to combat phishing attacks by analyzing and classifying URLs using an ensemble machine learning model. It extracts key lexical, host-based, and DNS-related features from URLs to determine their legitimacy.

## 🧠 Model Information

- **Algorithm Used**: Random Forest Classifier
- **Accuracy**: 96.86%
- **Precision**: 0.97
- **Recall**: 0.96
- **F1-Score**: 0.96
- **Dataset**: Custom dataset including both benign and malicious URLs, collected from open phishing feeds and verified sources.

## 🧪 Features Extracted

- URL length
- Presence of IP address
- Number of subdomains
- Use of HTTPS
- Domain registration length (WHOIS)
- DNS record availability
- Alexa ranking
- URL shortening service detection
- and 20+ additional handcrafted features.

## 📊 Prediction Output

Each URL submission is classified into:
- **Legitimate**
- **Suspicious**
- **Phishing**

With associated risk level and feature explanation based on the model's interpretation.

## 🌐 Frontend

- Built with HTML/CSS and Flask templating
- Loading state UI with form validation
- Real-time predictions displayed on `results.html`

## 🛡️ Goal

To create a lightweight, browser-based phishing URL detector that can be used as a research project, cybersecurity demo, or integrated into a broader SOC dashboard.

---

