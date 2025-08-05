#!/usr/bin/env python3
"""
Generate training data CSV file for URL Security Analyzer
This script creates the same synthetic dataset used to train the ML model
"""

import numpy as np
import pandas as pd
import logging

def generate_training_data(n_samples=10000):
    """Generate synthetic training data for URL classification"""
    np.random.seed(42)  # Same seed as ML model for consistency
    
    # Feature names in correct order
    feature_names = [
        'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//', 'PrefixSuffix-',
        'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon', 'NonStdPort', 'HTTPSDomainURL',
        'RequestURL', 'AnchorURL', 'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail',
        'AbnormalURL', 'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
        'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
        'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage', 'StatsReport'
    ]
    
    # Generate features for legitimate URLs (class 0)
    print(f"Generating {n_samples//2} legitimate URL samples...")
    n_legit = n_samples // 2
    legit_features = []
    
    for _ in range(n_legit):
        features = [
            np.random.choice([0, 1], p=[0.98, 0.02]),  # UsingIP - almost never for legit
            np.random.choice([0, 1], p=[0.7, 0.3]),   # LongURL - sometimes long for legit
            np.random.choice([0, 1], p=[0.99, 0.01]), # ShortURL - rarely short URLs
            np.random.choice([0, 1], p=[0.995, 0.005]), # Symbol@ - very rare in legit URLs
            np.random.choice([0, 1], p=[0.98, 0.02]), # Redirecting// - very rare
            np.random.choice([0, 1], p=[0.6, 0.4]),   # PrefixSuffix- - common in legit sites
            np.random.choice([0, 1, 2], p=[0.5, 0.4, 0.1]), # SubDomains - often 0-1
            np.random.choice([0, 1], p=[0.85, 0.15]), # HTTPS - mostly use HTTPS
            np.random.choice([0, 1], p=[0.9, 0.1]),   # DomainRegLen - mostly long reg
            np.random.choice([0, 1], p=[0.95, 0.05]), # Favicon - usually from same domain
            np.random.choice([0, 1], p=[0.98, 0.02]), # NonStdPort - usually standard
            np.random.choice([0, 1], p=[0.9, 0.1]),   # HTTPSDomainURL
            np.random.choice([0, 1], p=[0.9, 0.1]),   # RequestURL
            np.random.choice([0, 1], p=[0.85, 0.15]), # AnchorURL
            np.random.choice([0, 1], p=[0.9, 0.1]),   # LinksInScriptTags
            np.random.choice([0, 1], p=[0.98, 0.02]), # ServerFormHandler
            np.random.choice([0, 1], p=[0.4, 0.6]),   # InfoEmail - many legit sites have email
            np.random.choice([0, 1], p=[0.95, 0.05]), # AbnormalURL
            np.random.choice([0, 1], p=[0.98, 0.02]), # WebsiteForwarding
            np.random.choice([0, 1], p=[0.99, 0.01]), # StatusBarCust
            np.random.choice([0, 1], p=[0.99, 0.01]), # DisableRightClick
            np.random.choice([0, 1], p=[0.98, 0.02]), # UsingPopupWindow
            np.random.choice([0, 1], p=[0.95, 0.05]), # IframeRedirection
            np.random.choice([0, 1], p=[0.9, 0.1]),   # AgeofDomain - most legit sites are old
            np.random.choice([0, 1], p=[0.98, 0.02]), # DNSRecording
            np.random.choice([0, 1], p=[0.8, 0.2]),   # WebsiteTraffic - better distribution for legit
            np.random.choice([0, 1], p=[0.8, 0.2]),   # PageRank - better for legit
            np.random.choice([0, 1], p=[0.9, 0.1]),   # GoogleIndex - most legit sites indexed
            np.random.choice([0, 1], p=[0.75, 0.25]), # LinksPointingToPage
            np.random.choice([0, 1], p=[0.7, 0.3])    # StatsReport
        ]
        legit_features.append(features)
    
    # Generate features for malicious URLs (class 1)
    print(f"Generating {n_samples - n_legit} malicious URL samples...")
    n_malicious = n_samples - n_legit
    malicious_features = []
    
    for _ in range(n_malicious):
        features = [
            np.random.choice([0, 1], p=[0.3, 0.7]),   # UsingIP - more likely in malicious
            np.random.choice([0, 1], p=[0.4, 0.6]),   # LongURL - often long
            np.random.choice([0, 1], p=[0.6, 0.4]),   # ShortURL - sometimes short
            np.random.choice([0, 1], p=[0.8, 0.2]),   # Symbol@ - more common
            np.random.choice([0, 1], p=[0.7, 0.3]),   # Redirecting// - more common
            np.random.choice([0, 1], p=[0.4, 0.6]),   # PrefixSuffix- - often present
            np.random.choice([0, 1, 2], p=[0.2, 0.3, 0.5]), # SubDomains - often multiple
            np.random.choice([0, 1], p=[0.3, 0.7]),   # HTTPS - often no HTTPS
            np.random.choice([0, 1], p=[0.2, 0.8]),   # DomainRegLen - often short reg
            np.random.choice([0, 1], p=[0.3, 0.7]),   # Favicon - often external
            np.random.choice([0, 1], p=[0.7, 0.3]),   # NonStdPort - sometimes non-std
            np.random.choice([0, 1], p=[0.3, 0.7]),   # HTTPSDomainURL
            np.random.choice([0, 1], p=[0.2, 0.8]),   # RequestURL - often external
            np.random.choice([0, 1], p=[0.3, 0.7]),   # AnchorURL - often external
            np.random.choice([0, 1], p=[0.4, 0.6]),   # LinksInScriptTags
            np.random.choice([0, 1], p=[0.6, 0.4]),   # ServerFormHandler
            np.random.choice([0, 1], p=[0.3, 0.7]),   # InfoEmail - often missing
            np.random.choice([0, 1], p=[0.2, 0.8]),   # AbnormalURL - often abnormal
            np.random.choice([0, 1], p=[0.6, 0.4]),   # WebsiteForwarding
            np.random.choice([0, 1], p=[0.7, 0.3]),   # StatusBarCust - sometimes used
            np.random.choice([0, 1], p=[0.7, 0.3]),   # DisableRightClick
            np.random.choice([0, 1], p=[0.6, 0.4]),   # UsingPopupWindow
            np.random.choice([0, 1], p=[0.5, 0.5]),   # IframeRedirection
            np.random.choice([0, 1], p=[0.1, 0.9]),   # AgeofDomain - usually new
            np.random.choice([0, 1], p=[0.6, 0.4]),   # DNSRecording
            np.random.choice([0, 1], p=[0.2, 0.8]),   # WebsiteTraffic - usually low
            np.random.choice([0, 1], p=[0.2, 0.8]),   # PageRank - usually low
            np.random.choice([0, 1], p=[0.3, 0.7]),   # GoogleIndex - often not indexed
            np.random.choice([0, 1], p=[0.2, 0.8]),   # LinksPointingToPage - usually few
            np.random.choice([0, 1], p=[0.1, 0.9])    # StatsReport - usually none
        ]
        malicious_features.append(features)
    
    # Combine features and labels
    all_features = legit_features + malicious_features
    labels = [0] * n_legit + [1] * n_malicious
    
    # Create DataFrame
    print("Creating DataFrame...")
    data = []
    for i, (features, label) in enumerate(zip(all_features, labels)):
        row = dict(zip(feature_names, features))
        row['Index'] = i + 1
        row['label'] = label
        data.append(row)
    
    df = pd.DataFrame(data)
    
    # Reorder columns to match the original feature order
    columns_order = ['Index'] + feature_names + ['label']
    df = df[columns_order]
    
    return df

def main():
    print("URL Security Analyzer - Training Data Generator")
    print("=" * 50)
    
    # Generate training data
    df = generate_training_data(10000)
    
    # Save to CSV
    csv_filename = 'url_security_training_data.csv'
    print(f"Saving training data to {csv_filename}...")
    df.to_csv(csv_filename, index=False)
    
    # Display statistics
    print(f"\nTraining Data Statistics:")
    print(f"Total samples: {len(df)}")
    print(f"Legitimate URLs (label 0): {len(df[df['label'] == 0])}")
    print(f"Malicious URLs (label 1): {len(df[df['label'] == 1])}")
    print(f"Features: {len(df.columns) - 2}")  # Exclude Index and label
    print(f"CSV file saved: {csv_filename}")
    
    # Show first few rows
    print(f"\nFirst 5 rows of training data:")
    print(df.head())
    
    print(f"\nFile successfully created: {csv_filename}")
    print("You can now download this CSV file to use for training or analysis.")

if __name__ == "__main__":
    main()