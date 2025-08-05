# URL Security Analyzer

## Overview

This is a machine learning-powered web application that analyzes URLs for security threats, particularly focusing on phishing and malicious website detection. The system extracts 30+ features from URLs and uses a Random Forest classifier to predict the risk level. Built with Flask, it provides a user-friendly web interface for URL analysis with detailed feature extraction and risk assessment.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Web Framework**: Flask with Jinja2 templating
- **UI Components**: Bootstrap-based responsive design with custom CSS
- **User Interface**: Single-page form for URL input with detailed results page
- **Styling**: Dark theme Bootstrap with Font Awesome icons for visual consistency

### Backend Architecture
- **Web Server**: Flask application with route-based request handling
- **Feature Extraction**: Custom URLFeatureExtractor class that analyzes 30+ URL characteristics including:
  - Basic URL structure (IP usage, length, subdomains)
  - Security indicators (HTTPS, certificates, ports)
  - Content analysis (HTML parsing, links, forms)
  - Domain reputation (registration length, DNS records, traffic)
- **Machine Learning Pipeline**: URLClassifier using Random Forest algorithm with synthetic training data
- **Model Persistence**: Pickle-based model serialization for reuse across sessions

### Data Processing
- **Feature Engineering**: Comprehensive URL analysis including network requests, DNS lookups, SSL certificate validation, and HTML content parsing
- **Risk Assessment**: Multi-level risk categorization based on ML prediction probabilities
- **Error Handling**: Robust exception handling with fallback mechanisms for network failures

### Security Features
- **Input Validation**: URL format validation and sanitization
- **Request Handling**: Configurable timeouts and proper error handling for external requests
- **SSL Verification**: Certificate validation and HTTPS protocol checking

## External Dependencies

### Core Frameworks
- **Flask**: Web application framework for routing and templating
- **scikit-learn**: Machine learning library for Random Forest classification
- **NumPy**: Numerical computing for feature arrays and model operations

### Web Scraping and Analysis
- **requests**: HTTP library for fetching webpage content and API calls
- **BeautifulSoup4**: HTML parsing for content analysis and feature extraction
- **urllib**: URL parsing and manipulation utilities

### Network and Security Analysis
- **python-whois**: Domain registration information lookup
- **dnspython**: DNS record querying and validation
- **socket**: Network connectivity and IP address validation
- **ssl**: SSL certificate verification and security checks

### Development and Deployment
- **Replit hosting**: Cloud-based development and deployment environment
- **Bootstrap CDN**: Frontend UI framework and styling
- **Font Awesome CDN**: Icon library for user interface elements

### Data Storage
- **File-based model storage**: Pickle files for ML model persistence
- **In-memory feature caching**: Runtime feature storage for analysis results