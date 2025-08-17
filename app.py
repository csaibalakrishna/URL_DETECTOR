import os
import logging
import traceback
from flask import Flask, render_template, request, flash, jsonify
from feature_extractor import URLFeatureExtractor
from ml_model import URLClassifier

# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")

# Initialize feature extractor and ML classifier
feature_extractor = URLFeatureExtractor()
url_classifier = URLClassifier()

def normalize_url(url):
    """Ensure URL has protocol"""
    if not url.startswith(('http://', 'https://')):
        return 'http://' + url
    return url

@app.route('/')
def index():
    """Main page with URL input form"""
    return render_template('index.html', results=None)

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze URL and return results on same page"""
    try:
        url = request.form.get('url', '').strip()
        logging.debug(f"Received URL: {url}")

        if not url:
            flash('Please enter a URL to analyze.', 'error')
            return render_template('index.html', results=None)

        url = normalize_url(url)
        logging.debug(f"Normalized URL: {url}")

        features = feature_extractor.extract_features(url)
        logging.debug(f"Extracted features: {features}")

        prediction = url_classifier.predict(features)
        logging.debug(f"Prediction result: {prediction}")

        results = {
            'url': url,
            'features': features,
            'prediction': prediction,
            'risk_level': get_risk_level(prediction['probability']),
            'feature_explanations': get_feature_explanations()
        }

        return render_template('index.html', results=results)

    except Exception as e:
        logging.error(f"Error analyzing URL: {str(e)}")
        logging.error(traceback.format_exc())
        flash(f'Error analyzing URL: {str(e)}', 'error')
        return render_template('index.html', results=None)

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for URL analysis"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400

        url = normalize_url(data['url'].strip())
        logging.debug(f"API received URL: {url}")

        features = feature_extractor.extract_features(url)
        prediction = url_classifier.predict(features)

        return jsonify({
            'url': url,
            'features': features,
            'prediction': prediction,
            'risk_level': get_risk_level(prediction['probability'])
        })

    except Exception as e:
        logging.error(f"API Error: {str(e)}")
        logging.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

def get_risk_level(probability):
    """Determine risk level based on probability"""
    if probability >= 0.8:
        return {'level': 'High', 'class': 'danger', 'description': 'Very likely to be malicious'}
    elif probability >= 0.6:
        return {'level': 'Medium-High', 'class': 'warning', 'description': 'Likely to be suspicious'}
    elif probability >= 0.4:
        return {'level': 'Medium', 'class': 'info', 'description': 'Potentially suspicious'}
    elif probability >= 0.2:
        return {'level': 'Low-Medium', 'class': 'secondary', 'description': 'Slightly suspicious'}
    else:
        return {'level': 'Low', 'class': 'success', 'description': 'Likely to be legitimate'}

def get_feature_explanations():
    """Return explanations for each feature"""
    return {
        'UsingIP': 'URL uses IP address instead of domain name',
        'LongURL': 'URL length exceeds normal limits',
        'ShortURL': 'URL uses URL shortening service',
        'Symbol@': 'URL contains @ symbol (possible redirection)',
        'Redirecting//': 'URL contains // redirecting pattern',
        'PrefixSuffix-': 'Domain contains prefix-suffix pattern with dashes',
        'SubDomains': 'Number of subdomains in the URL',
        'HTTPS': 'URL uses HTTPS protocol',
        'DomainRegLen': 'Domain registration length in days',
        'Favicon': 'Favicon loaded from external domain',
        'NonStdPort': 'URL uses non-standard port',
        'HTTPSDomainURL': 'HTTPS used in domain URL',
        'RequestURL': 'Percentage of request URLs from different domains',
        'AnchorURL': 'Percentage of anchor tags pointing to different domains',
        'LinksInScriptTags': 'Percentage of links in script tags from different domains',
        'ServerFormHandler': 'Form handler from different domain',
        'InfoEmail': 'Email address found in webpage',
        'AbnormalURL': 'URL does not match domain registration info',
        'WebsiteForwarding': 'Website forwards to different domain',
        'StatusBarCust': 'Status bar customization detected',
        'DisableRightClick': 'Right-click disabled on webpage',
        'UsingPopupWindow': 'Popup windows used on webpage',
        'IframeRedirection': 'Iframe redirection detected',
        'AgeofDomain': 'Age of domain in days',
        'DNSRecording': 'DNS record exists for domain',
        'WebsiteTraffic': 'Website traffic ranking',
        'PageRank': 'Google PageRank score',
        'GoogleIndex': 'Website indexed by Google',
        'LinksPointingToPage': 'Number of external links pointing to page',
        'StatsReport': 'Statistics report availability'
    }

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
