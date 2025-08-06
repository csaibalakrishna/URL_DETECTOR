import os
import logging
from flask import Flask, render_template, request, jsonify
from feature_extractor import URLFeatureExtractor
from ml_model import URLClassifier
import traceback
from flask_cors import CORS
CORS(app)


# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")

# Initialize feature extractor and ML classifier
feature_extractor = URLFeatureExtractor()
url_classifier = URLClassifier()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    try:
        # Validate content-type
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        data = request.get_json(force=True, silent=True)
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400

        url = data.get('url', '').strip()
        if not url:
            return jsonify({'error': 'URL is required'}), 400

        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        # Extract features and run prediction
        features = feature_extractor.extract_features(url)
        prediction = url_classifier.predict(features)

        result = {
            'url': url,
            'features': features,
            'prediction': prediction,
            'risk_level': get_risk_level(prediction['probability'])
        }

        return jsonify(result)

    except Exception as e:
        logging.error("❌ Internal server error: %s", str(e))
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500

def get_risk_level(probability):
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
