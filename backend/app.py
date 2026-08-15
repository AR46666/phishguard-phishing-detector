import os
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from .hybrid_scorer import HybridScorer
from .model import PhishingClassifier
from .heuristic_engine import HeuristicEngine
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates")
)
CORS(app)

# Initialize components
scorer = HybridScorer()
heuristic_engine = HeuristicEngine()

@app.route('/api/check', methods=['POST'])
def check_url():
    """Analyze a single URL."""
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing URL parameter'}), 400
    
    url = data['url'].strip()
    
    if not url:
        return jsonify({'error': 'Empty URL'}), 400
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    result = scorer.analyze(url)
    
    return jsonify(result)

@app.route('/api/check_batch', methods=['POST'])
def check_batch():
    """Analyze multiple URLs at once."""
    data = request.get_json()
    
    if not data or 'urls' not in data:
        return jsonify({'error': 'Missing urls parameter'}), 400
    
    urls = data['urls']
    if not isinstance(urls, list):
        return jsonify({'error': 'urls must be a list'}), 400
    
    results = []
    for url in urls:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        results.append(scorer.analyze(url.strip()))
    
    return jsonify({'results': results, 'count': len(results)})

@app.route('/api/report', methods=['POST'])
def get_report():
    """Get a detailed text report for a URL."""
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing URL parameter'}), 400
    
    url = data['url'].strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    report = scorer.get_detailed_report(url)
    
    return jsonify({'report': report})

@app.route('/api/quick_check', methods=['GET'])
def quick_check():
    """Quick check via GET request with query parameter."""
    url = request.args.get('url', '')
    
    if not url:
        return jsonify({'error': 'Missing url query parameter'}), 400
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    result = scorer.analyze(url)
    
    # Simplified response
    return jsonify({
        'url': result['url'],
        'verdict': result['verdict'],
        'severity': result['severity'],
        'score': result['combined_score']
    })

@app.route('/api/features', methods=['POST'])
def get_features():
    """Extract and return features from a URL (debug/diagnostics)."""
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing URL parameter'}), 400
    
    url = data['url'].strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    extractor = heuristic_engine.feature_extractor
    features = extractor.extract_all(url)
    
    # Convert non-serializable values
    clean_features = {k: v for k, v in features.items() if isinstance(v, (int, float, str, bool))}
    
    return jsonify({'features': clean_features, 'count': len(clean_features)})

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'ok',
        'ml_available': scorer.ml_available,
        'version': '2.0.0'
    })

# Serve frontend (for development)
@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)