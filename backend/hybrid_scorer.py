import numpy as np
from .heuristic_engine import HeuristicEngine
from .model import PhishingClassifier

class HybridScorer:
    """
    Hybrid phishing detection combining heuristic rules and ML predictions.
    Uses weighted fusion to produce a final confidence score.
    """
    
    def __init__(self, ml_weight=0.6, heuristic_weight=0.4):
        self.heuristic = HeuristicEngine()
        self.ml_classifier = PhishingClassifier()
        self.ml_weight = ml_weight
        self.heuristic_weight = heuristic_weight
        
        # Attempt to load ML model (will be trained first if not found)
        try:
            self.ml_classifier._load_model()
            self.ml_available = True
        except Exception as e:
            # Any error while loading the model should not crash the app.
            print(f"Warning: ML model could not be loaded: {e}")
            print("Falling back to heuristic-only mode.")
            self.ml_available = False
    
    def analyze(self, url):
        """Complete analysis of a URL using both methods."""
        # Step 1: Heuristic analysis (always available)
        heuristic_result = self.heuristic.score_url(url)
        
        # Step 2: ML analysis (if available)
        ml_result = None
        if self.ml_available:
            try:
                ml_result = self.ml_classifier.predict(url)
            except Exception as e:
                print(f"ML prediction failed: {e}")
        
        # Step 3: Combine scores
        if ml_result:
            # Heuristic gives 0-100, ML gives 0-1 probability
            heuristic_score_normalized = heuristic_result['heuristic_score'] / 100.0
            ml_score = ml_result['ml_probability']
            
            # Weighted fusion
            combined_score = (
                self.ml_weight * ml_score +
                self.heuristic_weight * heuristic_score_normalized
            )
            
            # Confidence
            ml_conf = ml_result['ml_confidence']
            heuristic_conf = 1.0 - abs(0.5 - heuristic_score_normalized) * 2  # Map to 0-1
            combined_confidence = (
                self.ml_weight * ml_conf +
                self.heuristic_weight * heuristic_conf
            )
            
            # Final verdict
            if combined_score >= 0.65:
                verdict = 'phishing'
                severity = 'CRITICAL' if combined_score >= 0.85 else 'HIGH'
            elif combined_score >= 0.40:
                verdict = 'suspicious'
                severity = 'MEDIUM'
            else:
                verdict = 'safe'
                severity = 'LOW'
        else:
            # Heuristic-only fallback
            combined_score = heuristic_result['heuristic_score'] / 100.0
            combined_confidence = 1.0 - abs(0.5 - combined_score) * 2
            
            if combined_score >= 0.50:
                verdict = 'suspicious'
                severity = 'MEDIUM'
            else:
                verdict = 'safe'
                severity = 'LOW'
        
        return {
            'url': url,
            'verdict': verdict,
            'severity': severity,
            'combined_score': round(float(combined_score), 4),
            'confidence': round(float(combined_confidence), 4),
            'heuristic': heuristic_result,
            'ml': ml_result,
            'ml_weight': self.ml_weight,
            'heuristic_weight': self.heuristic_weight
        }
    
    def get_detailed_report(self, url):
        """Generate a human-readable report for a URL analysis."""
        result = self.analyze(url)
        
        report = f"""
╔══════════════════════════════════════════════════════════╗
║                 PHISHGUARD ANALYSIS REPORT               ║
╚══════════════════════════════════════════════════════════╝

URL:           {result['url']}
Verdict:       {result['verdict'].upper()}
Severity:      {result['severity']}
Confidence:    {result['confidence']:.1%}
Combined Score: {result['combined_score']:.2%}

──────────────────────────────────────────────────────────
HEURISTIC ANALYSIS
──────────────────────────────────────────────────────────
Score:  {result['heuristic']['heuristic_score']:.1f}/100
Verdict: {result['heuristic']['heuristic_verdict'].upper()}
"""
        if result['heuristic']['heuristic_reasons']:
            report += "Flags:\n"
            for r in result['heuristic']['heuristic_reasons']:
                report += f"  ⚠  {r}\n"
        else:
            report += "No heuristic flags raised.\n"
        
        if result['ml']:
            report += f"""
──────────────────────────────────────────────────────────
MACHINE LEARNING ANALYSIS
──────────────────────────────────────────────────────────
Prediction: {result['ml']['ml_verdict'].upper()}
Probability: {result['ml']['ml_probability']:.1%}
Confidence:  {result['ml']['ml_confidence']:.1%}

──────────────────────────────────────────────────────────
FUSION
──────────────────────────────────────────────────────────
ML Weight:      {result['ml_weight']:.0%}
Heuristic Weight: {result['heuristic_weight']:.0%}
"""
        
        return report