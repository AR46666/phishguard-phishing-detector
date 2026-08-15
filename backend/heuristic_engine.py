import re
from urllib.parse import urlparse
from .feature_extractor import FeatureExtractor

class HeuristicEngine:
    """
    Rule-based phishing detection engine.
    Each rule contributes a weighted score. Total > threshold => likely phishing.
    """
    
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        
        # Weights for each heuristic rule
        self.weights = {
            'has_ip': 25,
            'url_too_long': 10,
            'excessive_special_chars': 10,
            'suspicious_tld': 20,
            'brand_misplaced': 30,
            'at_symbol_present': 30,
            'multiple_subdomains': 15,
            'no_https': 15,
            'very_new_domain': 25,
            'suspicious_words': 15,
            'high_digit_ratio': 10,
            'shortened_url': 20,
            'excessive_hyphens': 10,
        }
        
        self.max_score = sum(self.weights.values())
    
    def score_url(self, url):
        """Score a URL from 0 (safe) to 100 (definitely phishing) using heuristic rules."""
        features = self.feature_extractor.extract_all(url)
        score = 0
        reasons = []
        
        # 1. IP address instead of domain
        if features.get('has_ip', 0) == 1:
            score += self.weights['has_ip']
            reasons.append("IP address used instead of domain name")
        
        # 2. URL too long (> 75 chars is suspicious)
        if features.get('url_length', 0) > 75:
            score += self.weights['url_too_long']
            reasons.append(f"URL is very long ({features['url_length']} chars)")
        
        # 3. Excessive special characters
        if features.get('num_special_chars', 0) > 15:
            score += self.weights['excessive_special_chars']
            reasons.append(f"Excessive special characters ({features['num_special_chars']})")
        
        # 4. Suspicious TLD
        if features.get('suspicious_tld', 0) == 1:
            score += self.weights['suspicious_tld']
            reasons.append("Suspicious top-level domain")
        
        # 5. Brand name misplaced (brand in subdomain, not main domain)
        if features.get('brand_misplaced', 0) == 1:
            score += self.weights['brand_misplaced']
            reasons.append("Brand name appears in subdomain but not main domain")
        
        # 6. @ symbol in URL
        if features.get('num_at_symbols', 0) > 0:
            score += self.weights['at_symbol_present']
            reasons.append("@ symbol present in URL (attempts to hide real domain)")
        
        # 7. Multiple subdomains
        if features.get('subdomain_count', 0) >= 3:
            score += self.weights['multiple_subdomains']
            reasons.append(f"Multiple subdomains detected ({features['subdomain_count']})")
        
        # 8. No HTTPS
        if features.get('uses_https', 0) == 0:
            score += self.weights['no_https']
            reasons.append("No HTTPS encryption")
        
        # 9. Very new domain (< 6 months)
        if features.get('domain_age_days', -1) >= 0 and features['domain_age_days'] < 180:
            score += self.weights['very_new_domain']
            reasons.append(f"Domain is very new ({features['domain_age_days']} days old)")
        
        # 10. Suspicious words in URL
        if features.get('suspicious_word_count', 0) >= 2:
            score += self.weights['suspicious_words']
            reasons.append(f"Suspicious keywords detected ({features['suspicious_word_count']})")
        
        # 11. High digit ratio (> 30% digits)
        if features.get('digit_ratio', 0) > 0.3:
            score += self.weights['high_digit_ratio']
            reasons.append(f"High digit ratio in URL ({features['digit_ratio']:.1%})")
        
        # 12. Shortened URL (bit.ly, tinyurl, etc.)
        parsed = urlparse(url)
        shortening_services = [
            'bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'tiny.cc', 'tr.im',
            'is.gd', 'cli.gs', 'shorturl', 'short.link', 'buff.ly',
            'adf.ly', 'bc.vc', '2.gp', 'v.gd', 'soo.gd'
        ]
        if any(service in parsed.netloc.lower() for service in shortening_services):
            score += self.weights['shortened_url']
            reasons.append("URL is shortened (masks destination)")
        
        # 13. Excessive hyphens
        if features.get('num_hyphens', 0) >= 4:
            score += self.weights['excessive_hyphens']
            reasons.append(f"Excessive hyphens in URL ({features['num_hyphens']})")
        
        # Normalize score to 0-100
        normalized_score = min(100, (score / self.max_score) * 100)
        
        return {
            'heuristic_score': round(normalized_score, 2),
            'heuristic_verdict': 'phishing' if normalized_score >= 50 else 'suspicious' if normalized_score >= 25 else 'safe',
            'heuristic_reasons': reasons,
            'heuristic_raw_score': score
        }