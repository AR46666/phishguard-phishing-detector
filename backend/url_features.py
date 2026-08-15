import re
import math
import hashlib
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
import requests
import whois
import dns.resolver
import tldextract
from datetime import datetime


class URLFeatureExtractor:
    """Extract 40+ features from URLs for phishing detection."""
    
    def __init__(self):
        self.suspicious_tlds = {
            'tk', 'ml', 'ga', 'cf', 'top', 'xyz', 'work', 'download', 'review',
            'gq', 'date', 'cricket', 'stream', 'science', 'icu', 'accountant', 'webcam'
        }
        self.suspicious_keywords = {
            'verify', 'confirm', 'validate', 'update', 'secure', 'urgent',
            'action', 'required', 'alert', 'click', 'suspended', 'locked',
            'restore', 'unusual', 'activity', 'login', 'signin', 'account',
            'bank', 'paypal', 'amazon', 'apple', 'microsoft', 'google'
        }
        self.known_brands = {
            'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
            'twitter', 'netflix', 'spotify', 'dropbox', 'instagram', 'linkedin'
        }
        self.session = requests.Session()
        self.session.timeout = 5
    
    def extract_all(self, url):
        """Extract all 40+ features from a URL."""
        features = {}
        
        try:
            # URL structure features
            features.update(self._extract_url_structure_features(url))
            
            # Domain features
            features.update(self._extract_domain_features(url))
            
            # Content features (requires fetching HTML)
            features.update(self._extract_content_features(url))
            
        except Exception as e:
            print(f"Error extracting features: {e}")
        
        return features
    
    def _extract_url_structure_features(self, url):
        """Extract lexical features from URL string."""
        features = {}
        parsed = urlparse(url)
        
        # Basic length features
        features['url_length'] = len(url)
        features['path_length'] = len(parsed.path)
        
        # Character count features
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_equals'] = url.count('=')
        features['num_at_symbols'] = url.count('@')
        features['num_ampersands'] = url.count('&')
        features['num_hashes'] = url.count('#')
        features['num_digits'] = sum(1 for c in url if c.isdigit())
        
        # Special character count
        special_chars = set('!~*\'();:@&=+$,/?#[]')
        features['num_special_chars'] = sum(1 for c in url if c in special_chars)
        
        # Digit ratio
        features['digit_ratio'] = features['num_digits'] / len(url) if len(url) > 0 else 0
        
        # Protocol
        features['uses_https'] = 1 if parsed.scheme == 'https' else 0
        
        # Port present
        features['has_port'] = 1 if parsed.port else 0
        
        # Query parameters
        features['num_query_params'] = len(parse_qs(parsed.query))
        
        # IP address detection
        features['has_ip'] = self._is_ip_address(parsed.hostname or '')
        
        # Subdomain count
        netloc = parsed.netloc.split(':')[0]  # Remove port
        features['subdomain_count'] = self._count_subdomains(netloc)
        
        # Max token length (longest continuous alphanumeric sequence)
        tokens = re.findall(r'[a-zA-Z0-9]+', url)
        features['max_token_length'] = max(len(t) for t in tokens) if tokens else 0
        
        # URL entropy
        features['url_entropy'] = self._calculate_entropy(url)
        
        return features
    
    def _extract_domain_features(self, url):
        """Extract domain-based features."""
        features = {}
        parsed = urlparse(url)
        netloc = parsed.netloc.split(':')[0]
        
        try:
            extracted = tldextract.extract(url)
            
            # TLD features
            tld = extracted.suffix.lower()
            features['suspicious_tld'] = 1 if tld in self.suspicious_tlds else 0
            
            # Domain brand features
            domain_lower = extracted.domain.lower()
            subdomain_lower = extracted.subdomain.lower()
            
            # Check if known brand is in domain/subdomain
            brand_found = any(brand in domain_lower or brand in subdomain_lower 
                            for brand in self.known_brands)
            features['brand_in_url'] = 1 if brand_found else 0
            
            # Brand misplaced (in subdomain but not main domain)
            brand_in_subdomain = any(brand in subdomain_lower for brand in self.known_brands)
            brand_in_domain = any(brand in domain_lower for brand in self.known_brands)
            features['brand_misplaced'] = 1 if (brand_in_subdomain and not brand_in_domain) else 0
            
        except Exception:
            features['suspicious_tld'] = 0
            features['brand_in_url'] = 0
            features['brand_misplaced'] = 0
        
        # Suspicious words in URL
        url_lower = url.lower()
        features['suspicious_word_count'] = sum(1 for word in self.suspicious_keywords 
                                               if word in url_lower)
        
        # Domain age and registration
        try:
            domain_info = whois.whois(netloc)
            
            if domain_info.creation_date:
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                domain_age = (datetime.now() - creation_date).days
                features['domain_age_days'] = max(0, domain_age)
            else:
                features['domain_age_days'] = -1
            
            if domain_info.expiration_date:
                expiration_date = domain_info.expiration_date
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]
                days_remaining = (expiration_date - datetime.now()).days
                features['domain_registration_remaining'] = max(0, days_remaining)
            else:
                features['domain_registration_remaining'] = -1
                
        except Exception:
            features['domain_age_days'] = -1
            features['domain_registration_remaining'] = -1
        
        # DNS features
        try:
            dns_records = 0
            try:
                dns.resolver.resolve(netloc, 'A')
                dns_records += 1
            except:
                pass
            try:
                dns.resolver.resolve(netloc, 'MX')
                dns_records += 1
            except:
                pass
            
            features['dns_record_count'] = dns_records
            features['has_dns'] = 1 if dns_records > 0 else 0
        except Exception:
            features['dns_record_count'] = 0
            features['has_dns'] = 0
        
        return features
    
    def _extract_content_features(self, url):
        """Extract content-based features from HTML."""
        features = {
            'has_title': 0,
            'has_submit_button': 0,
            'has_password_field': 0,
            'has_external_forms': 0,
            'num_external_links': 0,
            'num_internal_links': 0,
            'has_iframe': 0,
            'has_popup': 0,
            'has_onclick': 0,
            'has_javascript_redirect': 0,
            'page_entropy': 0
        }
        
        try:
            response = self.session.get(url, allow_redirects=True, verify=False)
            html_content = response.text
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Title feature
            if soup.title or soup.find('title'):
                features['has_title'] = 1
            
            # Form features
            forms = soup.find_all('form')
            for form in forms:
                # Check for submit button
                if form.find('input', {'type': 'submit'}) or form.find('button'):
                    features['has_submit_button'] = 1
                
                # Check for password field
                if form.find('input', {'type': 'password'}):
                    features['has_password_field'] = 1
                
                # Check if form action is external
                form_action = form.get('action', '')
                if form_action and not self._is_same_domain(url, form_action):
                    features['has_external_forms'] = 1
            
            # Link features
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            links = soup.find_all('a', href=True)
            for link in links:
                href = link['href']
                if href.startswith('http') and not self._is_same_domain(url, href):
                    features['num_external_links'] += 1
                elif href.startswith('/') or not href.startswith('http'):
                    features['num_internal_links'] += 1
            
            # Iframe feature
            if soup.find('iframe'):
                features['has_iframe'] = 1
            
            # Popup/window features
            if 'window.open' in html_content or 'alert(' in html_content:
                features['has_popup'] = 1
            
            # onclick features
            if 'onclick' in html_content:
                features['has_onclick'] = 1
            
            # JavaScript redirect
            if re.search(r'window\.location|location\.href|document\.location', html_content):
                features['has_javascript_redirect'] = 1
            
            # Page entropy
            features['page_entropy'] = self._calculate_entropy(html_content)
            
        except Exception as e:
            # If we can't fetch, return default content features
            pass
        
        return features
    
    def _is_ip_address(self, hostname):
        """Check if hostname is an IP address."""
        if not hostname:
            return 0
        
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, hostname):
            parts = hostname.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                return 1
        
        # IPv6 pattern
        if ':' in hostname:
            return 1
        
        return 0
    
    def _count_subdomains(self, netloc):
        """Count number of subdomains."""
        if not netloc:
            return 0
        
        # Remove port if present
        netloc = netloc.split(':')[0]
        
        # IP address has 0 subdomains
        if self._is_ip_address(netloc):
            return 0
        
        # Count dots
        return netloc.count('.')
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text."""
        if not text or len(text) == 0:
            return 0
        
        # Calculate frequency of each character
        char_freq = {}
        for char in text:
            char_freq[char] = char_freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        for freq in char_freq.values():
            probability = freq / len(text)
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _is_same_domain(self, url1, url2):
        """Check if two URLs have the same domain."""
        try:
            parsed1 = urlparse(url1)
            parsed2 = urlparse(url2)
            
            domain1 = tldextract.extract(url1).registered_domain
            domain2 = tldextract.extract(url2).registered_domain
            
            return domain1 == domain2 if domain1 and domain2 else False
        except:
            return False
