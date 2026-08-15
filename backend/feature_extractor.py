from .url_features import URLFeatureExtractor


class FeatureExtractor:
    """Wrapper around URLFeatureExtractor that provides vector conversion."""

    def __init__(self):
        self.extractor = URLFeatureExtractor()
        self._feature_names = [
            'url_length',
            'num_dots',
            'num_hyphens',
            'num_underscores',
            'num_slashes',
            'num_question_marks',
            'num_equals',
            'num_at_symbols',
            'num_ampersands',
            'num_hashes',
            'num_digits',
            'num_special_chars',
            'has_ip',
            'subdomain_count',
            'path_length',
            'num_query_params',
            'uses_https',
            'has_port',
            'suspicious_tld',
            'suspicious_word_count',
            'brand_in_url',
            'brand_misplaced',
            'url_entropy',
            'max_token_length',
            'digit_ratio',
            'domain_age_days',
            'domain_registration_remaining',
            'dns_record_count',
            'has_dns',
            'has_title',
            'has_submit_button',
            'has_password_field',
            'has_external_forms',
            'num_external_links',
            'num_internal_links',
            'has_iframe',
            'has_popup',
            'has_onclick',
            'has_javascript_redirect',
            'page_entropy',
        ]

    def extract_all(self, url):
        return self.extractor.extract_all(url)

    def get_feature_vector(self, url):
        features = self.extract_all(url)
        return [features.get(name, 0) for name in self._feature_names]

    def get_feature_names(self):
        return list(self._feature_names)
