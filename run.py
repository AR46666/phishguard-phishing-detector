#!/usr/bin/env python3
"""
PhishGuard v2.0 — Smart Phishing Detection System
Entry point for training and running the server.
"""

import os
import sys
import argparse
from backend.model import PhishingClassifier
from backend.app import app

def train_model(dataset_path=None):
    """Train the ML model."""
    print("🛡️  PhishGuard - Model Training")
    print("=" * 50)
    
    classifier = PhishingClassifier()
    
    if dataset_path:
        print(f"Training with dataset: {dataset_path}")
        results = classifier.train(csv_path=dataset_path)
    else:
        # Use built-in fallback: train with sample data
        print("No dataset provided. Training with built-in sample data...")
        results = classifier.train(
            urls=[
                # Phishing examples
                "http://secure-paypal.com/login/verify/account123",
                "https://paypa1.com/signin?return=https://paypal.com",
                "http://192.168.1.1/banking/login",
                "https://www.amazon-secure.com/update-billing",
                "http://bit.ly/3xK9mN2",
                "https://login.microsoftonline.com-verify.xyz/",
                "http://support-apple.com-id8392.help/",
                "https://wellsfargo-account-alert.com/verify",
                "http://chase-online-banking.ml/login",
                "https://google-drive-share.tk/document",
                "http://netflix.com-account-verify.stream/",
                "https://www.paypal-security-login.tk/",
                "http://facebook-free-votes.ga/login",
                "https://instagram-verification-help.top/",
                "http://dropbox-shared-file.xyz/download",
                "https://www.bankofamerica-signin.com/",
                "http://amazon-order-confirm.ml/",
                "https://adobe-account-update.work/",
                "http://password-reset-verify-login.com/",
                "https://steamcommunity-com-mods.xyz/login",
                # Legitimate examples
                "https://www.google.com/search?q=phishing+detection",
                "https://github.com/Th-Shivam/Phishguard",
                "https://www.python.org/downloads/",
                "https://stackoverflow.com/questions/tagged/phishing",
                "https://www.wikipedia.org/",
                "https://www.amazon.com/gp/cart/view.html",
                "https://www.paypal.com/signin",
                "https://www.microsoft.com/en-us/software-download",
                "https://www.linkedin.com/in/some-profile/",
                "https://support.apple.com/en-us/HT201222",
                "https://netflix.com/browse/genre/839338",
                "https://www.wellsfargo.com/help/faq/",
                "https://chaseonline.chase.com/Logon",
                "https://www.bankofamerica.com/online-banking/",
                "https://www.dropbox.com/home",
                "https://www.instagram.com/accounts/login/",
                "https://www.facebook.com/help/",
                "https://twitter.com/home",
                "https://www.adobe.com/creativecloud.html",
                "https://wordpress.com/log-in"
            ],
            labels=[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  # phishing
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]  # legitimate
        )
    
    print("\n✅ Training complete!")
    print(f"   Accuracy:  {results['accuracy']:.2%}")
    print(f"   Precision: {results['precision']:.2%}")
    print(f"   Recall:    {results['recall']:.2%}")
    print(f"   F1-Score:  {results['f1']:.2%}")
    print(f"   AUC-ROC:   {results['auc']:.4f}")


def run_server(host='0.0.0.0', port=5000, debug=False):
    """Run the Flask web server."""
    print("🛡️  PhishGuard - Web Server")
    print("=" * 50)
    print(f"Starting server on {host}:{port}")
    print("Open http://localhost:5000 in your browser")
    print("Press Ctrl+C to stop\n")
    
    app.run(host=host, port=port, debug=debug)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='PhishGuard - AI-Powered Phishing Detection System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py train                     # Train with built-in sample data
  python run.py train data/urls.csv       # Train with custom dataset
  python run.py server                    # Start web server
  python run.py server --port 8080        # Start on custom port
  python run.py check "https://example.com"  # Check single URL
        """
    )
    
    parser.add_argument(
        'command',
        nargs='?',
        default='server',
        choices=['train', 'server', 'check'],
        help='Command to execute (default: server)'
    )
    
    parser.add_argument(
        'arg',
        nargs='?',
        help='Argument for command (e.g., dataset path for train, URL for check)'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Port for web server (default: 5000)'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Run server in debug mode'
    )
    
    args = parser.parse_args()
    
    if args.command == 'train':
        train_model(args.arg)
    
    elif args.command == 'server':
        run_server(port=args.port, debug=args.debug)
    
    elif args.command == 'check':
        if not args.arg:
            print("Error: Please provide a URL to check")
            sys.exit(1)
        
        from backend.hybrid_scorer import HybridScorer
        scorer = HybridScorer()
        url = args.arg
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        print("\n" + scorer.get_detailed_report(url))


if __name__ == "__main__":
    app.run(debug=True)