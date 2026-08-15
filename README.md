# 🛡️ PhishGuard — Smart Phishing Detection System

An AI-powered hybrid phishing detection system combining heuristic rules and machine learning.

## Features

- **Hybrid Detection** — Combines rule-based heuristics (30+ checks) with a Random Forest ML classifier
- **30+ URL Features** — Lexical, domain (WHOIS/DNS), and content-based feature extraction
- **Real-Time Analysis** — REST API with web interface for instant URL checking
- **Batch Processing** — Check multiple URLs at once
- **Detailed Reports** — Full breakdown of heuristic flags and ML probability scores

## Quick Start

```bash
# 1. Install dependencies
cd backend
pip install -r requirements.txt

# 2. Train the model (or it auto-trains on first run)
cd ..
python run.py train

# 3. Start the web server
python run.py server

# 4. Open in browser
open http://localhost:5000