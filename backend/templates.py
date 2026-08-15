"""
PhishGuard - Phishing Email & URL Templates Database
=====================================================
100+ templates used for:
  - Pattern matching in the heuristic engine
  - Training data generation
  - Reference signatures for detection
  - Testing and validation

Each template has: category, subject_pattern, body_signatures, url_patterns, threat_score
"""

PHISHING_TEMPLATES = {
    # ================================================================
    # CATEGORY 1: BANKING & FINANCIAL PHISHING (Templates 1-20)
    # ================================================================
    1: {
        "category": "Banking Alert",
        "target": "General Banking",
        "subject_patterns": [
            "urgent security alert", "account suspended", "unauthorized login detected",
            "verify your account immediately", "suspicious activity detected",
            "account limited", "confirm your identity", "security verification required"
        ],
        "body_signatures": [
            "we detected unusual activity", "click here to verify", "temporary suspension",
            "for your security please confirm", "account will be deactivated",
            "login to verify your identity", "secure your account now"
        ],
        "url_patterns": [
            "secure-", "-banking-", "account-verify", "login-security",
            "bank-verification", "secure-login"
        ],
        "threat_score": 85,
        "technique": "Urgency + Credential Harvesting"
    },
    2: {
        "category": "Banking Alert",
        "target": "Chase Bank",
        "subject_patterns": [
            "chase security alert", "chase account suspended", "chase verification needed",
            "your chase account has been locked", "chase fraud alert"
        ],
        "body_signatures": [
            "chase bank", "chase.com", "chase online", "chase security",
            "your chase account", "chase fraud department"
        ],
        "url_patterns": [
            "chase-secure", "chaseonline-verify", "chase-account-alert",
            "chasebank-login", "chase-verification"
        ],
        "threat_score": 90,
        "technique": "Brand Spoofing + Credential Harvesting"
    },
    3: {
        "category": "Banking Alert",
        "target": "Wells Fargo",
        "subject_patterns": [
            "wells fargo alert", "wells fargo account notice", "wells fargo verification",
            "unusual sign-in detected - wells fargo", "wells fargo security update"
        ],
        "body_signatures": [
            "wells fargo", "wellsfargo.com", "wells fargo online",
            "wells fargo security center", "your wells fargo account"
        ],
        "url_patterns": [
            "wellsfargo-verify", "wellsfargo-secure", "wells-fargo-alert",
            "wf-online-verify", "wellsfargo-security"
        ],
        "threat_score": 90,
        "technique": "Brand Spoofing + Urgency"
    },
    4: {
        "category": "Banking Alert",
        "target": "Bank of America",
        "subject_patterns": [
            "bank of america alert", "bofa security notice", "bank of america verification",
            "your bank of america account", "bofa fraud alert"
        ],
        "body_signatures": [
            "bank of america", "bankofamerica.com", "bofa",
            "bank of america security", "your bofa account"
        ],
        "url_patterns": [
            "bankofamerica-verify", "bofa-secure", "bank-america-alert",
            "bofa-online-verify", "bankofamerica-security"
        ],
        "threat_score": 88,
        "technique": "Brand Spoofing + Credential Harvesting"
    },
    5: {
        "category": "Banking Alert",
        "target": "Citibank",
        "subject_patterns": [
            "citibank security alert", "citi account notice", "citibank verification",
            "citi fraud department notice", "your citi account suspended"
        ],
        "body_signatures": [
            "citibank", "citi.com", "citi bank", "citi online",
            "citi security", "your citi account"
        ],
        "url_patterns": [
            "citi-verify", "citibank-secure", "citi-alert",
            "citi-online-verify", "citibank-security"
        ],
        "threat_score": 85,
        "technique": "Brand Spoofing + Urgency"
    },
    6: {
        "category": "Banking Alert",
        "target": "HSBC",
        "subject_patterns": [
            "hsbc security alert", "hsbc account verification", "hsbc fraud alert",
            "hsbc online banking notice", "your hsbc account"
        ],
        "body_signatures": [
            "hsbc", "hsbc.com", "hsbc bank", "hsbc online banking",
            "hsbc security", "hsbc fraud department"
        ],
        "url_patterns": [
            "hsbc-verify", "hsbc-secure", "hsbc-alert",
            "hsbc-online-verify", "hsbc-security-login"
        ],
        "threat_score": 83,
        "technique": "Brand Spoofing"
    },
    7: {
        "category": "Banking Alert",
        "target": "Barclays",
        "subject_patterns": [
            "barclays security alert", "barclays account notice", "barclays verification",
            "barclays online banking alert", "your barclays account"
        ],
        "body_signatures": [
            "barclays", "barclays.com", "barclays bank", "barclays online",
            "barclays security", "barclays fraud"
        ],
        "url_patterns": [
            "barclays-verify", "barclays-secure", "barclays-alert",
            "barclays-online-verify", "barclays-security"
        ],
        "threat_score": 82,
        "technique": "Brand Spoofing"
    },
    8: {
        "category": "Payment Alert",
        "target": "PayPal",
        "subject_patterns": [
            "paypal security alert", "paypal account limited", "paypal transaction dispute",
            "unusual activity on your paypal", "paypal verification required",
            "paypal account suspended", "confirm your paypal email"
        ],
        "body_signatures": [
            "paypal", "paypal.com", "paypal security", "paypal account",
            "your paypal account", "paypal resolution center", "paypal buyer protection"
        ],
        "url_patterns": [
            "paypal-verify", "paypal-secure", "paypal-alert",
            "paypal-login-verify", "paypal-dispute",
            "paypal-resolution", "paypal-confirm"
        ],
        "threat_score": 95,
        "technique": "Brand Spoofing + Credential Harvesting"
    },
    9: {
        "category": "Payment Alert",
        "target": "Venmo",
        "subject_patterns": [
            "venmo security alert", "venmo account notice", "venmo payment received",
            "venmo verification required", "venmo unauthorized transaction"
        ],
        "body_signatures": [
            "venmo", "venmo.com", "venmo account", "venmo payment",
            "venmo security", "venmo support"
        ],
        "url_patterns": [
            "venmo-verify", "venmo-secure", "venmo-login",
            "venmo-alert", "venmo-confirm"
        ],
        "threat_score": 88,
        "technique": "Brand Spoofing"
    },
    10: {
        "category": "Payment Alert",
        "target": "Stripe",
        "subject_patterns": [
            "stripe security alert", "stripe account notice", "stripe payment failed",
            "stripe verification required", "your stripe account"
        ],
        "body_signatures": [
            "stripe", "stripe.com", "stripe account", "stripe payment",
            "stripe dashboard", "stripe support"
        ],
        "url_patterns": [
            "stripe-verify", "stripe-secure", "stripe-login",
            "stripe-dashboard-verify", "stripe-alert"
        ],
        "threat_score": 80,
        "technique": "Brand Spoofing + Business Email Compromise"
    },
    11: {
        "category": "Payment Alert",
        "target": "Square",
        "subject_patterns": [
            "square security alert", "square account update", "square payment notice",
            "square verification", "your square account"
        ],
        "body_signatures": [
            "square", "squareup.com", "square account", "square payment",
            "square reader", "square support"
        ],
        "url_patterns": [
            "square-verify", "square-secure", "square-login",
            "squareup-verify", "square-alert"
        ],
        "threat_score": 78,
        "technique": "Brand Spoofing"
    },
    12: {
        "category": "Payment Alert",
        "target": "Western Union",
        "subject_patterns": [
            "western union transfer alert", "western union account notice",
            "money transfer pending", "western union verification"
        ],
        "body_signatures": [
            "western union", "westernunion.com", "money transfer",
            "western union account", "transfer confirmation"
        ],
        "url_patterns": [
            "westernunion-verify", "wu-secure", "western-union-alert",
            "money-transfer-verify", "wu-login"
        ],
        "threat_score": 80,
        "technique": "Urgency + Financial Scam"
    },
    13: {
        "category": "Payment Alert",
        "target": "MoneyGram",
        "subject_patterns": [
            "moneygram transfer notice", "moneygram account alert",
            "moneygram verification needed", "moneygram payment received"
        ],
        "body_signatures": [
            "moneygram", "moneygram.com", "money transfer",
            "moneygram account", "moneygram online"
        ],
        "url_patterns": [
            "moneygram-verify", "moneygram-secure", "mg-alert",
            "moneygram-login", "moneygram-transfer"
        ],
        "threat_score": 75,
        "technique": "Financial Scam"
    },
    14: {
        "category": "Investment Alert",
        "target": "Coinbase",
        "subject_patterns": [
            "coinbase security alert", "coinbase account notice",
            "coinbase login attempt", "coinbase verification needed",
            "your coinbase account"
        ],
        "body_signatures": [
            "coinbase", "coinbase.com", "coinbase account", "coinbase wallet",
            "coinbase security", "crypto wallet"
        ],
        "url_patterns": [
            "coinbase-verify", "coinbase-secure", "coinbase-login",
            "coinbase-alert", "coinbase-wallet-verify"
        ],
        "threat_score": 92,
        "technique": "Brand Spoofing + Cryptocurrency Theft"
    },
    15: {
        "category": "Investment Alert",
        "target": "Binance",
        "subject_patterns": [
            "binance security alert", "binance account notice",
            "binance withdrawal confirmation", "binance verification",
            "binance login from new device"
        ],
        "body_signatures": [
            "binance", "binance.com", "binance account", "binance wallet",
            "binance security", "binance support"
        ],
        "url_patterns": [
            "binance-verify", "binance-secure", "binance-login",
            "binance-alert", "binance-withdrawal"
        ],
        "threat_score": 90,
        "technique": "Brand Spoofing + Crypto Theft"
    },
    16: {
        "category": "Investment Alert",
        "target": "Kraken",
        "subject_patterns": [
            "kraken security alert", "kraken account notice",
            "kraken verification required", "kraken login attempt"
        ],
        "body_signatures": [
            "kraken", "kraken.com", "kraken account", "kraken pro",
            "kraken security"
        ],
        "url_patterns": [
            "kraken-verify", "kraken-secure", "kraken-login",
            "kraken-alert", "kraken-pro-verify"
        ],
        "threat_score": 82,
        "technique": "Brand Spoofing"
    },
    17: {
        "category": "Investment Alert",
        "target": "Robinhood",
        "subject_patterns": [
            "robinhood security alert", "robinhood account notice",
            "robinhood verification needed", "robinhood login alert"
        ],
        "body_signatures": [
            "robinhood", "robinhood.com", "robinhood account",
            "robinhood investing", "robinhood support"
        ],
        "url_patterns": [
            "robinhood-verify", "robinhood-secure", "robinhood-login",
            "robinhood-alert", "robinhood-account"
        ],
        "threat_score": 85,
        "technique": "Brand Spoofing"
    },
    18: {
        "category": "Investment Alert",
        "target": "ETrade",
        "subject_patterns": [
            "etrade security alert", "etrade account notice",
            "etrade verification required", "etrade login alert"
        ],
        "body_signatures": [
            "etrade", "etrade.com", "etrade account",
            "etrade financial", "etrade support"
        ],
        "url_patterns": [
            "etrade-verify", "etrade-secure", "etrade-login",
            "etrade-alert", "etrade-account-verify"
        ],
        "threat_score": 80,
        "technique": "Brand Spoofing"
    },
    19: {
        "category": "Investment Alert",
        "target": "TD Ameritrade",
        "subject_patterns": [
            "td ameritrade security alert", "td ameritrade account notice",
            "td ameritrade verification", "your td ameritrade account"
        ],
        "body_signatures": [
            "td ameritrade", "tdameritrade.com", "ameritrade account",
            "td ameritrade investing"
        ],
        "url_patterns": [
            "tdameritrade-verify", "ameritrade-secure",
            "tdameritrade-login", "td-ameritrade-alert"
        ],
        "threat_score": 78,
        "technique": "Brand Spoofing"
    },
    20: {
        "category": "Banking Alert",
        "target": "Capital One",
        "subject_patterns": [
            "capital one alert", "capital one account notice",
            "capital one fraud alert", "capital one verification"
        ],
        "body_signatures": [
            "capital one", "capitalone.com", "capital one account",
            "capital one 360", "capital one banking"
        ],
        "url_patterns": [
            "capitalone-verify", "capitalone-secure",
            "capital-one-alert", "capitalone-login"
        ],
        "threat_score": 85,
        "technique": "Brand Spoofing"
    },

    # ================================================================
    # CATEGORY 2: TECH & EMAIL SERVICES (Templates 21-35)
    # ================================================================
    21: {
        "category": "Email Account Alert",
        "target": "Gmail / Google",
        "subject_patterns": [
            "google security alert", "gmail account notice",
            "sign-in attempt blocked", "google account recovery",
            "your google account", "google verification code"
        ],
        "body_signatures": [
            "google", "gmail", "google account", "google workspace",
            "google security", "google drive", "google docs"
        ],
        "url_patterns": [
            "google-verify", "google-secure", "gmail-verify",
            "google-login", "google-account-alert",
            "google-docs-verify", "google-drive-share"
        ],
        "threat_score": 92,
        "technique": "Brand Spoofing + Credential Harvesting"
    },
    22: {
        "category": "Email Account Alert",
        "target": "Microsoft / Outlook",
        "subject_patterns": [
            "microsoft security alert", "outlook account notice",
            "microsoft account suspended", "verify your microsoft account",
            "unusual sign-in activity", "microsoft 365 alert"
        ],
        "body_signatures": [
            "microsoft", "outlook", "microsoft 365", "office 365",
            "microsoft account", "azure", "microsoft teams"
        ],
        "url_patterns": [
            "microsoft-verify", "outlook-secure", "microsoft-login",
            "office365-verify", "microsoft-alert",
            "microsoftonline-verify", "azure-login"
        ],
        "threat_score": 90,
        "technique": "Brand Spoofing + Credential Harvesting"
    },
    23: {
        "category": "Email Account Alert",
        "target": "Yahoo Mail",
        "subject_patterns": [
            "yahoo security alert", "yahoo mail notice",
            "yahoo account suspended", "yahoo verification required",
            "unusual sign-in on your yahoo account"
        ],
        "body_signatures": [
            "yahoo", "yahoo.com", "yahoo mail", "yahoo account",
            "yahoo security", "yahoo fantasy"
        ],
        "url_patterns": [
            "yahoo-verify", "yahoo-secure", "yahoo-login",
            "yahoo-mail-alert", "yahoo-account-verify"
        ],
        "threat_score": 82,
        "technique": "Brand Spoofing"
    },
    24: {
        "category": "Email Account Alert",
        "target": "ProtonMail",
        "subject_patterns": [
            "protonmail security alert", "proton account notice",
            "protonmail verification", "your proton account"
        ],
        "body_signatures": [
            "protonmail", "proton", "proton.me", "proton account",
            "protonmail security", "proton vpn"
        ],
        "url_patterns": [
            "proton-verify", "protonmail-secure", "proton-login",
            "proton-alert", "protonmail-account"
        ],
        "threat_score": 75,
        "technique": "Brand Spoofing"
    },
    25: {
        "category": "Cloud Storage Alert",
        "target": "Google Drive",
        "subject_patterns": [
            "someone shared a document", "google drive shared with you",
            "google drive storage full", "google docs shared",
            "google drive security alert"
        ],
        "body_signatures": [
            "google drive", "google docs", "google sheets",
            "shared a document", "shared a file", "view document"
        ],
        "url_patterns": [
            "google-drive-share", "docs-google-verify",
            "drive-google-login", "google-doc-share"
        ],
        "threat_score": 88,
        "technique": "Social Engineering + Malicious Link"
    },
    26: {
        "category": "Cloud Storage Alert",
        "target": "Dropbox",
        "subject_patterns": [
            "dropbox shared a file", "dropbox account notice",
            "dropbox storage full", "dropbox security alert",
            "dropbox suspicious activity"
        ],
        "body_signatures": [
            "dropbox", "dropbox.com", "dropbox account",
            "shared a file with you", "dropbox paper"
        ],
        "url_patterns": [
            "dropbox-verify", "dropbox-secure", "dropbox-login",
            "dropbox-share", "dropbox-alert"
        ],
        "threat_score": 85,
        "technique": "Social Engineering + Malicious Link"
    },
    27: {
        "category": "Cloud Storage Alert",
        "target": "OneDrive",
        "subject_patterns": [
            "onedrive shared a file", "microsoft onedrive alert",
            "onedrive security notice", "onedrive storage full"
        ],
        "body_signatures": [
            "onedrive", "onedrive.com", "microsoft onedrive",
            "shared a file", "onedrive for business"
        ],
        "url_patterns": [
            "onedrive-verify", "onedrive-secure", "onedrive-login",
            "onedrive-share", "onedrive-alert"
        ],
        "threat_score": 82,
        "technique": "Social Engineering"
    },
    28: {
        "category": "Cloud Storage Alert",
        "target": "iCloud",
        "subject_patterns": [
            "icloud storage full", "apple id account notice",
            "icloud security alert", "icloud verification needed",
            "your apple id was used to sign in"
        ],
        "body_signatures": [
            "icloud", "apple id", "apple.com", "icloud.com",
            "apple account", "apple support"
        ],
        "url_patterns": [
            "icloud-verify", "appleid-secure", "icloud-login",
            "apple-account-alert", "icloud-storage"
        ],
        "threat_score": 90,
        "technique": "Brand Spoofing + Credential Harvesting"
    },
    29: {
        "category": "Cloud Storage Alert",
        "target": "Box.com",
        "subject_patterns": [
            "box shared a file", "box account notice",
            "box security alert", "box document shared"
        ],
        "body_signatures": [
            "box", "box.com", "box account",
            "shared a file with you", "box secure"
        ],
        "url_patterns": [
            "box-verify", "box-secure", "box-login",
            "box-share", "box-alert"
        ],
        "threat_score": 72,
        "technique": "Social Engineering"
    },
    30: {
        "category": "Tech Support",
        "target": "Microsoft Support",
        "subject_patterns": [
            "microsoft support alert", "windows security warning",
            "your computer has a virus", "microsoft tech support",
            "windows license expired"
        ],
        "body_signatures": [
            "microsoft support", "windows defender", "windows security",
            "computer virus detected", "tech support",
            "call us immediately", "your computer is compromised"
        ],
        "url_patterns": [
            "microsoft-support", "windows-security-verify",
            "microsoft-tech-support", "windows-defender-alert"
        ],
        "threat_score": 95,
        "technique": "Tech Support Scam + Fake Antivirus"
    },
    31: {
        "category": "Tech Support",
        "target": "Apple Support",
        "subject_patterns": [
            "apple support alert", "your apple id has been compromised",
            "icloud security breach", "apple security warning",
            "your device has been infected"
        ],
        "body_signatures": [
            "apple support", "apple security", "apple id compromised",
            "your iphone has a virus", "call apple support"
        ],
        "url_patterns": [
            "apple-support-verify", "appleid-secure-alert",
            "apple-security-warning", "icloud-alert"
        ],
        "threat_score": 92,
        "technique": "Tech Support Scam"
    },
    32: {
        "category": "Tech Support",
        "target": "Generic PC Support",
        "subject_patterns": [
            "your computer has been hacked", "virus detected alert",
            "windows security warning", "your ip address has been compromised",
            "your internet security is expired"
        ],
        "body_signatures": [
            "your computer", "virus detected", "security warning",
            "ip address compromised", "call immediately",
            "do not shut down", "unauthorized access detected"
        ],
        "url_patterns": [
            "pc-security-alert", "virus-scan-now",
            "computer-security-warning", "system-alert"
        ],
        "threat_score": 90,
        "technique": "Tech Support Scam + Fear Tactics"
    },
    33: {
        "category": "Email Account Alert",
        "target": "AOL Mail",
        "subject_patterns": [
            "aol security alert", "aol mail account notice",
            "aol account verification", "your aol account"
        ],
        "body_signatures": [
            "aol", "aol.com", "aol mail", "aol account",
            "aol security"
        ],
        "url_patterns": [
            "aol-verify", "aol-secure", "aol-login",
            "aol-mail-alert", "aol-account"
        ],
        "threat_score": 70,
        "technique": "Brand Spoofing"
    },
    34: {
        "category": "Email Account Alert",
        "target": "Zoho Mail",
        "subject_patterns": [
            "zoho security alert", "zoho mail account notice",
            "zoho account verification", "your zoho account"
        ],
        "body_signatures": [
            "zoho", "zoho.com", "zoho mail", "zoho account",
            "zoho crm"
        ],
        "url_patterns": [
            "zoho-verify", "zoho-secure", "zoho-login",
            "zoho-mail-alert", "zoho-account"
        ],
        "threat_score": 65,
        "technique": "Brand Spoofing"
    },
    35: {
        "category": "Email Account Alert",
        "target": "GMX Mail",
        "subject_patterns": [
            "gmx security alert", "gmx mail account notice",
            "gmx account verification", "your gmx account"
        ],
        "body_signatures": [
            "gmx", "gmx.com", "gmx mail", "gmx account"
        ],
        "url_patterns": [
            "gmx-verify", "gmx-secure", "gmx-login",
            "gmx-mail-alert"
        ],
        "threat_score": 60,
        "technique": "Brand Spoofing"
    },

    # ================================================================
    # CATEGORY 3: SOCIAL MEDIA (Templates 36-50)
    # ================================================================
    36: {
        "category": "Social Media Alert",
        "target": "Facebook",
        "subject_patterns": [
            "facebook security alert", "facebook account suspended",
            "someone tried to log into your facebook",
            "facebook verification required", "facebook copyright violation"
        ],
        "body_signatures": [
            "facebook", "facebook.com", "meta", "facebook account",
            "facebook security", "facebook marketplace"
        ],
        "url_patterns": [
            "facebook-verify", "facebook-secure", "facebook-login",
            "fb-security-alert", "facebook-account-verify",
            "meta-verify"
        ],
        "threat_score": 88,
        "technique": "Brand Spoofing + Credential Harvesting"
    },
    37: {
        "category": "Social Media Alert",
        "target": "Instagram",
        "subject_patterns": [
            "instagram security alert", "instagram account suspended",
            "instagram verification badge", "instagram login attempt",
            "your instagram account"
        ],
        "body_signatures": [
            "instagram", "instagram.com", "ig", "instagram account",
            "instagram security", "instagram support"
        ],
        "url_patterns": [
            "instagram-verify", "instagram-secure", "instagram-login",
            "ig-security-alert", "instagram-account"
        ],
        "threat_score": 87,
        "technique": "Brand Spoofing"
    },
    38: {
        "category": "Social Media Alert",
        "target": "Twitter / X",
        "subject_patterns": [
            "twitter security alert", "x security notice",
            "twitter account suspended", "twitter verification",
            "suspicious login on your twitter account"
        ],
        "body_signatures": [
            "twitter", "x.com", "twitter.com", "twitter account",
            "x account", "twitter security"
        ],
        "url_patterns": [
            "twitter-verify", "x-secure", "twitter-login",
            "twitter-alert", "x-account-verify"
        ],
        "threat_score": 85,
        "technique": "Brand Spoofing"
    },
    39: {
        "category": "Social Media Alert",
        "target": "LinkedIn",
        "subject_patterns": [
            "linkedin security alert", "linkedin account notice",
            "you have a new connection request",
            "linkedin verification required",
            "your linkedin account has been limited"
        ],
        "body_signatures": [
            "linkedin", "linkedin.com", "linkedin account",
            "linkedin recruiter", "linkedin security",
            "connection request", "profile view"
        ],
        "url_patterns": [
            "linkedin-verify", "linkedin-secure", "linkedin-login",
            "linkedin-alert", "linkedin-account"
        ],
        "threat_score": 82,
        "technique": "Brand Spoofing + Social Engineering"
    },
    40: {
        "category": "Social Media Alert",
        "target": "Snapchat",
        "subject_patterns": [
            "snapchat security alert", "snapchat account notice",
            "snapchat login attempt", "snapchat verification"
        ],
        "body_signatures": [
            "snapchat", "snapchat.com", "snapchat account",
            "snapchat security", "snap"
        ],
        "url_patterns": [
            "snapchat-verify", "snapchat-secure", "snapchat-login",
            "snapchat-alert", "snapchat-account"
        ],
        "threat_score": 78,
        "technique": "Brand Spoofing"
    },
    41: {
        "category": "Social Media Alert",
        "target": "TikTok",
        "subject_patterns": [
            "tiktok security alert", "tiktok account notice",
            "tiktok login attempt", "tiktok verification",
            "tiktok follower alert"
        ],
        "body_signatures": [
            "tiktok", "tiktok.com", "tiktok account",
            "tiktok security", "tiktok for business"
        ],
        "url_patterns": [
            "tiktok-verify", "tiktok-secure", "tiktok-login",
            "tiktok-alert", "tiktok-account"
        ],
        "threat_score": 80,
        "technique": "Brand Spoofing"
    },
    42: {
        "category": "Social Media Alert",
        "target": "Reddit",
        "subject_patterns": [
            "reddit security alert", "reddit account notice",
            "reddit login attempt", "reddit verification"
        ],
        "body_signatures": [
            "reddit", "reddit.com", "reddit account",
            "reddit security", "reddit gold"
        ],
        "url_patterns": [
            "reddit-verify", "reddit-secure", "reddit-login",
            "reddit-alert", "reddit-account"
        ],
        "threat_score": 72,
        "technique": "Brand Spoofing"
    },
    43: {
        "category": "Social Media Alert",
        "target": "Pinterest",
        "subject_patterns": [
            "pinterest security alert", "pinterest account notice",
            "pinterest login attempt", "pinterest verification"
        ],
        "body_signatures": [
            "pinterest", "pinterest.com", "pinterest account",
            "pinterest security"
        ],
        "url_patterns": [
            "pinterest-verify", "pinterest-secure", "pinterest-login",
            "pinterest-alert"
        ],
        "threat_score": 68,
        "technique": "Brand Spoofing"
    },
    44: {
        "category": "Social Media Alert",
        "target": "Telegram",
        "subject_patterns": [
            "telegram security alert", "telegram account notice",
            "telegram login code", "telegram verification"
        ],
        "body_signatures": [
            "telegram", "telegram.org", "telegram account",
            "telegram security", "telegram messenger"
        ],
        "url_patterns": [
            "telegram-verify", "telegram-secure", "telegram-login",
            "telegram-alert", "telegram-account"
        ],
        "threat_score": 75,
        "technique": "Brand Spoofing"
    },
    45: {
        "category": "Social Media Alert",
        "target": "Discord",
        "subject_patterns": [
            "discord security alert", "discord account notice",
            "discord login attempt", "discord verification",
            "discord nitro gift"
        ],
        "body_signatures": [
            "discord", "discord.com", "discord account",
            "discord nitro", "discord security",
            "discord server"
        ],
        "url_patterns": [
            "discord-verify", "discord-secure", "discord-login",
            "discord-alert", "discord-nitro-free"
        ],
        "threat_score": 85,
        "technique": "Brand Spoofing + Gift Scam"
    },
    46: {
        "category": "Social Media Alert",
        "target": "WhatsApp",
        "subject_patterns": [
            "whatsapp security alert", "whatsapp account notice",
            "whatsapp verification code", "whatsapp web login",
            "whatsapp account suspended"
        ],
        "body_signatures": [
            "whatsapp", "whatsapp.com", "whatsapp account",
            "whatsapp web", "whatsapp business",
            "whatsapp security"
        ],
        "url_patterns": [
            "whatsapp-verify", "whatsapp-secure", "whatsapp-login",
            "whatsapp-web-verify", "whatsapp-alert"
        ],
        "threat_score": 86,
        "technique": "Brand Spoofing + Account Takeover"
    },
    47: {
        "category": "Social Media Alert",
        "target": "Signal",
        "subject_patterns": [
            "signal security alert", "signal account notice",
            "signal verification code", "signal login attempt"
        ],
        "body_signatures": [
            "signal", "signal.org", "signal account",
            "signal messenger", "signal security"
        ],
        "url_patterns": [
            "signal-verify", "signal-secure", "signal-login",
            "signal-alert", "signal-account"
        ],
        "threat_score": 65,
        "technique": "Brand Spoofing"
    },
    48: {
        "category": "Social Media Alert",
        "target": "WeChat",
        "subject_patterns": [
            "wechat security alert", "wechat account notice",
            "wechat verification", "wechat login attempt"
        ],
        "body_signatures": [
            "wechat", "wechat.com", "wechat account",
            "wechat security", "wechat pay"
        ],
        "url_patterns": [
            "wechat-verify", "wechat-secure", "wechat-login",
            "wechat-alert", "wechat-account"
        ],
        "threat_score": 70,
        "technique": "Brand Spoofing"
    },
    49: {
        "category": "Social Media Alert",
        "target": "OnlyFans",
        "subject_patterns": [
            "onlyfans security alert", "onlyfans account notice",
            "onlyfans login attempt", "onlyfans verification"
        ],
        "body_signatures": [
            "onlyfans", "onlyfans.com", "onlyfans account",
            "onlyfans security", "onlyfans creator"
        ],
        "url_patterns": [
            "onlyfans-verify", "onlyfans-secure", "onlyfans-login",
            "onlyfans-alert", "onlyfans-account"
        ],
        "threat_score": 72,
        "technique": "Brand Spoofing"
    },
    50: {
        "category": "Social Media Alert",
        "target": "Medium",
        "subject_patterns": [
            "medium security alert", "medium account notice",
            "medium login attempt", "medium verification"
        ],
        "body_signatures": [
            "medium", "medium.com", "medium account",
            "medium security", "medium member"
        ],
        "url_patterns": [
            "medium-verify", "medium-secure", "medium-login",
            "medium-alert", "medium-account"
        ],
        "threat_score": 55,
        "technique": "Brand Spoofing"
    },

    # ================================================================
    # CATEGORY 4: E-COMMERCE (Templates 51-65)
    # ================================================================
    51: {
        "category": "E-Commerce Alert",
        "target": "Amazon",
        "subject_patterns": [
            "amazon order confirmation", "amazon account alert",
            "amazon login attempt", "amazon verification required",
            "your amazon account has been compromised",
            "amazon prime renewal"
        ],
        "body_signatures": [
            "amazon", "amazon.com", "amazon account",
            "amazon prime", "amazon order", "amazon pay",
            "amazon customer service"
        ],
        "url_patterns": [
            "amazon-verify", "amazon-secure", "amazon-login",
            "amazon-alert", "amazon-account",
            "amazon-prime-verify", "amazon-pay-alert"
        ],
        "threat_score": 92,
        "technique": "Brand Spoofing + Credential Harvesting"
    },
    52: {
        "category": "E-Commerce Alert",
        "target": "eBay",
        "subject_patterns": [
            "ebay security alert", "ebay account notice",
            "ebay bid confirmation", "ebay verification required",
            "your ebay account has been compromised"
        ],
        "body_signatures": [
            "ebay", "ebay.com", "ebay account",
            "ebay security", "ebay seller", "ebay buyer"
        ],
        "url_patterns": [
            "ebay-verify", "ebay-secure", "ebay-login",
            "ebay-alert", "ebay-account"
        ],
        "threat_score": 85,
        "technique": "Brand Spoofing"
    },
    53: {
        "category": "E-Commerce Alert",
        "target": "Walmart",
        "subject_patterns": [
            "walmart order confirmation", "walmart account alert",
            "walmart verification", "your walmart account"
        ],
        "body_signatures": [
            "walmart", "walmart.com", "walmart account",
            "walmart order", "walmart pay"
        ],
        "url_patterns": [
            "walmart-verify", "walmart-secure", "walmart-login",
            "walmart-alert", "walmart-account"
        ],
        "threat_score": 82,
        "technique": "Brand Spoofing"
    },
    54: {
        "category": "E-Commerce Alert",
        "target": "Target",
        "subject_patterns": [
            "target order confirmation", "target account alert",
            "target verification", "your target account"
        ],
        "body_signatures": [
            "target", "target.com", "target account",
            "target order", "target redcard"
        ],
        "url_patterns": [
            "target-verify", "target-secure", "target-login",
            "target-alert", "target-account"
        ],
        "threat_score": 78,
        "technique": "Brand Spoofing"
    },
    55: {
        "category": "E-Commerce Alert",
        "target": "Best Buy",
        "subject_patterns": [
            "best buy order confirmation", "best buy account alert",
            "best buy verification", "best buy reward zone"
        ],
        "body_signatures": [
            "best buy", "bestbuy.com", "best buy account",
            "best buy order", "best buy rewards"
        ],
        "url_patterns": [
            "bestbuy-verify", "bestbuy-secure", "bestbuy-login",
            "bestbuy-alert", "bestbuy-account"
        ],
        "threat_score": 75,
        "technique": "Brand Spoofing"
    },
    56: {
        "category": "E-Commerce Alert",
        "target": "Shopify",
        "subject_patterns": [
            "shopify order notification", "shopify account alert",
            "shopify login attempt", "your shopify store"
        ],
        "body_signatures": [
            "shopify", "shopify.com", "shopify account",
            "shopify store", "shopify admin", "shopify payments"
        ],
        "url_patterns": [
            "shopify-verify", "shopify-secure", "shopify-login",
            "shopify-alert", "shopify-admin"
        ],
        "threat_score": 80,
        "technique": "Brand Spoofing + Business Email Compromise"
    },
    57: {
        "category": "E-Commerce Alert",
        "target": "Etsy",
        "subject_patterns": [
            "etsy order confirmation", "etsy account alert",
            "etsy verification", "etsy purchase notification"
        ],
        "body_signatures": [
            "etsy", "etsy.com", "etsy account",
            "etsy order", "etsy seller", "etsy buyer"
        ],
        "url_patterns": [
            "etsy-verify", "etsy-secure", "etsy-login",
            "etsy-alert", "etsy-account"
        ],
        "threat_score": 72,
        "technique": "Brand Spoofing"
    },
    58: {
        "category": "E-Commerce Alert",
        "target": "Alibaba",
        "subject_patterns": [
            "alibaba order confirmation", "alibaba account alert",
            "alibaba verification", "alibaba trade assurance"
        ],
        "body_signatures": [
            "alibaba", "alibaba.com", "alibaba account",
            "alibaba order", "alibaba trade"
        ],
        "url_patterns": [
            "alibaba-verify", "alibaba-secure", "alibaba-login",
            "alibaba-alert", "alibaba-account"
        ],
        "threat_score": 76,
        "technique": "Brand Spoofing + Business Scam"
    },
    59: {
        "category": "E-Commerce Alert",
        "target": "AliExpress",
        "subject_patterns": [
            "aliexpress order confirmation", "aliexpress account alert",
            "aliexpress verification", "aliexpress coupon"
        ],
        "body_signatures": [
            "aliexpress", "aliexpress.com", "aliexpress account",
            "aliexpress order"
        ],
        "url_patterns": [
            "aliexpress-verify", "aliexpress-secure", "aliexpress-login",
            "aliexpress-alert"
        ],
        "threat_score": 74,
        "technique": "Brand Spoofing"
    },
    60: {
        "category": "E-Commerce Alert",
        "target": "Groupon",
        "subject_patterns": [
            "groupon deal alert", "groupon account notice",
            "groupon verification", "groupon coupon"
        ],
        "body_signatures": [
            "groupon", "groupon.com", "groupon account",
            "groupon deal"
        ],
        "url_patterns": [
            "groupon-verify", "groupon-secure", "groupon-login",
            "groupon-alert"
        ],
        "threat_score": 68,
        "technique": "Brand Spoofing"
    },
    61: {
        "category": "E-Commerce Alert",
        "target": "Kickstarter",
        "subject_patterns": [
            "kickstarter pledge confirmation", "kickstarter account alert",
            "kickstarter verification", "kickstarter project"
        ],
        "body_signatures": [
            "kickstarter", "kickstarter.com", "kickstarter account",
            "kickstarter project"
        ],
        "url_patterns": [
            "kickstarter-verify", "kickstarter-secure", "kickstarter-login",
            "kickstarter-alert"
        ],
        "threat_score": 60,
        "technique": "Brand Spoofing"
    },
    62: {
        "category": "E-Commerce Alert",
        "target": "Craigslist",
        "subject_patterns": [
            "craigslist reply notification", "craigslist account alert",
            "craigslist verification", "craigslist scam alert"
        ],
        "body_signatures": [
            "craigslist", "craigslist.org", "craigslist account"
        ],
        "url_patterns": [
            "craigslist-verify", "craigslist-secure", "craigslist-login"
        ],
        "threat_score": 65,
        "technique": "Scam"
    },
    63: {
        "category": "E-Commerce Alert",
        "target": "Booking.com",
        "subject_patterns": [
            "booking.com reservation confirmed", "booking account alert",
            "booking verification", "booking payment required"
        ],
        "body_signatures": [
            "booking.com", "booking", "booking account",
            "reservation", "booking confirmation"
        ],
        "url_patterns": [
            "booking-verify", "booking-secure", "booking-login",
            "booking-payment", "booking-alert"
        ],
        "threat_score": 80,
        "technique": "Brand Spoofing + Payment Scam"
    },
    64: {
        "category": "E-Commerce Alert",
        "target": "Airbnb",
        "subject_patterns": [
            "airbnb booking confirmed", "airbnb account alert",
            "airbnb verification", "airbnb payment required"
        ],
        "body_signatures": [
            "airbnb", "airbnb.com", "airbnb account",
            "airbnb booking", "airbnb host"
        ],
        "url_patterns": [
            "airbnb-verify", "airbnb-secure", "airbnb-login",
            "airbnb-payment", "airbnb-alert"
        ],
        "threat_score": 82,
        "technique": "Brand Spoofing + Payment Scam"
    },
    65: {
        "category": "E-Commerce Alert",
        "target": "Uber Eats",
        "subject_patterns": [
            "uber eats order confirmation", "uber eats account alert",
            "uber eats verification", "uber eats promo"
        ],
        "body_signatures": [
            "uber eats", "ubereats.com", "uber eats account",
            "uber eats order"
        ],
        "url_patterns": [
            "ubereats-verify", "ubereats-secure", "ubereats-login",
            "ubereats-alert"
        ],
        "threat_score": 72,
        "technique": "Brand Spoofing"
    },

    # ================================================================
    # CATEGORY 5: STREAMING & MEDIA (Templates 66-75)
    # ================================================================
    66: {
        "category": "Streaming Alert",
        "target": "Netflix",
        "subject_patterns": [
            "netflix account suspended", "netflix payment failed",
            "netflix verification required", "your netflix account",
            "netflix subscription cancelled", "netflix security alert"
        ],
        "body_signatures": [
            "netflix", "netflix.com", "netflix account",
            "netflix payment", "netflix subscription",
            "netflix security"
        ],
        "url_patterns": [
            "netflix-verify", "netflix-secure", "netflix-login",
            "netflix-alert", "netflix-account",
            "netflix-payment-update"
        ],
        "threat_score": 92,
        "technique": "Brand Spoofing + Credential Harvesting"
    },
    67: {
        "category": "Streaming Alert",
        "target": "Hulu",
        "subject_patterns": [
            "hulu account suspended", "hulu payment failed",
            "hulu verification", "your hulu account"
        ],
        "body_signatures": [
            "hulu", "hulu.com", "hulu account",
            "hulu payment", "hulu subscription"
        ],
        "url_patterns": [
            "hulu-verify", "hulu-secure", "hulu-login",
            "hulu-alert", "hulu-account"
        ],
        "threat_score": 80,
        "technique": "Brand Spoofing"
    },
    68: {
        "category": "Streaming Alert",
        "target": "Disney+",
        "subject_patterns": [
            "disney+ account suspended", "disney+ payment failed",
            "disney+ verification", "your disney+ account"
        ],
        "body_signatures": [
            "disney+", "disneyplus.com", "disney plus",
            "disney+ account", "disney+ subscription"
        ],
        "url_patterns": [
            "disneyplus-verify", "disneyplus-secure",
            "disneyplus-login", "disneyplus-alert"
        ],
        "threat_score": 84,
        "technique": "Brand Spoofing"
    },
    69: {
        "category": "Streaming Alert",
        "target": "Spotify",
        "subject_patterns": [
            "spotify account suspended", "spotify payment failed",
            "spotify premium alert", "spotify verification"
        ],
        "body_signatures": [
            "spotify", "spotify.com", "spotify account",
            "spotify premium", "spotify payment"
        ],
        "url_patterns": [
            "spotify-verify", "spotify-secure", "spotify-login",
            "spotify-alert", "spotify-premium"
        ],
        "threat_score": 82,
        "technique": "Brand Spoofing"
    },
    70: {
        "category": "Streaming Alert",
        "target": "YouTube",
        "subject_patterns": [
            "youtube copyright strike", "youtube account suspended",
            "youtube verification", "youtube monetization alert",
            "your youtube channel"
        ],
        "body_signatures": [
            "youtube", "youtube.com", "youtube account",
            "youtube channel", "youtube studio",
            "youtube copyright", "youtube monetization"
        ],
        "url_patterns": [
            "youtube-verify", "youtube-secure", "youtube-login",
            "youtube-alert", "youtube-studio",
            "youtube-copyright"
        ],
        "threat_score": 86,
        "technique": "Brand Spoofing + Copyright Scam"
    },
    71: {
        "category": "Streaming Alert",
        "target": "Twitch",
        "subject_patterns": [
            "twitch account suspended", "twitch verification",
            "twitch partnership alert", "twitch login attempt"
        ],
        "body_signatures": [
            "twitch", "twitch.tv", "twitch account",
            "twitch streamer", "twitch partnership"
        ],
        "url_patterns": [
            "twitch-verify", "twitch-secure", "twitch-login",
            "twitch-alert", "twitch-account"
        ],
        "threat_score": 78,
        "technique": "Brand Spoofing"
    },
    72: {
        "category": "Streaming Alert",
        "target": "HBO Max",
        "subject_patterns": [
            "hbo max account suspended", "hbo max payment",
            "hbo max verification", "your hbo max account"
        ],
        "body_signatures": [
            "hbo max", "hbomax.com", "hbo max account",
            "hbo max subscription"
        ],
        "url_patterns": [
            "hbomax-verify", "hbomax-secure", "hbomax-login",
            "hbomax-alert"
        ],
        "threat_score": 76,
        "technique": "Brand Spoofing"
    },
    73: {
        "category": "Streaming Alert",
        "target": "Apple Music",
        "subject_patterns": [
            "apple music payment failed", "apple music account",
            "apple music verification", "apple id music alert"
        ],
        "body_signatures": [
            "apple music", "apple.com", "apple music account",
            "apple id", "apple subscription"
        ],
        "url_patterns": [
            "applemusic-verify", "apple-secure", "appleid-login",
            "apple-music-alert"
        ],
        "threat_score": 82,
        "technique": "Brand Spoofing"
    },
    74: {
        "category": "Streaming Alert",
        "target": "Amazon Prime Video",
        "subject_patterns": [
            "prime video payment failed", "prime video account",
            "amazon prime alert", "prime video verification"
        ],
        "body_signatures": [
            "prime video", "amazon prime", "primevideo.com",
            "prime video account"
        ],
        "url_patterns": [
            "primevideo-verify", "primevideo-secure",
            "primevideo-login", "primevideo-alert"
        ],
        "threat_score": 80,
        "technique": "Brand Spoofing"
    },
    75: {
        "category": "Streaming Alert",
        "target": "Paramount+",
        "subject_patterns": [
            "paramount+ account suspended", "paramount+ payment",
            "paramount+ verification", "your paramount+ account"
        ],
        "body_signatures": [
            "paramount+", "paramountplus.com", "paramount plus",
            "paramount+ account"
        ],
        "url_patterns": [
            "paramountplus-verify", "paramountplus-secure",
            "paramountplus-login", "paramountplus-alert"
        ],
        "threat_score": 70,
        "technique": "Brand Spoofing"
    },

    # ================================================================
    # CATEGORY 6: GOVERNMENT & TAX (Templates 76-85)
    # ================================================================
    76: {
        "category": "Government Alert",
        "target": "IRS (Tax)",
        "subject_patterns": [
            "irs tax refund alert", "irs notice", "tax refund pending",
            "irs tax return verification", "irs alert - immediate action required",
            "your tax refund is on hold"
        ],
        "body_signatures": [
            "irs", "internal revenue service", "tax refund",
            "tax return", "irs.gov", "taxpayer",
            "refund pending", "tax audit"
        ],
        "url_patterns": [
            "irs-verify", "irs-gov-alert", "tax-refund-verify",
            "irs-tax-return", "irs-notice"
        ],
        "threat_score": 95,
        "technique": "Government Impersonation + Fear Tactics"
    },
    77: {
        "category": "Government Alert",
        "target": "Social Security Administration",
        "subject_patterns": [
            "social security alert", "ssa notice", "social security number suspended",
            "ssa benefits alert", "social security verification"
        ],
        "body_signatures": [
            "social security", "ssa", "social security administration",
            "social security number", "ssa.gov", "benefits"
        ],
        "url_patterns": [
            "ssa-verify", "socialsecurity-alert", "ssa-benefits",
            "socialsecurity-verify", "ssa-notice"
        ],
        "threat_score": 93,
        "technique": "Government Impersonation + Identity Theft"
    },
    78: {
        "category": "Government Alert",
        "target": "USPS",
        "subject_patterns": [
            "usps package delivery", "usps delivery failed",
            "usps tracking alert", "usps package held",
            "usps shipping confirmation"
        ],
        "body_signatures": [
            "usps", "united states postal service", "usps.com",
            "package delivery", "tracking number",
            "shipping confirmation", "delivery failed"
        ],
        "url_patterns": [
            "usps-verify", "usps-tracking", "usps-delivery",
            "usps-package", "usps-alert"
        ],
        "threat_score": 90,
        "technique": "Brand Spoofing + Package Delivery Scam"
    },
    79: {
        "category": "Government Alert",
        "target": "UPS",
        "subject_patterns": [
            "ups delivery notification", "ups package alert",
            "ups delivery failed", "ups tracking update",
            "ups shipping label"
        ],
        "body_signatures": [
            "ups", "united parcel service", "ups.com",
            "package delivery", "tracking number",
            "ups delivery"
        ],
        "url_patterns": [
            "ups-verify", "ups-tracking", "ups-delivery",
            "ups-package", "ups-alert"
        ],
        "threat_score": 88,
        "technique": "Brand Spoofing + Delivery Scam"
    },
    80: {
        "category": "Government Alert",
        "target": "FedEx",
        "subject_patterns": [
            "fedex delivery notification", "fedex package alert",
            "fedex delivery failed", "fedex tracking update"
        ],
        "body_signatures": [
            "fedex", "fedex.com", "fedex delivery",
            "package delivery", "tracking number"
        ],
        "url_patterns": [
            "fedex-verify", "fedex-tracking", "fedex-delivery",
            "fedex-package", "fedex-alert"
        ],
        "threat_score": 85,
        "technique": "Brand Spoofing + Delivery Scam"
    },
    81: {
        "category": "Government Alert",
        "target": "DHL",
        "subject_patterns": [
            "dhl delivery notification", "dhl package alert",
            "dhl delivery failed", "dhl tracking update"
        ],
        "body_signatures": [
            "dhl", "dhl.com", "dhl delivery",
            "dhl express", "package delivery"
        ],
        "url_patterns": [
            "dhl-verify", "dhl-tracking", "dhl-delivery",
            "dhl-package", "dhl-alert"
        ],
        "threat_score": 82,
        "technique": "Brand Spoofing + Delivery Scam"
    },
    82: {
        "category": "Government Alert",
        "target": "Medicare",
        "subject_patterns": [
            "medicare alert", "medicare benefits update",
            "medicare card verification", "medicare notice"
        ],
        "body_signatures": [
            "medicare", "medicare.gov", "medicare benefits",
            "medicare card", "centers for medicare"
        ],
        "url_patterns": [
            "medicare-verify", "medicare-alert", "medicare-benefits",
            "medicare-notice", "medicare-card"
        ],
        "threat_score": 88,
        "technique": "Government Impersonation + Identity Theft"
    },
    83: {
        "category": "Government Alert",
        "target": "Unemployment Benefits",
        "subject_patterns": [
            "unemployment benefits alert", "ui claim notice",
            "unemployment verification", "benefits update"
        ],
        "body_signatures": [
            "unemployment", "benefits", "claim",
            "unemployment insurance", "department of labor"
        ],
        "url_patterns": [
            "unemployment-verify", "benefits-alert", "ui-claim",
            "unemployment-notice"
        ],
        "threat_score": 85,
        "technique": "Government Impersonation + Benefits Theft"
    },
    84: {
        "category": "Government Alert",
        "target": "FBI / Cybercrime",
        "subject_patterns": [
            "fbi cybercrime alert", "your ip address detected",
            "cyber crime investigation", "fbi notice"
        ],
        "body_signatures": [
            "fbi", "federal bureau of investigation", "cybercrime",
            "ip address", "illegal activity", "investigation"
        ],
        "url_patterns": [
            "fbi-alert", "cybercrime-notice", "fbi-investigation",
            "ip-detected-alert"
        ],
        "threat_score": 95,
        "technique": "Government Impersonation + Fear & Intimidation"
    },
    85: {
        "category": "Government Alert",
        "target": "Court / Legal Notice",
        "subject_patterns": [
            "court summons notice", "legal action pending",
            "lawsuit filed against you", "subpoena notice",
            "legal document awaiting your response"
        ],
        "body_signatures": [
            "court", "lawsuit", "legal action",
            "subpoena", "summons", "attorney general",
            "legal notice", "litigation"
        ],
        "url_patterns": [
            "court-notice", "legal-action-alert", "subpoena-verify",
            "lawsuit-notice", "legal-document"
        ],
        "threat_score": 92,
        "technique": "Legal Scam + Fear Tactics"
    },

    # ================================================================
    # CATEGORY 7: SOFTWARE & SUBSCRIPTIONS (Templates 86-95)
    # ================================================================
    86: {
        "category": "Software Alert",
        "target": "Adobe",
        "subject_patterns": [
            "adobe account suspended", "adobe subscription expired",
            "adobe verification required", "adobe creative cloud alert",
            "your adobe account"
        ],
        "body_signatures": [
            "adobe", "adobe.com", "adobe creative cloud",
            "adobe account", "adobe subscription",
            "adobe acrobat", "adobe photoshop"
        ],
        "url_patterns": [
            "adobe-verify", "adobe-secure", "adobe-login",
            "adobe-cc-alert", "adobe-account"
        ],
        "threat_score": 82,
        "technique": "Brand Spoofing"
    },
    87: {
        "category": "Software Alert",
        "target": "Microsoft 365",
        "subject_patterns": [
            "microsoft 365 subscription expired", "office 365 alert",
            "microsoft 365 payment failed", "microsoft 365 verification"
        ],
        "body_signatures": [
            "microsoft 365", "office 365", "microsoft subscription",
            "microsoft account", "office subscription"
        ],
        "url_patterns": [
            "microsoft365-verify", "office365-secure",
            "microsoft-subscription", "office365-alert"
        ],
        "threat_score": 85,
        "technique": "Brand Spoofing"
    },
    88: {
        "category": "Software Alert",
        "target": "Norton Antivirus",
        "subject_patterns": [
            "norton subscription expired", "norton security alert",
            "your norton protection has expired", "norton renewal"
        ],
        "body_signatures": [
            "norton", "norton.com", "norton security",
            "norton antivirus", "norton subscription"
        ],
        "url_patterns": [
            "norton-verify", "norton-secure", "norton-login",
            "norton-renewal", "norton-alert"
        ],
        "threat_score": 78,
        "technique": "Brand Spoofing + Fake Renewal"
    },
    89: {
        "category": "Software Alert",
        "target": "McAfee",
        "subject_patterns": [
            "mcafee subscription expired", "mcafee security alert",
            "mcafee protection expired", "mcafee renewal"
        ],
        "body_signatures": [
            "mcafee", "mcafee.com", "mcafee security",
            "mcafee antivirus", "mcafee subscription"
        ],
        "url_patterns": [
            "mcafee-verify", "mcafee-secure", "mcafee-login",
            "mcafee-renewal", "mcafee-alert"
        ],
        "threat_score": 76,
        "technique": "Brand Spoofing + Fake Renewal"
    }
}

# Threat score ranges
THREAT_LEVELS = {
    "CRITICAL": (85, 100),
    "HIGH": (70, 84),
    "MEDIUM": (50, 69),
    "LOW": (0, 49)
}

# Common phishing keywords
PHISHING_KEYWORDS = {
    "urgency": ["urgent", "immediate", "now", "immediately", "asap"],
    "verification": ["verify", "confirm", "validate", "authenticate"],
    "account": ["account", "suspended", "locked", "limited"],
    "security": ["security", "alert", "threat", "malware"],
    "payment": ["billing", "payment", "card", "credit"]
}

# Suspicious TLDs
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "top", "xyz", "work", "download", "review"
}

# Legitimate domains
LEGITIMATE_DOMAINS = {
    "google.com", "amazon.com", "facebook.com", "microsoft.com",
    "apple.com", "paypal.com", "linkedin.com"
}

def get_template(template_id):
    """Get a template by ID."""
    return PHISHING_TEMPLATES.get(template_id)

def get_all_templates():
    """Get all templates."""
    return PHISHING_TEMPLATES

def get_threat_level(score):
    """Get threat level based on score."""
    for level, (min_score, max_score) in THREAT_LEVELS.items():
        if min_score <= score <= max_score:
            return level
    return "LOW"

def find_matching_templates(url, threshold=70):
    """Find templates matching a URL."""
    matches = []
    for template_id, template in PHISHING_TEMPLATES.items():
        for pattern in template.get("url_patterns", []):
            if pattern.lower() in url.lower():
                if template["threat_score"] >= threshold:
                    matches.append({
                        "template_id": template_id,
                        "template": template,
                        "threat_score": template["threat_score"]
                    })
    return matches 