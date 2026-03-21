"""
PhishGuard AI - Model Training Pipeline
Trains URL (RandomForest) and Text (TF-IDF + LogisticRegression) models.

Run: python train_models.py
"""
import os
import pickle
import random
import logging
import numpy as np
import warnings
warnings.filterwarnings('ignore')

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, roc_auc_score

# Add project root to path
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.url_features import get_feature_vector
from config import Config


# ════════════════════════════════════════════════════════════
# SECTION 1: SYNTHETIC DATASET GENERATION
# ════════════════════════════════════════════════════════════

PHISHING_DOMAINS = [
    'paypa1-verify.com', 'amazonsecurity-alert.com', 'google-login-verify.xyz',
    'facebook-secure-update.tk', 'microsoft-alert-urgent.ml', 'apple-id-locked.ga',
    'netflix-billing-update.cf', 'chase-bank-secure.top', 'irs-tax-refund.xyz',
    'paypal-account-verify.click', 'amazon-prime-expire.tk', 'secure-login-google.ml',
    'wellsfargo-verify.xyz', 'instagram-confirm.ga', 'twitter-security.top',
    'dropbox-secure-link.click', 'usps-delivery-alert.xyz', 'fedex-package-confirm.tk',
    'covid-relief-fund.ga', 'free-iphone-winner.ml', 'bank-alert-suspicious.xyz',
    'account-suspended-now.com', 'verify-your-paypal.tk', 'login-facebook-verify.xyz'
]

LEGIT_DOMAINS = [
    'google.com', 'amazon.com', 'facebook.com', 'microsoft.com', 'apple.com',
    'github.com', 'stackoverflow.com', 'wikipedia.org', 'youtube.com', 'linkedin.com',
    'twitter.com', 'instagram.com', 'reddit.com', 'netflix.com', 'dropbox.com',
    'slack.com', 'zoom.us', 'shopify.com', 'stripe.com', 'cloudflare.com',
    'adobe.com', 'salesforce.com', 'hubspot.com', 'mailchimp.com', 'notion.so'
]

PHISHING_PATHS = [
    '/login/verify', '/account/suspended', '/secure/update', '/confirm/identity',
    '/payment/update', '/signin/verify', '/security/alert', '/password/reset/urgent',
    '/account/locked/verify', '/billing/update/now'
]

LEGIT_PATHS = [
    '/', '/about', '/products', '/blog', '/contact', '/docs', '/help',
    '/search', '/news', '/pricing', '/features', '/download', '/api', '/status'
]

PHISHING_QUERIES = [
    '?redirect=http://evil.com&token=abc123',
    '?verify=true&userid=12345&secure=1',
    '?action=suspend&account=yes&confirm=now',
    '?update=billing&token=xyz&session=active'
]

SPAM_MESSAGES = [
    "URGENT: Your account has been compromised. Click here immediately to verify your identity: http://paypa1-verify.com/login",
    "Congratulations! You've won $1,000,000 in our lottery! Claim your prize NOW at free-winner.tk",
    "FINAL NOTICE: Your PayPal account will be suspended. Confirm your details here: http://paypal-verify.xyz",
    "Dear Customer, We detected suspicious activity on your account. Please verify NOW: http://secure-bank.ml",
    "Your Amazon Prime membership will expire. Update payment immediately: amazon-billing.xyz/update",
    "IRS TAX REFUND: You are owed $2,847. Provide your SSN and bank details to claim now.",
    "Microsoft Security Alert: Your Windows license has expired. Renew immediately to avoid data loss.",
    "Your Apple ID has been locked due to multiple failed attempts. Verify your account: apple-verify.ga",
    "LIMITED TIME OFFER: Earn $500/day working from home! No experience needed. Click here FREE!",
    "ALERT: Unauthorized access detected on your Chase bank account. Call 1-800-FAKE now!",
    "Dear Valued Member, Your Netflix subscription payment failed. Update billing info: netflix-billing.tk",
    "You have been selected for a $5000 government stimulus grant. Confirm your details NOW.",
    "WINNER! Your email was selected in our draw. Claim your iPhone 15 Pro: free-iphone.ml",
    "Social Security Administration: Your SSN has been suspended. Call immediately to avoid arrest.",
    "FedEx: Your package #394856 is on hold. Pay delivery fee of $2.99 to release: fedex-alert.xyz",
    "Dear Account Holder, Your bank account has been frozen due to suspicious activity. Verify now.",
    "Urgent action required: Your password expires in 24 hours. Click to reset: secure-password.tk",
    "You have unclaimed funds of $45,000 from a deceased relative. Contact us to claim your inheritance.",
    "WARNING: Your computer has been infected with 5 viruses. Call Microsoft Support NOW: 1-800-SCAM.",
    "Congratulations! As a loyal customer, you qualify for a $1000 Walmart gift card. Claim today!",
]

LEGIT_MESSAGES = [
    "Hi John, just following up on our meeting last Tuesday. Can we reschedule to Thursday afternoon?",
    "The project deadline is next Friday. Please submit your deliverables by EOD Thursday.",
    "Your order #12345 has shipped! Expected delivery: March 15. Track at ups.com/track",
    "Team meeting moved to 3pm in Conference Room B. Please update your calendars.",
    "Python 3.12 released with new features including improved error messages and performance gains.",
    "Reminder: Quarterly performance reviews begin next week. Please prepare your self-assessments.",
    "The monthly newsletter is now available on our website. Check out the latest updates.",
    "Your subscription renewal is coming up on April 1. No action needed if you want to continue.",
    "We're excited to announce our new product launch next month. Stay tuned for details!",
    "Hi, I came across your blog post on machine learning and found it very insightful. Great work!",
    "The conference agenda has been finalized. Please review the schedule and plan your sessions.",
    "GitHub Dependabot has detected 2 vulnerabilities in your dependencies. Review pull request #42.",
    "Your weekly summary: 5 new followers, 12 likes, 3 comments on your recent posts.",
    "Thanks for signing up! Your account is now active. Explore our getting started guide.",
    "Invoice #INV-2024-001 for $450 is due on March 30. Pay at your convenience.",
    "Stack Overflow: Someone answered your question about Python list comprehensions.",
    "Your domain example.com will expire in 30 days. Renew at your registrar to keep it.",
    "The code review for PR #156 is complete. Two minor suggestions before merging.",
    "Office closed on Monday for the holiday. Normal operations resume Tuesday morning.",
    "Your LinkedIn connection request was accepted. You're now connected with Sarah Johnson.",
]


def generate_url_dataset(n_phishing=2000, n_legit=2000):
    """Generate synthetic URL dataset with features and labels."""
    logger.info(f"Generating URL dataset ({n_phishing} phishing + {n_legit} legit)...")

    urls = []
    labels = []

    # Generate phishing URLs
    for _ in range(n_phishing):
        domain = random.choice(PHISHING_DOMAINS)
        path = random.choice(PHISHING_PATHS + [''])
        query = random.choice(PHISHING_QUERIES + ['', ''])

        # Add variations
        variations = [
            f"http://{domain}{path}{query}",
            f"https://{domain}{path}{query}",
            f"http://{random.randint(10,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}{path}",
            f"http://{'www.' if random.random() > 0.5 else ''}{domain}{path}",
            f"http://{domain}/{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=12))}/verify"
        ]
        urls.append(random.choice(variations))
        labels.append(1)  # 1 = phishing

    # Generate legitimate URLs
    for _ in range(n_legit):
        domain = random.choice(LEGIT_DOMAINS)
        path = random.choice(LEGIT_PATHS)
        urls.append(f"https://www.{domain}{path}")
        labels.append(0)  # 0 = legit

    return urls, labels


def extract_features_batch(urls):
    """Extract features for all URLs."""
    logger.info(f"Extracting features for {len(urls)} URLs...")
    features = []
    for url in urls:
        try:
            fv = get_feature_vector(url)
            features.append(fv)
        except Exception:
            features.append([0] * 20)
    return np.array(features)


def generate_text_dataset():
    """Generate text dataset from spam/legit messages with augmentation."""
    logger.info("Generating text dataset...")

    texts = []
    labels = []

    # Augment spam messages
    for msg in SPAM_MESSAGES:
        texts.append(msg)
        labels.append(1)
        # Augmentations
        texts.append(msg.upper())
        labels.append(1)
        texts.append("FWD: " + msg)
        labels.append(1)
        texts.append(msg + " DO NOT IGNORE THIS MESSAGE!!!")
        labels.append(1)
        texts.append("IMPORTANT: " + msg)
        labels.append(1)

    # Augment legit messages
    for msg in LEGIT_MESSAGES:
        texts.append(msg)
        labels.append(0)
        texts.append("Re: " + msg)
        labels.append(0)
        texts.append("Fwd: " + msg)
        labels.append(0)
        texts.append(msg + " Let me know if you have any questions.")
        labels.append(0)
        texts.append("Hi, " + msg)
        labels.append(0)

    # Additional synthetic phishing
    extra_phishing = [
        "Your account verification is required within 24 hours or your account will be permanently deleted.",
        "CONGRATULATIONS! You are our lucky winner. Click the link to claim $10,000 prize money NOW.",
        "SECURITY ALERT: We noticed unusual login from Russia. Verify your identity immediately.",
        "Dear user, your subscription has been charged $299. If you didn't authorize this, click here.",
        "Your package cannot be delivered. Pay $1.99 customs fee at this link to reschedule delivery.",
        "IRS URGENT: Criminal charges filed against your SSN. Call 800-123-4567 to avoid arrest.",
        "Nigerian Prince needs your help to transfer $25 million. You keep 30%! Reply with bank details.",
        "FREE iPhone 15 Pro waiting for you! Complete this short survey to claim. Limited time offer!",
        "ACCOUNT LOCKED: Unusual activity detected. Restore access now: http://fake-bank-verify.xyz",
        "Your crypto wallet has been flagged. Verify your seed phrase immediately to avoid loss.",
    ]

    for msg in extra_phishing:
        texts.append(msg)
        labels.append(1)
        texts.append("URGENT: " + msg)
        labels.append(1)
        texts.append(msg.replace('.', '!!!'))
        labels.append(1)

    # Additional synthetic legit
    extra_legit = [
        "Please review the attached document and provide feedback by end of week.",
        "The sprint planning meeting is scheduled for Monday at 10am in the main conference room.",
        "Your pull request #234 has been approved and merged into the main branch.",
        "New blog post published: '10 Tips for Better Python Code'. Check it out on our website.",
        "Your monthly statement is now available in your online banking portal.",
        "The team lunch is on Friday at noon. We're going to the Italian place on 5th Street.",
        "Reminder: submit your expense reports before the end of the quarter.",
        "Your annual performance review has been scheduled for next Wednesday at 2pm.",
        "The new software update includes bug fixes and performance improvements.",
        "Welcome to our community! Please read the community guidelines before posting.",
    ]

    for msg in extra_legit:
        texts.append(msg)
        labels.append(0)
        texts.append("Re: " + msg)
        labels.append(0)

    # Shuffle
    combined = list(zip(texts, labels))
    random.shuffle(combined)
    texts, labels = zip(*combined)

    return list(texts), list(labels)


# ════════════════════════════════════════════════════════════
# SECTION 2: MODEL TRAINING
# ════════════════════════════════════════════════════════════

def train_url_model():
    """Train GradientBoosting URL classifier."""
    logger.info("\n" + "="*50)
    logger.info("TRAINING URL MODEL")
    logger.info("="*50)

    urls, labels = generate_url_dataset(n_phishing=2000, n_legit=2000)
    X = extract_features_batch(urls)
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train Gradient Boosting
    logger.info("Training GradientBoostingClassifier...")
    model = GradientBoostingClassifier(
        n_estimators=200,
        learning_rate=0.1,
        max_depth=5,
        subsample=0.8,
        min_samples_split=5,
        random_state=42,
        verbose=0
    )
    model.fit(X_train_scaled, y_train)

    # Evaluate
    y_pred = model.predict(X_test_scaled)
    y_proba = model.predict_proba(X_test_scaled)[:, 1]

    logger.info("\nURL Model Performance:")
    logger.info(classification_report(y_test, y_pred, target_names=['Legit', 'Phishing']))
    logger.info(f"ROC-AUC: {roc_auc_score(y_test, y_proba):.4f}")

    # Cross-validation
    cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5, scoring='roc_auc')
    logger.info(f"Cross-val AUC: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    return model, scaler


def train_text_model():
    """Train TF-IDF + LogisticRegression text classifier."""
    logger.info("\n" + "="*50)
    logger.info("TRAINING TEXT MODEL")
    logger.info("="*50)

    texts, labels = generate_text_dataset()
    y = np.array(labels)

    logger.info(f"Dataset: {len(texts)} samples ({sum(labels)} phishing, {len(labels)-sum(labels)} legit)")

    # TF-IDF vectorization
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 3),
        min_df=1,
        max_df=0.95,
        sublinear_tf=True,
        strip_accents='unicode',
        analyzer='word',
        token_pattern=r'\b[a-zA-Z0-9_]+\b'
    )

    X = vectorizer.fit_transform(texts)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Train Logistic Regression
    logger.info("Training LogisticRegression...")
    model = LogisticRegression(
        C=1.0,
        max_iter=1000,
        class_weight='balanced',
        solver='lbfgs',
        random_state=42
    )
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    logger.info("\nText Model Performance:")
    logger.info(classification_report(y_test, y_pred, target_names=['Legit', 'Spam/Phishing']))
    logger.info(f"ROC-AUC: {roc_auc_score(y_test, y_proba):.4f}")

    return model, vectorizer


# ════════════════════════════════════════════════════════════
# SECTION 3: SAVE MODELS
# ════════════════════════════════════════════════════════════

def save_models(url_model, url_scaler, text_model, text_vectorizer):
    """Save trained models to disk."""
    os.makedirs(Config.MODELS_DIR, exist_ok=True)

    logger.info("\n" + "="*50)
    logger.info("SAVING MODELS")
    logger.info("="*50)

    models = {
        Config.URL_MODEL_PATH: url_model,
        Config.URL_SCALER_PATH: url_scaler,
        Config.TEXT_MODEL_PATH: text_model,
        Config.TEXT_VECTORIZER_PATH: text_vectorizer,
    }

    for path, obj in models.items():
        with open(path, 'wb') as f:
            pickle.dump(obj, f)
        logger.info(f"Saved: {path}")

    logger.info("All models saved successfully!")


def verify_models():
    """Quick sanity check on saved models."""
    logger.info("\n" + "="*50)
    logger.info("VERIFYING MODELS")
    logger.info("="*50)

    test_urls = [
        "https://paypa1-verify.com/login?redirect=evil.com",
        "https://www.google.com/search?q=test"
    ]

    test_texts = [
        "URGENT: Your account suspended! Verify NOW at fake-bank.xyz",
        "Hi team, meeting scheduled for Monday at 10am. Please confirm."
    ]

    try:
        with open(Config.URL_MODEL_PATH, 'rb') as f:
            url_model = pickle.load(f)
        with open(Config.URL_SCALER_PATH, 'rb') as f:
            url_scaler = pickle.load(f)
        with open(Config.TEXT_MODEL_PATH, 'rb') as f:
            text_model = pickle.load(f)
        with open(Config.TEXT_VECTORIZER_PATH, 'rb') as f:
            text_vectorizer = pickle.load(f)

        logger.info("URL model predictions:")
        for url in test_urls:
            fv = np.array(get_feature_vector(url)).reshape(1, -1)
            scaled = url_scaler.transform(fv)
            proba = url_model.predict_proba(scaled)[0]
            logger.info(f"  {url[:60]!r} → Phishing: {proba[1]:.2%}")

        logger.info("Text model predictions:")
        for text in test_texts:
            vec = text_vectorizer.transform([text])
            proba = text_model.predict_proba(vec)[0]
            logger.info(f"  {text[:60]!r} → Phishing: {proba[1]:.2%}")

        logger.info("\nAll models verified successfully!")
        return True

    except Exception as e:
        logger.error(f"Model verification failed: {e}")
        return False


if __name__ == '__main__':
    logger.info("PhishGuard AI - Training Pipeline")
    logger.info("=" * 50)

    # Train
    url_model, url_scaler = train_url_model()
    text_model, text_vectorizer = train_text_model()

    # Save
    save_models(url_model, url_scaler, text_model, text_vectorizer)

    # Verify
    verify_models()

    logger.info("\n✅ Training complete! You can now run: python app.py")
