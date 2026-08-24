# app.py – Full ML version with complete feature extraction

import re
import os
import socket
import ssl
import whois
import requests
import tldextract
import dns.resolver
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS
import cloudpickle

app = Flask(__name__)
CORS(app)

# ------------------------------------------------------------
# 1. Paths to model files
# ------------------------------------------------------------
MODEL_PATH = os.path.join(os.path.dirname(__file__), "best_model.pkl")
X_TRAIN_PATH = os.path.join(os.path.dirname(__file__), "X_train.pkl")
Y_TRAIN_PATH = os.path.join(os.path.dirname(__file__), "y_train.pkl")

print("=" * 60)
print("Checking model files...")
print(f"  MODEL_PATH: {MODEL_PATH}")
print(f"  X_TRAIN_PATH: {X_TRAIN_PATH}")
print(f"  Y_TRAIN_PATH: {Y_TRAIN_PATH}")
print(f"  Model exists: {os.path.exists(MODEL_PATH)}")
print(f"  X_train exists: {os.path.exists(X_TRAIN_PATH)}")
print(f"  y_train exists: {os.path.exists(Y_TRAIN_PATH)}")
print("=" * 60)

_model = None
_X_train = None
_y_train = None
_global_means = None
_global_stds = None
_legit_means = None
_phish_means = None

def load_artifacts():
    global _model, _X_train, _y_train, _global_means, _global_stds, _legit_means, _phish_means
    if _model is not None:
        return

    if not all(os.path.exists(p) for p in (MODEL_PATH, X_TRAIN_PATH, Y_TRAIN_PATH)):
        print("ERROR: One or more model files are missing.")
        return

    try:
        with open(MODEL_PATH, 'rb') as f:
            _model = cloudpickle.load(f)
        with open(X_TRAIN_PATH, 'rb') as f:
            _X_train = cloudpickle.load(f)
        with open(Y_TRAIN_PATH, 'rb') as f:
            _y_train = cloudpickle.load(f)

        print(f"Loaded model type: {type(_model)}")
        print(f"X_train shape: {_X_train.shape}")
        print(f"y_train shape: {_y_train.shape}")

        _global_means = _X_train.mean()
        _global_stds = _X_train.std()
        _legit_means = _X_train[_y_train == -1].mean()
        _phish_means = _X_train[_y_train == 1].mean()
        print("✅ Model and training data loaded successfully.")
    except Exception as e:
        print(f"Failed to load artifacts: {e}")

# ------------------------------------------------------------
# 2. Full feature extraction with robust error handling
# ------------------------------------------------------------
def extract_raw_features(url):
    raw = {}
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        path = parsed.path
        query = parsed.query
        scheme = parsed.scheme
        full_url = url

        def fetch_html(url):
            try:
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                resp = requests.get(url, timeout=10, headers=headers)
                if resp.status_code == 200:
                    return resp.text
            except:
                pass
            return None

        html = fetch_html(url)
        soup = BeautifulSoup(html, 'html.parser') if html else None

        # Always computable
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        raw['having_IPhaving_IP_Address'] = -1 if ip_pattern.search(hostname) else 1

        length = len(full_url)
        raw['URLURL_Length'] = 1 if length < 54 else (0 if 54 <= length <= 75 else -1)

        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly']
        raw['Shortining_Service'] = 1 if any(s in hostname for s in shorteners) else -1
        raw['having_At_Symbol'] = 1 if '@' in full_url else -1
        raw['double_slash_redirecting'] = 1 if '//' in path else -1

        ext = tldextract.extract(full_url)
        raw['Prefix_Suffix'] = 1 if '-' in ext.domain else -1

        subdomain = ext.subdomain
        if subdomain == '':
            raw['having_Sub_Domain'] = -1
        else:
            count = subdomain.count('.') + 1
            raw['having_Sub_Domain'] = 0 if count <= 1 else 1

        raw['port'] = -1 if not (parsed.port and parsed.port not in (80, 443)) else 1
        raw['HTTPS_token'] = 1 if 'https' in full_url.lower() else -1

        # SSL (None if not verifiable)
        ssl_val = None
        if scheme == 'https':
            try:
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        if cert:
                            exp_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            ssl_val = 1 if exp_date > datetime.now() else 0
                        else:
                            ssl_val = 0
            except:
                pass
        raw['SSLfinal_State'] = ssl_val

        # Domain WHOIS (None if fails)
        domain = ext.domain + '.' + ext.suffix
        domain_reg = None
        try:
            w = whois.whois(domain)
            if w.creation_date:
                creation = w.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                age = (datetime.now() - creation).days / 365.0
                domain_reg = 1 if age >= 1 else -1
            else:
                domain_reg = -1
        except:
            pass
        raw['Domain_registeration_length'] = domain_reg
        raw['age_of_domain'] = domain_reg

        # DNS (None if fails)
        dns_val = None
        try:
            dns.resolver.resolve(hostname, 'A')
            dns_val = 1
        except:
            pass
        raw['DNSRecord'] = dns_val

        # Favicon (None if not found / cannot check)
        favicon = None
        if soup:
            favicon_link = soup.find('link', rel='icon')
            if favicon_link and favicon_link.get('href'):
                favicon = 1
            else:
                base = f"{scheme}://{hostname}"
                try:
                    r = requests.head(base + '/favicon.ico', timeout=3)
                    if r.status_code == 200:
                        favicon = 1
                    else:
                        favicon = -1
                except:
                    pass
        raw['Favicon'] = favicon

        # HTML‑based features (None if no HTML)
        def extract_from_soup(soup, hostname):
            if soup is None:
                return {k: None for k in ['Request_URL', 'URL_of_Anchor', 'Links_in_tags',
                                         'SFH', 'Submitting_to_email', 'Redirect',
                                         'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe']}
            d = {}
            external = 0
            for tag in soup.find_all(['script', 'img', 'link']):
                src = tag.get('src') or tag.get('href')
                if src and not src.startswith('//') and not src.startswith('/') and not src.startswith('#'):
                    external += 1
            d['Request_URL'] = 1 if external > 5 else -1

            external_anchors = 0
            for a in soup.find_all('a', href=True):
                href = a['href']
                if href.startswith('http') and hostname not in href:
                    external_anchors += 1
            d['URL_of_Anchor'] = 1 if external_anchors > 3 else -1

            external_links = 0
            for link in soup.find_all('link', href=True):
                href = link['href']
                if href.startswith('http') and hostname not in href:
                    external_links += 1
            d['Links_in_tags'] = 1 if external_links > 2 else -1

            sfh = -1
            for form in soup.find_all('form'):
                action = form.get('action')
                if not action or (action.startswith('http') and hostname not in action):
                    sfh = 1
                    break
            d['SFH'] = sfh

            d['Submitting_to_email'] = 1 if any(form.get('action', '').startswith('mailto:') for form in soup.find_all('form')) else -1

            d['Redirect'] = 1 if any('url=' in meta.get('content', '').lower() for meta in soup.find_all('meta', attrs={'http-equiv': 'refresh'})) else -1

            d['on_mouseover'] = 1 if soup.find_all(attrs={'onmouseover': True}) else -1
            d['RightClick'] = 1 if soup.find_all(attrs={'oncontextmenu': True}) else -1

            d['popUpWidnow'] = 1 if any('window.open' in (script.string or '') for script in soup.find_all('script')) else -1
            d['Iframe'] = 1 if soup.find('iframe') else -1

            return d

        html_feats = extract_from_soup(soup, hostname)
        raw.update(html_feats)

        # Google Index (None if cannot check)
        google_val = None
        try:
            r = requests.head(f"{scheme}://{hostname}/robots.txt", timeout=5)
            if r.status_code < 400:
                google_val = 1
        except:
            pass
        raw['Google_Index'] = google_val

        # Remaining (always -1)
        raw['web_traffic'] = -1
        raw['Page_Rank'] = -1
        raw['Links_pointing_to_page'] = -1
        raw['Statistical_report'] = -1

    except Exception as e:
        print(f"Error extracting features for {url}: {e}")
        # Return an empty dict; imputation will use global means
        return {}

    return raw

# ------------------------------------------------------------
# 3. Imputation and prediction
# ------------------------------------------------------------
def impute_with_means(raw, means, stds, noise_scale=0.15):
    imputed = []
    for col in _X_train.columns:
        val = raw.get(col)
        if val is None:
            mean = means[col]
            std = stds[col] * noise_scale
            val = np.random.normal(mean, std)
        imputed.append(val)
    return imputed

def predict_with_imputation(url, model, n_imputations=20):
    raw = extract_raw_features(url)

    # First pass
    first_imputed = []
    for col in _X_train.columns:
        val = raw.get(col)
        if val is None:
            val = _global_means[col]
        first_imputed.append(val)
    X_first = pd.DataFrame([first_imputed], columns=_X_train.columns)
    pred_first = model.predict(X_first)[0]

    # Class‑conditional imputation
    means = _legit_means if pred_first == -1 else _phish_means
    stds = _global_stds
    probas = []
    for _ in range(n_imputations):
        imputed = impute_with_means(raw, means, stds, noise_scale=0.15)
        X_new = pd.DataFrame([imputed], columns=_X_train.columns)
        prob = model.predict_proba(X_new)[0]
        probas.append(prob)

    avg_proba = np.mean(probas, axis=0)
    std_proba = np.std(probas, axis=0)
    pred = 1 if avg_proba[1] > 0.5 else -1
    confidence = 1 - std_proba.mean()
    return pred, avg_proba, confidence

# ------------------------------------------------------------
# 4. Routes
# ------------------------------------------------------------
@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json(silent=True) or {}
    url = (data.get('url') or '').strip()
    if not url:
        return jsonify({'error': 'Missing URL'}), 400

    print(f"Received URL: {url}")

    load_artifacts()

    if _model is not None and _X_train is not None:
        try:
            pred, proba, confidence = predict_with_imputation(url, _model)
            label = 'Phishing' if pred == 1 else 'Legitimate'
            return jsonify({
                'prediction': label,
                'probabilities': {
                    'legitimate': round(float(proba[0]), 4),
                    'phishing': round(float(proba[1]), 4)
                },
                'confidence': round(float(confidence), 4),
                'source': 'ml_model'
            })
        except Exception as e:
            app.logger.error(f'Prediction error: {e}')
            return jsonify({'error': str(e)}), 500
    else:
        return jsonify({'error': 'Model not loaded'}), 503

@app.route('/health', methods=['GET'])
def health():
    load_artifacts()
    return jsonify({'status': 'ok', 'model_loaded': _model is not None})

if __name__ == '__main__':
    # Load once at startup
    load_artifacts()
    app.run(host='0.0.0.0', port=5000, debug=True)