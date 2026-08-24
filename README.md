# 🛡️ Phishing Website Detector

A machine learning-powered web application that detects phishing websites by analyzing 30 URL features. Built with React + TypeScript (frontend) and Flask + scikit-learn (backend).

🔗 **Live Demo**: [your-netlify-url.netlify.app](https://your-netlify-url.netlify.app) (replace with your actual URL after deployment)

---

## ✨ Features

- **Real-time URL analysis** – Paste any URL and get an instant verdict.
- **ML-powered** – Uses a trained RandomForest model with 30 extracted features.
- **Class‑conditional imputation** – Handles missing features robustly.
- **Beautiful, responsive UI** – Modern dark theme with clear results.
- **Confidence scores** – Shows probability percentages and model confidence.
- **Deployable** – Ready for cloud deployment on Render + Netlify.

---

## 🧠 How It Works

1. **User submits a URL** via the web interface.
2. **Backend extracts 30 features**:
   - URL structure (length, special characters, subdomains, etc.)
   - SSL certificate validity
   - WHOIS domain registration age
   - DNS resolution
   - HTML content analysis (external links, forms, iframes, scripts, etc.)
   - Favicon presence, port usage, and more.
3. **Class‑conditional multiple imputation** fills any missing features with training‑set statistics.
4. **Trained RandomForest model** predicts whether the URL is **Legitimate** or **Phishing**.
5. **Result** is returned to the frontend with probabilities and confidence.

---

## 🛠️ Tech Stack

### Frontend
- React + TypeScript
- Vite (build tool)
- Tailwind CSS
- Lucide React (icons)
- Zustand (state management)

### Backend
- Flask (Python web framework)
- scikit-learn (RandomForest model)
- cloudpickle (model serialization)
- BeautifulSoup4 (HTML parsing)
- python-whois, dnspython, tldextract (feature extraction)
- Flask-CORS (cross-origin support)

---

## 📁 Project Structure

```
website-phishing-detector/
├── backend/
│   ├── app.py                 # Flask server with ML logic
│   ├── requirements.txt       # Python dependencies
│   ├── best_model.pkl         # Trained RandomForest model
│   ├── X_train.pkl            # Training features (for imputation)
│   ├── y_train.pkl            # Training labels (for imputation)
│   └── app_old.py             # Legacy heuristic version (backup)
├── src/
│   ├── App.tsx                # Main React component
│   ├── lib/
│   │   └── detector.ts        # API client
│   ├── index.css              # Tailwind styles
│   └── main.tsx               # React entry point
├── index.html                 # HTML template
├── package.json               # Node dependencies
├── tailwind.config.js         # Tailwind config
├── vite.config.ts             # Vite config
├── .gitignore                 # Git ignored files
└── README.md                  # This file
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- Node.js 18+
- pip and npm installed

### 1. Clone the Repository

```bash
git clone https://github.com/OmarTanah/website-phishing-detector.git
cd website-phishing-detector
```

### 2. Set Up the Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

The backend will run at `http://localhost:5000`.

### 3. Set Up the Frontend

Open a new terminal in the project root:

```bash
npm install
npm run dev
```

The frontend will run at `http://localhost:5173`.

### 4. Test the Application

1. Open `http://localhost:5173`.
2. Enter a URL (e.g., `http://85.17.116.190/kWC5PHA1` or `https://www.google.com`).
3. Click **Check URL** – you'll see the verdict and probabilities.

---

## 🧪 Sample URLs to Test

| URL | Expected Result |
|-----|----------------|
| `https://www.google.com` | Legitimate |
| `http://85.17.116.190/kWC5PHA1` | Phishing |
| `https://orange-verification-fr.s-host.net/` | Phishing |
| `https://github.com` | Legitimate |
| `http://secure-login-update.account-verify.tk/login` | Phishing |

---

## 📊 Feature Extraction (30 Features)

The model uses 30 features extracted from the URL and its content:

1. Having IP address
2. URL length
3. Shortening service
4. Having @ symbol
5. Double slash redirecting
6. Prefix suffix (dash in domain)
7. Subdomain count
8. SSL final state
9. Domain registration length
10. Favicon presence
11. Port number
12. HTTPS token in URL
13. Request URL (external resources)
14. URL of anchor (external links)
15. Links in tags
16. Server form handler (SFH)
17. Submitting to email
18. Abnormal URL (suspicious keywords)
19. Redirect count
20. On mouseover
21. Right click disabled
22. Popup window
23. Iframe usage
24. Age of domain
25. DNS record
26. Web traffic
27. Page rank
28. Google index
29. Links pointing to page
30. Statistical report

---

## ☁️ Deployment

### Backend (Render)

1. Push code to GitHub.
2. Go to [render.com](https://render.com) → New Web Service.
3. Connect your GitHub repo.
4. Set:
   - **Root Directory**: `backend/`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
5. Deploy.

### Frontend (Netlify)

1. Build the frontend: `npm run build`.
2. Go to [netlify.com](https://netlify.com) → Add new site → Deploy manually.
3. Drag the `dist/` folder to the Netlify drop area.
4. Update the API endpoint in `App.tsx` to your Render URL and redeploy.

---

## 🔧 Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| `STACK_GLOBAL requires str` | Use `cloudpickle` to save/load the model (included in `app.py`). |
| Model not loading | Ensure `best_model.pkl`, `X_train.pkl`, `y_train.pkl` are in `backend/`. |
| CORS errors | Flask has `CORS(app)` – if needed, restrict origins in production. |
| `NoneType` error in feature extraction | `extract_raw_features` wraps everything in a try/except and returns `{}` on failure. |

### Python Version Compatibility

- **Trained on**: Python 3.10 – 3.11 (scikit-learn 1.6.1)
- **Works with**: Python 3.10 – 3.14 (scikit-learn 1.6.1 – 1.9.0)
- Use `cloudpickle` to avoid version mismatch errors.

---

## 📈 Model Performance

- **Accuracy**: 96.7% on the test set
- **Precision**: 96.0%
- **Recall**: 98.1%
- **Features**: 30
- **Algorithm**: RandomForestClassifier (max_depth=20, n_estimators=200)

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/your-feature`.
3. Commit your changes: `git commit -m "Add feature"`.
4. Push: `git push origin feature/your-feature`.
5. Open a Pull Request.

---

## 📝 License

This project is open-source and available under the MIT License.

---

## 📧 Contact

**Omar Tanah** – [omartanah4@gmail.com](mailto:omartanah4@gmail.com)  
GitHub: [@OmarTanah](https://github.com/OmarTanah)

---

## 🙏 Acknowledgements

- [Kaggle Dataset](https://www.kaggle.com/datasets/mdsultanulislamovi/phishing-website-detection-datasets) for the phishing dataset.
- scikit-learn, Flask, React, and all open-source libraries used.
- The open‑source community for making ML and web development accessible.

---

⭐ **If you find this project useful, please give it a star on GitHub!**
```
