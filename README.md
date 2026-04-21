# Kryptos — CSE721 Cryptography Web App

## Run Locally

```bash
pip install flask gunicorn
python app.py
# Open http://localhost:5050
```

## Deploy to Render (Free, recommended)

1. Push this folder to a GitHub repo
2. Go to https://render.com → New → Web Service
3. Connect your GitHub repo
4. Render auto-detects `render.yaml` — just click **Deploy**
5. Your app is live at `https://kryptos-cse721.onrender.com`

## Deploy to Railway

1. Push to GitHub
2. Go to https://railway.app → New Project → Deploy from GitHub
3. Select repo → Railway reads `Procfile` automatically
4. Done — live in ~2 minutes

## Deploy to Vercel (like kryptos-rho.vercel.app)

Vercel needs a `vercel.json` for Python/Flask:

```json
{
  "builds": [{"src": "app.py", "use": "@vercel/python"}],
  "routes": [{"src": "/(.*)", "dest": "app.py"}]
}
```

Add this file, then: `vercel deploy --prod`

## Project Structure

```
kryptos_web/
├── app.py                  ← Flask backend (all API routes)
├── requirements.txt
├── Procfile
├── render.yaml
├── templates/
│   └── index.html          ← Full SPA (all pages in one file)
├── classical/
│   ├── substitution.py
│   └── double_transposition.py
├── symmetric/
│   ├── des.py
│   └── aes.py
└── public_key/
    ├── rsa.py
    └── ecc.py
```
