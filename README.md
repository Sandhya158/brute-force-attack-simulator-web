# Brute Force Simulator — Flask Web App
### CEH Academic Project | Free Deployment on Render

## Run Locally
```bash
pip install flask gunicorn
python app.py
# Open http://localhost:5000
```

## Deploy Free on Render (get a live URL)
1. Push this folder to a GitHub repo
2. Go to https://render.com → Sign up free
3. Click "New +" → "Web Service"
4. Connect your GitHub repo
5. Render auto-detects settings from render.yaml
6. Click "Create Web Service" → get your URL in ~2 minutes

## Project Structure
```
bf_flask/
├── app.py              ← Flask server (replaces Tkinter app.py)
├── requirements.txt    ← flask + gunicorn
├── Procfile            ← Render/Heroku start command
├── render.yaml         ← One-click Render config
├── core/
│   ├── auth.py         ← Unchanged from original
│   ├── simulator.py    ← Unchanged from original
│   ├── wordlist.py     ← Unchanged from original
│   └── logger.py       ← Unchanged from original
└── templates/
    └── index.html      ← Full browser dashboard
```
