# Whisp

Anonymous message app with file-based JSON persistence.

## Run locally

1. Install dependencies:
   - `npm install`
2. Start server:
   - `npm start`
3. Open:
   - `http://localhost:3000`

## Data storage

- `data/users.json` stores user records.
- `data/messages.json` stores anonymous messages.

## Deploy fast (Render)

1. Push this folder to GitHub.
2. In Render: **New +** -> **Web Service** -> select repo.
3. Configure:
   - Build Command: `npm install`
   - Start Command: `npm start`
4. Deploy and open generated URL.

Your share link format in production is:
- `https://your-domain.com/Whisp.html?to=username`
