# Neon Motion

**To run:** double-click `start.bat` (needs Node.js, which you already have).
First run installs everything, creates your settings automatically, and opens http://localhost:3000.
Your admin login is printed in the black window (also saved in `backend/.env`). Admin page: /admin.html

```
neon-motion/
├── start.bat        <- double-click this
├── frontend/        <- website pages (index, account, admin)
└── backend/         <- server + database (server.js, package.json)
```

Optional (edit `backend/.env`): `SMTP_URL` for real emails, `STRIPE_SECRET_KEY` + `STRIPE_WEBHOOK_SECRET` for payments.
Before going live: set a strong `ADMIN_PASSWORD`, `SEED_DEMO=false`, `NODE_ENV=production`, and your real `BASE_URL`.

## Chatbot
The chat window (bottom-right of the site) works straight away: it answers from your real plans, classes and coaches.
For more natural AI answers, add your key to `backend/.env`:
```
ANTHROPIC_API_KEY=your-key-here
```
(get one at console.anthropic.com). The key stays on the server and is never sent to visitors.
Optional: `CHAT_MODEL` (default claude-haiku-5-5) and `CHAT_DAILY_LIMIT` (default 500 AI replies a day; after that it uses the built-in answers).
If the AI service is unreachable, the chat falls back to the built-in answers automatically.
Visitors can tap "Talk to the team" to leave a message — it appears in Admin → Messages.
