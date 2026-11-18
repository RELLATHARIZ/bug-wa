# NIGHTMARE real-auth starter

This is a local backend starter (not a preconfigured demo account). It uses SQLite, bcrypt password hashes, server-side sessions, login rate limiting, and role checks.

## Requirements
- Node.js 20+ recommended

## First run
1. Install dependencies: `npm install`
2. Set Owner bootstrap values and session secret in your shell (do not commit them):
   - `NIGHTMARE_OWNER_USERNAME` = your chosen username
   - `NIGHTMARE_OWNER_PASSWORD` = strong password, 12+ chars
   - `NIGHTMARE_SESSION_SECRET` = long random secret
3. Run: `npm start`
4. Open `http://localhost:3000`

Owner bootstrap happens only if there is no Owner account in the database. Owner can create Developer/Admin/VIP/Member. Developer can create Admin/VIP/Member only. This starter is intended for local development; before public deployment configure HTTPS, a persistent session store, CSRF protection, secure secrets, and backups.

Bug Lab is only a local visual simulation and does not interact with WhatsApp or external accounts.
