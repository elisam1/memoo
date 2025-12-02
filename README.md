# Memoo

Simple HR-to-Manager memo web app featuring DOCX/PDF uploads, email notifications, and a reply workflow with role-based access (HR, Manager, Admin).

## Features
- Upload `.docx` or `.pdf` memos (HR)
- `.docx` auto-converts to HTML for preview; `.pdf` previews inline via browser
- Assign memos to a manager by email; track status (`open`, `waiting`, `closed`)
- Threaded replies between HR and Manager with email notifications
- Role-based dashboards and access control (HR / Manager / Admin)
- Domain enforcement for logins; configure allowed domains and SMTP per company
- Optional Firebase-based signup/login; server verifies ID tokens via Firebase Admin
- Lightweight file-based storage (`data/`) for memos and users

## Tech Stack
- Node.js, Express, EJS, express-ejs-layouts
- Session auth via `express-session` and `bcrypt`
- File upload via `multer`; DOCX → HTML via `mammoth`; PDF inline viewing
- Email via `nodemailer` with per-domain SMTP settings
- Optional email via Firebase Extensions (Trigger Email) writing to Firestore `mail` collection
- Firebase Admin (optional) for verifying client auth tokens; Firebase client for auth and analytics

## Project Structure
```
memoo/
├─ data/               # JSON storage for memos, users, company SMTP config
├─ lib/                # Helpers: store, mailer, company + Firebase admin
├─ public/             # Static assets (CSS)
├─ views/              # EJS templates (pages + email templates)
├─ server.js           # Express app and routes
├─ package.json        # Scripts and dependencies
├─ .env.example        # Config template
├─ start_memoo.cmd     # Windows launcher (prod-ish, port 8081)
└─ README_WINDOWS_SETUP.md
```

## Requirements
- Node.js LTS (v18+ recommended)
- An SMTP provider for sending email notifications
- Optional: Firebase project + service account if using client-based auth

## Quick Start (Development)
1. Install dependencies:
   ```bash
   npm install
   ```
2. Create `.env` based on `.env.example` (see Configuration below).
3. Start the dev server (auto-restart on changes):
   ```bash
   npm run dev
   ```
4. Open `http://localhost:3000/`.

To run without auto-restart:
```bash
npm start
```
Set a custom port via `PORT`, e.g. `PORT=8080`.

## Windows One-Click Start
- Double-click `start_memoo.cmd` to run on port `8081` and auto-open the browser.
- For LAN access and email links that work for other PCs, set `BASE_URL` (see below) and follow `README_WINDOWS_SETUP.md`.

## Configuration (.env)
Copy `.env.example` to `.env` and set as needed:

- `SESSION_SECRET` — required; long random string for signing sessions
- `ALLOW_ANY_DOMAIN` — `true`/`false`; when `false`, only emails from domains listed in `data/companies.json` can log in
- `UPLOAD_MAX_BYTES` — max upload size in bytes for `.docx` (default 10MB)
- `BASE_URL` — the public base URL used in emails, e.g. `http://HR-PC:8081` or `http://192.168.1.50:8081`
- `MAIL_FROM` — sender shown in outbound emails, e.g. `Memoo <no-reply@yourdomain.com>`
- `ADMIN_MAX` — max number of admin accounts
- `ADMIN_ALLOWLIST` — comma-separated emails allowed to create admin accounts
- Firebase Admin (choose ONE):
  - `FIREBASE_SERVICE_ACCOUNT_FILE` — path to service account JSON
  - `FIREBASE_SERVICE_ACCOUNT_JSON` — raw JSON string
  - `FIREBASE_SERVICE_ACCOUNT_BASE64` — base64-encoded JSON
  - `FIREBASE_PROJECT_ID` — override project id if needed
  - `FIREBASE_EMAIL_ENABLED` — `true`/`false` to send email via Firebase Trigger Email extension

Note: SMTP host/user/pass are managed per company domain via Admin UI and `data/companies.json`, not via `.env`.

## Domain & Email Setup
Admins manage allowed email domains and SMTP credentials:
- UI: `Admin → Manage Domains` (`/admin/domains`)
- Stored in `data/companies.json` as:
  ```json
  {
    "name": "Globex",
    "domain": "example.com",
    "smtp": {
      "host": "smtp.example.com",
      "port": 587,
      "secure": false,
      "auth": { "user": "no-reply@example.com", "pass": "***" }
    }
  }
  ```
- Emails use `MAIL_FROM` as the envelope sender and set `replyTo` to the actual human sender (HR or Manager) for conversation continuity.

Alternatively, enable Firebase Trigger Email:
- Install Firebase Extensions: Trigger Email in your Firebase project
- Configure provider (SendGrid/Mailgun/SES) in the extension
- Set `FIREBASE_EMAIL_ENABLED=true` in `.env` and provide a service account via one of `FIREBASE_SERVICE_ACCOUNT_*`
- The app writes notifications to Firestore `mail` with `to`, `replyTo`, and `message.subject/html`

For links in notification emails to open from other PCs, set `BASE_URL` to your machine’s LAN URL and ensure firewall allows the chosen `PORT`.

## Roles & Access Control
- `HR` — create memos, assign managers, view and update memo status, reply
- `Manager` — view assigned memos, reply
- `Admin` — manage allowed domains (SMTP) and admin accounts with seat limits
- Server enforces role access; visiting pages outside your role renders a restricted page

## Core Flows
- HR creates memo: uploads `.docx`, provides manager email and context → system stores memo and emails the manager
- Manager opens memo, previews converted HTML, and replies → system emails HR
- Statuses (`open`, `waiting`, `closed`) are adjustable by HR

## Data & Backups
File-based storage under `data/`:
- `db.json` — memos and replies
- `users.json` — user accounts (bcrypt hashes supported; plaintext allowed for demo)
- `companies.json` — domain → SMTP mapping
Uploads are saved under `uploads/` (auto-created). New memos also embed the file in `data/db.json` (base64 + mime) for portability across machines. Back up `data/` and `uploads/` regularly.

## Firebase Authentication (Optional)
- Client pages use Firebase Auth to acquire an ID token; server verifies it via Firebase Admin on `/sessionLogin`
- If Firebase Admin isn’t configured, token verification is disabled and login fails; configure one of `FIREBASE_SERVICE_ACCOUNT_*` options

## Scripts
- `npm run dev` — start with auto-reload via `nodemon`
- `npm start` — run the server

## Security Notes
- Set `NODE_ENV=production` in production for secure cookies
- Always set a strong `SESSION_SECRET`
- Do not commit Firebase service account credentials; prefer `FIREBASE_SERVICE_ACCOUNT_FILE` locally or environment injection in production

## Troubleshooting
- Email links point to `localhost`: set `BASE_URL` and restart
- Emails not sending: ensure SMTP is set for your domain in `Admin → Manage Domains` and that `MAIL_FROM` is valid
- Managers cannot connect from another PC: allow inbound TCP on your `PORT` (e.g., 8081) in Windows Firewall
- Preview fails: ensure the file exists in `uploads/` or that memo metadata is present; for `.docx` conversion issues, the file must be `.docx` and within `UPLOAD_MAX_BYTES`

---

For Windows-specific, zero-cost LAN hosting instructions, see `README_WINDOWS_SETUP.md`.
