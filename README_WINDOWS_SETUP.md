# Memoo – Windows Zero-Cost Setup

This guide helps an HR user run Memoo on a Windows PC and share it with managers over the local network, without paying for hosting.

## Prerequisites
- Install Node.js LTS from https://nodejs.org/en/download
- Unzip or copy the `memoo` folder to a simple location (e.g., `C:\Memoo`).

## First Run
1. Open the `memoo` folder.
2. Double-click `start_memoo.cmd`.
   - On first run, it installs dependencies.
   - It will open your browser to `http://localhost:8081/`.

## Configure Email Links (BASE_URL)
Managers need links that point to your PC’s address, not `localhost`.

1. Find your PC address:
   - Press `Win + R`, type `cmd`, press Enter.
   - Run `ipconfig` and find `IPv4 Address` (e.g., `192.168.1.50`).
2. Edit `.env` (create if missing) and add:
   - `BASE_URL=http://192.168.1.50:8081` (replace with your actual IP)
   - `MAIL_FROM=Memoo <no-reply@yourdomain.com>` (optional; improves email deliverability)
3. Save the file and re-launch `start_memoo.cmd`.

Now emails sent to managers include links they can open on their PCs.

## Allow Access From Other PCs (Firewall)
To let managers connect to your PC:

1. Press `Win + R`, type `control firewall.cpl`, press Enter.
2. Click `Advanced settings` (left side).
3. In `Inbound Rules`, click `New Rule...`.
4. Choose `Port` → `TCP` → `Specific local ports: 8081` → `Allow the connection` → Apply to Domain/Private networks → Name it `Memoo 8081`.

Managers can now visit `http://<your-ip>:8081/` to log in and view memos.

## Configure Firebase Admin (optional)
If you use Firebase for server-side auth verification, set the service account securely:

1. Create a folder outside the project, e.g., `C:\memoo_keys`.
2. Save your Firebase service account JSON file there (e.g., `C:\memoo_keys\serviceAccount.json`).
3. Choose one of the following and restart `start_memoo.cmd`:
   - In `.env`: `FIREBASE_SERVICE_ACCOUNT_FILE=../memoo_keys/serviceAccount.json`
   - Or set a user env var: `GOOGLE_APPLICATION_CREDENTIALS=C:\memoo_keys\serviceAccount.json`

Notes:
- Do not commit service account files to Git; they are secrets.
- If a key was ever committed, rotate it in Google Cloud: create a new key and delete the old one.
- If not configured, Memoo still runs; token verification endpoints will be disabled.

## Tips
- Keep `ALLOW_ANY_DOMAIN=true` in development (default) so managers can sign up regardless of email domain.
- For stronger session security, set `.env`:
  - `NODE_ENV=production`
  - `SESSION_SECRET=<a long random string>`
- Uploads are limited to 10MB by default. Adjust `UPLOAD_MAX_BYTES` in `.env` if needed.

## Backups
- Back up these folders/files regularly:
  - `data\db.json` (memos)
  - `data\users.json` (user accounts)
  - `uploads\` (uploaded DOCX files)

## Troubleshooting
- Links show `localhost` in emails: set `BASE_URL` correctly and restart.
- Emails not sending: check SMTP in `data\companies.json` and set `MAIL_FROM`.
- Managers cannot connect: create the firewall rule for TCP 8081 and ensure you share the correct `BASE_URL`.
