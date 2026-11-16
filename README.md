# Virus Scanner

## Run locally on Windows with XAMPP

1. Install Node.js and start **MySQL** in the XAMPP Control Panel. Apache is not required.
2. Open PowerShell in this project folder and run `npm install` once.
3. Copy `.env.example` to `.env`. The default `DATABASE_URL` works with XAMPP's default MySQL `root` account with no password. If your MySQL account has a password, update the URL.
4. Double-click `start-xampp.bat`. It starts the Node server, waits for the account database to respond, and opens the app.
5. Visit <http://localhost:3000>, click **Sign in**, then **Create an account**. Enter your name, email, and a password at least 8 characters long.

Use <http://localhost:3000>, not the XAMPP Apache project URL. Apache cannot run the Node API; the Node server hosts both the page and account API. You can also start the server manually with `npm start`.

Passwords are stored as scrypt hashes, and the app keeps sessions in MySQL. On Windows, scans use Microsoft Defender locally when no VirusTotal key is configured. On other platforms, add a valid `VIRUSTOTAL_API_KEY` to the local `.env` to enable scanning. If both are available, VirusTotal is used. VirusTotal receives uploaded files; do not submit files you aren't comfortable sharing. Never share or commit API keys. Email alerts additionally need `RESEND_API_KEY` and `RESEND_FROM_EMAIL`.

Keep `.env` private and never commit it or paste its contents into chat.
