# BB LTI Tester

A local LTI 1.3 tool tester for Blackboard Learn. Receives and inspects LTI launch JWTs from Blackboard via a browser-based dashboard — no code changes needed between launches.

## What it does

- Completes the full LTI 1.3 OIDC login flow (GET `/oidc-login` → redirect to Blackboard → POST `/redirect`)
- Validates the signed JWT from Blackboard using their published JWKS
- Displays decoded claims in a structured inspector: user info, roles, context, resource link, AGS/NRPS services, and Blackboard-specific extensions
- Shows your ngrok public URL for registering in the Developer Portal
- Exposes your tool's own JWKS endpoint at `/jwks` (for Deep Linking response signing)

## Prerequisites

- Python 3.8+
- [ngrok](https://ngrok.com/download) (required for real Blackboard launches — Blackboard needs a public HTTPS URL)
  ```
  brew install ngrok/ngrok/ngrok
  ngrok config add-authtoken <your-token>
  ```

## Quick Start

```bash
git clone <your-repo-url> bb-lti-tester
cd bb-lti-tester
chmod +x start.sh stop.sh
./start.sh
```

The script will:
1. Create a Python virtual environment and install dependencies
2. Generate RSA keys in `keys/` (auto, first run only)
3. Start the FastAPI server on port 8080
4. Start an ngrok tunnel (if ngrok is installed)
5. Open `http://localhost:8080` in your browser

## 5-Step Setup

### Step 1 — Start the tool
Run `./start.sh`. Note the ngrok URL printed in the terminal (e.g. `https://abc123.ngrok-free.app`).

### Step 2 — Register in the Blackboard Developer Portal
Go to [developer.blackboard.com](https://developer.blackboard.com) → My Apps → Create App.

| Field | Value |
|-------|-------|
| OIDC Login Initiation URL | `https://<ngrok-url>/oidc-login` |
| OIDC Redirect URL(s) | `https://<ngrok-url>/redirect` |
| JWKS URL | `https://<ngrok-url>/jwks` |

After saving, copy your **Client ID**.

### Step 3 — Configure this tool
Open the dashboard → Settings. Enter:
- **Client ID** — from the Developer Portal
- **OIDC Auth URL** — `https://developer.blackboard.com/api/v1/gateway/oidcauth`
- **Blackboard JWKS URL** — `https://developer.blackboard.com/api/v1/management/applications/keys`

Click **Save Configuration**.

### Step 4 — Register in Blackboard Learn
In your Learn instance: **System Admin → LTI Tool Providers → Register LTI 1.3 Tool**. Enter your Client ID and approve the tool to get a **Deployment ID**.

### Step 5 — Place and launch the tool
In a course: **Edit content area → Build Content → LTI Tool**. Select your tool, submit, then click the link. The launch will appear on the Launches page.

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Redirects to dashboard |
| `/oidc-login` | GET | LTI OIDC login initiation — Blackboard calls this first |
| `/redirect` | POST | LTI redirect endpoint — receives the signed JWT |
| `/jwks` | GET | This tool's public key (for Deep Linking response verification) |
| `/api/status` | GET | Server status, ngrok URL, config completeness |
| `/api/launches` | GET | List of received launches (no raw token) |
| `/api/launches/{id}` | GET | Full launch detail including raw JWT |
| `/api/launches` | DELETE | Clear all launches |
| `/api/config` | GET | Current configuration |
| `/api/config` | POST | Save configuration |
| `/api/ngrok` | GET | Current ngrok public URL |

## Stopping the server

```bash
./stop.sh
```

Or press `Ctrl+C` in the terminal running `start.sh`.

## Files

```
bb-lti-tester/
├── server.py          # FastAPI app — all server logic
├── requirements.txt   # Python dependencies
├── start.sh           # Start server + ngrok
├── stop.sh            # Stop server + ngrok
├── settings.json      # Created on first save (gitignored)
├── keys/              # Auto-generated RSA key pair (gitignored)
└── static/
    └── index.html     # Single-file SPA dashboard
```
