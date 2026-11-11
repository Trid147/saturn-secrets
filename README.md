# 🪐 Saturn Secrets

A self-hosted, zero-tracking, one-time secret sharing service built with **FastAPI**, **Podman**, **Ansible**, and **Nginx**. Designed with a security-first (DevSecOps) architecture to safely share passwords, API keys, and sensitive notes via self-destructing links.

🌐 **Live Demo:** [https://saturn-secrets.ru](https://saturn-secrets.ru)

---

## 🛡️ Security & DevSecOps Features

* **Encryption at Rest:** All secrets are symmetrically encrypted using **Fernet (AES-128-CBC + HMAC-SHA256)** before touching the SQLite database.
* **Burn-After-Reading & TTL:** Secrets are permanently wiped from the database immediately upon first view or automatically purged once their expiration timer (`1h`, `24h`, `7d`) elapses.
* **Granular Access Control:** Authenticated users can restrict secret links using username **Whitelists** or **Blacklists**, plus manually shred active secrets from their dashboard (protected against IDOR).
* **Hardened Authentication:** Passwords hashed with **Bcrypt**; session state managed via signed **JWTs** stored in `HttpOnly`, `Secure`, `SameSite=Lax` cookies.
* **Self-Hosted Anti-Spam CAPTCHA:** Stateless, zero-tracking math challenge signed with short-lived JWTs to prevent automated registration spam without third-party scripts.
* **Container & Network Isolation:** Packaged as a container image on **GitHub Container Registry (`ghcr.io`)**, bound strictly to `127.0.0.1:8000` behind an **Nginx** reverse proxy with **UFW** firewall rules and automated **Let's Encrypt TLS/HTTPS**.
* **Infrastructure as Code (IaC):** Fully automated VDS provisioning, container updates, and SSL configuration via **Ansible**.

---

## 🏗️ Architecture

```text
[ User Browser ]
       │  HTTPS (Port 443 / TLS 1.3)
       ▼
[ Nginx Reverse Proxy + Let's Encrypt ]
       │  Internal Loopback (127.0.0.1:8000)
       ▼
[ Podman Container (FastAPI + Uvicorn) ] ──► [ Persistent Host Volume (SQLite) ]
```

---

## 🚀 Quick Local Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Trid147/saturn-secrets
   cd saturn-secrets
   ```

2. **Create a `.env` file:**
   ```env
   SECRET_KEY=your_jwt_secret_key
   HTTPS_ENABLED=false
   ```

3. **Run with Podman Compose:**
   ```bash
   mkdir -p data
   podman-compose up -d --build
   ```
   Open `http://127.0.0.1:8000` in your browser.

---

## ⚙️ Automated Production Deployment (Ansible)

Deploy or update the application on an Ubuntu VDS using the included Ansible playbook:

```bash
ansible-playbook -i inventory.ini playbook.yml
```