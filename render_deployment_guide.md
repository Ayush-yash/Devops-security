# Render Deployment Guide for ShieldOps Platform

Because ShieldOps is designed as a single-repo monolith, deploying it to Render is extremely simple. Render will build the project and serve both the frontend UI and the backend APIs under a single Web Service.

You will need to deploy **three components** on Render:
1. **Render PostgreSQL** (Managed Database)
2. **Render Web Service** (Serves the UI & APIs)
3. **Render Background Worker** (Processes the scanning jobs queue)

---

## Step 1: Create a PostgreSQL Database on Render
1. Go to your Render Dashboard and click **New > Database**.
2. Configure:
   - **Name**: `shieldops-db`
   - **Database Name**: `shieldops`
   - **User**: `shieldops`
3. Click **Create Database**.
4. Once created, copy the **Internal Database URL** (e.g., `postgres://shieldops:password@host/shieldops`). You will need this for the other services.

---

## Step 2: Deploy the Web Service (UI + APIs)
1. Click **New > Web Service**.
2. Connect your GitHub repository: `https://github.com/Ayush-yash/Devops-security`.
3. Configure the settings:
   - **Name**: `shieldops-api`
   - **Environment**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `node server.js`
4. Add the following **Environment Variables**:
   - `DATABASE_URL`: *(Paste the Internal Database URL from Step 1)*
   - `PORT`: `10000` *(Render sets this automatically)*
   - `GITHUB_WEBHOOK_SECRET`: `your_webhook_secret_key`
5. Click **Deploy Web Service**. Render will build and host your Web UI at `https://shieldops-api.onrender.com`.

---

## Step 3: Deploy the Background Worker (Scanner Queue)
The worker runs compute-heavy security scans asynchronously. On Render, we deploy it as a Background Worker:
1. Click **New > Background Worker**.
2. Connect the same GitHub repository: `https://github.com/Ayush-yash/Devops-security`.
3. Configure:
   - **Name**: `shieldops-worker`
   - **Environment**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `node worker.js`
4. Add the **Environment Variables**:
   - `DATABASE_URL`: *(Paste the Internal Database URL from Step 1)*
5. Click **Deploy**. This worker will now poll the database queue and process job runs.
