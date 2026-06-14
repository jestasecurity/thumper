<div align="center">
  <p>
    <a href="https://jesta.ai">
      <img width="150" src="ui/public/thumper_gif.gif" alt="Thumper" />
    </a>
  </p>
  <h1>Thumper</h1>
  <p align="center">
  Plant fake-but-realistic credentials where the <a href="https://www.cisa.gov/news-events/alerts">Shai-Hulud</a>
  npm supply-chain worm scans - and get alerted the instant one is read.
  <br />
  The tokens authenticate to nothing. A <b><em>read</em></b> is the signal.
  </p>
  <p>
  <a href="docs/architecture.md"><strong>Get started »</strong></a>
</p>
<p align="center">
   <img src="https://img.shields.io/badge/release-v0.1.0-yellow.svg" alt="PRs welcome" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License" /></a>
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs welcome" />
</p>
</div>
<p>
Thumper is your self-hosted honeytoken platform for trapping attackers inside your environment. You create tripwires, distribute them across your fleet, and each machine plants unique bait.
  When an attacker-controlled process touches the bait, Thumper <b>immediately</b> triggers an alert. <br/>
  It's built and maintained by Jesta under the Apache 2.0 license.
</p>

<p>
<h2>🚀 Getting Started</h1>
The whole stack comes as **one Docker image**:

```bash
docker compose up --build        # → http://localhost:8000
```

That's it. Open the dashboard, create a tripwire, and ship it.

<details>
<summary>Run it from source instead (dev mode)</summary>

```bash
# backend (Python 3.10+)
pip install -e .
uvicorn thumper.main:app --reload --app-dir server     # → http://localhost:8000

# UI (separate terminal) — Vite proxies /api to the backend
cd ui && npm install && npm run dev                     # → http://localhost:5173
```
</details>
</p>

<p>
<h2>🌱 Contributing</h2>
Refer to <a href="CONTRIBUTING.md">CONTRIBUTING.md</a>
</p>
