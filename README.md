<div align="center">
  <p align="center">
    <a href="https://jesta.ai">
      <img width="150" src="ui/public/thumper_gif.gif" alt="Thumper" />
    </a>
  </p>
  <h1 align="center">Thumper</h1>
  <p align="center">
  Plant fake-but-realistic credentials where the <a href="https://www.securityweek.com/?s=shai+hulud">Shai-Hulud</a>
  npm supply-chain worm scans - and get alerted the instant one is read.
  <br />
  The tokens authenticate to nothing. A <b><em>read</em></b> is the signal.
  </p>
  <p align="center">
  <a href="https://jesta.ai/thumper">Website</a>
  &nbsp;·&nbsp;
  <a href="https://jesta.ai/docs"><strong>Docs</strong></a>
  &nbsp;·&nbsp;
  <a href="docs/architecture.md">Get started »</a>
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

<h2>See it in action</h2>

<p align="center">
  <img src="assets/screens/dashboard.png" alt="Thumper dashboard - fleet overview and live alert feed" width="840" />
</p>

<p align="center">
  <img src="assets/screens/endpoints.png" alt="Enrolled endpoints" width="840" />
</p>

<p>
<h2>🚀 Getting Started</h1>
The whole stack comes as <b>one Docker image</b>:

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

# UI (separate terminal) - Vite proxies /api to the backend
cd ui && npm install && npm run dev                     # → http://localhost:5173
```
</details>

<details>
<summary>Deploy on Kubernetes (Helm)</summary>

A Helm chart lives in [`deploy/helm/thumper`](deploy/helm/thumper). Build and push the image from the `Dockerfile` first, then:

```bash
helm install thumper ./deploy/helm/thumper \
  --set image.repository=ghcr.io/jestasecurity/thumper \
  --set secrets.enrollToken=$(openssl rand -hex 24) \
  --set secrets.installToken=$(openssl rand -hex 24) \
  --set config.baseUrl=https://thumper.example.com
```

Defaults to SQLite on a PVC (single replica). Set `externalDatabase.url` for Postgres/MySQL. See [`values.yaml`](deploy/helm/thumper/values.yaml) for all options.
</details>
</p>

<h2>Architecture</h2>

Thumper has three components - a **server**, a **dashboard**, and an **endpoint agent** - shipped as a single Docker image. You create tripwires, deploy them to endpoints, and each machine plants unique bait. When a credential is read, the agent sends a signed callback and the server fans out to your configured alert plugins.

<p align="center">
  <img src="assets/architecture.svg" alt="Thumper architecture: operator, control plane, endpoint fleet" width="940" />
</p>

See [docs/architecture.md](docs/architecture.md) for the full architecture reference.

<h2>Plugins</h2>

Alerting and deployment are pluggable - drop a directory under `plugins/{alert,deploy}/` with a `manifest.yaml` and a `plugin.py`, restart the server, and it shows up in the dashboard with a generated config form.

- **Alert plugins** deliver fired-tripwire events to external systems
- **Deploy plugins** distribute the install command to machines

See [docs/plugins.md](docs/plugins.md) for the full guide.

<p>
<h2>🌱 Contributing</h2>
Refer to <a href="CONTRIBUTING.md">CONTRIBUTING.md</a>
</p>

<h2>💫 Contributors</h2>

<a href="https://github.com/jestasecurity/thumper/graphs/contributors">
  <img alt="contributors" src="https://contrib.rocks/image?repo=jestasecurity/thumper"/>
</a>
