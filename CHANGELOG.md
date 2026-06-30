# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Fixed

## [0.1.0] - unreleased

Initial release: control-plane server, endpoint agent, dashboard UI, and the plugin system.

### Added

- **Server**: FastAPI control plane with SQLite/Postgres/MySQL support via SQLAlchemy + Alembic,
  and signed tripwire-trigger callbacks with replay protection.
- **Agent**: standalone Bash endpoint agent (`agent/thumper_agent.sh`, curl + openssl only, no
  Python dependency) that plants honeytoken files and reports reads back to the server.
- **UI**: React/Vite dashboard for creating tripwires, managing the enrolled endpoint fleet, and
  viewing the live alert feed.
- **Honeytoken types**: five built-in types — `aws`, `github`, `gcp`, `azure`, `ssh`. Each
  generated with a realistic-but-non-functional credential shape.
- **Alert plugins**: generic webhook, Splunk (HEC), Loki.
- **Deploy plugins**: SSH (direct) and MDM (Jamf Pro).
- **Deployment**: single Docker image (`docker compose up --build`) and a Helm chart for
  Kubernetes (`deploy/helm/thumper`).

[Unreleased]: https://github.com/jestasecurity/thumper/compare/v0.0.0...HEAD
[0.1.0]: https://github.com/jestasecurity/thumper/releases/tag/v0.1.0
