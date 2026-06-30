# Contributing

1. Fork the repo, create a branch, open a PR against `main`.
2. Run `pip install -e ".[dev]"` and make sure `pytest -v` passes before submitting.
3. For UI work: `cd ui && npm install && npm run dev`.
4. For plugins, see [docs/plugins.md](docs/plugins.md).
5. For honeytoken types, see [docs/tokens.md](docs/tokens.md).
6. If your change is user-facing, add a one-line entry under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md).

Report security vulnerabilities privately - see [SECURITY.md](SECURITY.md).

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).
