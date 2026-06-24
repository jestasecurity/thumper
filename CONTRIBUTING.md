# Contributing

1. Fork the repo, create a branch, open a PR against `main`.
2. **Sign your commits** (GPG or SSH). Unsigned commits will not be merged. See [GitHub's guide](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits) for setup.
3. Run `pip install -e ".[dev]"` and make sure `pytest -v` passes before submitting.
4. For UI work: `cd ui && npm install && npm run dev`.
5. For plugins, see [docs/plugins.md](docs/plugins.md).

Report security vulnerabilities privately - see [SECURITY.md](SECURITY.md).

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).
