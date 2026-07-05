<!-- Tip: PR/commit titles in this repo tend to use a "type: description" style, e.g. "fix: ...", "docs: ...", "feat: ..." -->

## Summary

<!-- What does this PR do, and why? -->

<!-- If this closes an issue, put the number below, e.g. "Closes #123" -->
Closes #

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Docs
- [ ] Refactor / internal (no user-facing change)
- [ ] Other:

## Checklist

- [ ] `pytest -v` passes locally (`pip install -e ".[dev]"` first — see [CONTRIBUTING.md](https://github.com/jestasecurity/thumper/blob/main/CONTRIBUTING.md))
- [ ] For UI changes: verified with `cd ui && npm install && npm run dev`
- [ ] For a new/changed plugin: follows [docs/plugins.md](https://github.com/jestasecurity/thumper/blob/main/docs/plugins.md)
- [ ] For a new honeytoken type: follows [docs/tokens.md](https://github.com/jestasecurity/thumper/blob/main/docs/tokens.md)
- [ ] Added a one-line entry under `## [Unreleased]` in [CHANGELOG.md](https://github.com/jestasecurity/thumper/blob/main/CHANGELOG.md) (skip for internal-only changes)
- [ ] PR is scoped to the linked issue — no unrelated changes

## Testing notes

<!-- How did you verify this? Manual steps, new/updated tests, edge cases considered. -->
