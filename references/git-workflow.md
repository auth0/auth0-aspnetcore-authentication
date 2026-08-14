# Git Workflow

## Branch naming

`<type>/<short-description>`, e.g. `feat/SDK-6831`, `fix/token-refresh`, `docs/mtls-examples`.

## Commit messages

Imperative subject with a type prefix, matching repo history:

- `feat:` — new functionality
- `fix:` — bug fixes
- `docs:` — documentation only

Example: `feat: Adds support for configuring mtls using .WithMtls()`.

## Pull Requests

The default base branch is `main`. Fill in the local `.github/PULL_REQUEST_TEMPLATE.md`:

- **Description** — purpose, background, impact; call out breaking changes, alternatives, API changes.
- **References** — linked issue/PR/community post (delete if none).
- **Testing** — how reviewers test it; note anything not covered.
- **Checklist:**
  - [ ] This change adds test coverage for new/changed/fixed functionality
  - [ ] Added documentation for new/changed functionality (here or in auth0.com/docs)
  - [ ] All active GitHub checks (tests, formatting, security) are passing
  - [ ] The correct base branch is being used, if not `main`

CI runs Build and Test (matrix over the four TFMs), Snyk SCA, and ReversingLabs (`rl-secure`) on PRs to `main`.
