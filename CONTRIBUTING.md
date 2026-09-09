# Contributing to Vexa Agent Control

Thank you for your interest in contributing to **Vexa Agent Control**! Whether you are reporting a bug, improving documentation, submitting a performance optimization, or proposing a new integration, we welcome and appreciate your contributions.

---

## Code of Conduct

We are dedicated to providing a welcoming, inclusive, and harassment-free experience for everyone. Please be respectful, constructive, and collaborative in all communications, whether on GitHub, Discord, or community channels.

---

## Reporting Bugs & Security Issues

- **Security Vulnerabilities:** Do **NOT** report security vulnerabilities via public GitHub issues. Please refer to our [Security Policy](SECURITY.md) and report via [GitHub Private Vulnerability Reporting](https://github.com/noviqtechnologies/Vexa-Agent-Control/security/advisories/new) or by emailing [`contact@vexasec.io`](mailto:contact@vexasec.io).
- **General Bugs:** Please check existing [GitHub Issues](https://github.com/noviqtechnologies/Vexa-Agent-Control/issues) first. If no existing issue covers your bug, open a new issue detailing your OS, Vexa version (`agentcontrol --version`), configuration file snippet, and steps to reproduce.

---

## Development Setup

### Prerequisites
- **Rust Toolchain:** Stable Rust 1.80+ (`rustup default stable`)
- **Go:** 1.22+ (only required if developing against `control-plane/api`)
- **Docker & Docker Compose:** (optional, for running local integration test beds)

### Building the Project
```bash
# Clone repository
git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
cd Vexa-Agent-Control

# Verify compilation
cargo check

# Run unit and integration tests
cargo test

# Check code formatting and linter
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

---

## Pull Request Guidelines

### 1. Semantic Commit Messages
We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification. Prefix your commit messages and PR titles with one of the following:
- `feat:` Additive, backward-compatible feature
- `fix:` Bug or defect fix
- `perf:` Performance optimization
- `docs:` Documentation updates or additions
- `refactor:` Code refactoring without behavioral alterations
- `test:` Adding or correcting tests
- `chore:` Build scripts, dependencies, or toolchain updates

### 2. Semantic Versioning (SemVer) Discipline
To maintain clarity for our users and enterprise consumers, PRs should align with our [Versioning and Release Policy](docs/reference/versioning-and-releases.md):
- **`semver:patch`**: Fixes bugs, security issues, documentation errors, or performance regressions without introducing new configuration keys or capabilities.
- **`semver:minor`**: Introduces new features, new model provider adapters, new CLI commands, or backward-compatible configuration directives.
- **`semver:major`**: Introduces breaking changes to configuration syntax, removed CLI flags, or wire protocol changes.

### 3. Developer Certificate of Origin (DCO)
All commits must be signed off to confirm that you have the right to submit the code under the project's [Apache 2.0 License](LICENSE). Use the `-s` flag when committing:
```bash
git commit -s -m "fix(scanner): correct boundary regex for bearer token detection"
```

### 4. PR Review Checklist
Before marking your PR as ready for review:
- [ ] Code compiles cleanly with `cargo check` and `cargo clippy`.
- [ ] Existing tests pass (`cargo test`).
- [ ] New functionality includes corresponding unit or integration tests.
- [ ] Any changes to CLI flags, configuration YAML schema, or environment variables are documented in `docs/reference/`.
- [ ] No secrets, credentials, or personal keys are included.
