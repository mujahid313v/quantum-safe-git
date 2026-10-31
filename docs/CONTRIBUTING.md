# Quantum-Safe Git (QSGit) – Contributing Guide

Thank you for considering contributing to QSGit! This guide outlines the project's contribution workflow, coding standards, and how to get your changes reviewed and merged.

## Table of Contents
1. [Getting Started](#getting-started)
2. [Branching Strategy](#branching-strategy)
3. [Code Review Process](#code-review-process)
4. [Commit Message Conventions](#commit-message-conventions)
5. [Testing](#testing)
6. [Documentation](#documentation)
7. [Security Considerations](#security-considerations)
8. [Licensing & Attribution](#licensing--attribution)
9. [Acknowledgments](#acknowledgments)

---

## Getting Started

### Prerequisites

Before you start contributing, ensure you have:

- **Git** (`>=2.30`) and **Git LFS** for large files.
- **Rust** (`cargo`) – for the Git hook plugin.
- **Go** (`go`) – for the signature service.
- **Node.js** (`npm`) – for the desktop UI and IDE extensions.
- **Docker** – for local development and testing.

### Clone the Repository

```bash
git clone https://github.com/your-org/quantum-safe-git.git qsgit
cd qsgit
```

### Set Up the Development Environment

```bash
# Start services (signature service, UI, etc.)
docker compose up -d

# Install the Git hook plugin (add to your local git ext)
./scripts/install_hook.sh
```

---

## Branching Strategy

We use **Git Flow** with the following primary branches:

- **`main`** – Production-ready code.
- **`develop`** – Pre-release integration branch.
- **`feature/<name>`** – New feature work.
- **`bugfix/<name>`** – Bug fixes.
- **`release/<version>`** – Release preparation.

**Workflow:**
1. Create a feature/bugfix branch from `develop`.
2. Implement, test, and commit.
3. Push the branch to the remote repository.
4. Open a **Pull Request (PR)** against `develop`.

---

## Code Review Process

### Pull Request Checklist

When opening a PR, ensure the following checklist is completed:

- [ ] **Code compiles** (both Rust and Go) without errors.
- [ ] **Tests pass** locally (`cargo test`, `go test ./...`).
- [ ] **Code coverage** ≥80% (new code) – run `cargo tarpaulin` and `go coverage`.
- [ ] **Linting** passes (`cargo clippy`, `gofmt -l`, `eslint`).
- [ ] **Documentation** (README, docstrings) is updated.
- [ ] **Security review** – no exposed secrets, proper key handling.
- [ ] **Changelog entry** added (see `CHANGELOG.md`).

### Review Steps

1. **Automatic Checks** – GitHub Actions will run CI pipelines (lint, test, build).
2. **Human Review** – Your PR will be assigned to a maintainer.
3. **Feedback Loop** – Address comments, push updated commits.
4. **Merge** – Once approved, the maintainer merges the PR into `develop`.

**Note:** All changes to the `main` branch must be released via a proper `release/<version>` branch to ensure a clean changelog.

---

## Commit Message Conventions

Follow these guidelines to keep a clear commit history:

```
<type>(<scope>): <short description>

<body>

<footer>
```

### Types

| Type | Description |
|------|-------------|
| **feat** | New feature. |
| **fix** | Bug fix. |
| **docs** | Documentation only changes. |
| **style** | Changes that do not affect code logic (formatting, linting). |
| **refactor** | Code refactoring without functional changes. |
| **perf** | Performance improvements. |
| **test** | Adding or updating tests. |
| **chore** | Maintenance tasks (CI configs, scripts). |
| **security** | Security-related fixes or improvements. |

### Example

```
feat(signature): add Dilithium3 signing support

Implement Dilithium3 signing for Git commits, with automatic key generation and verification.

Co-authored-by: openhands <openhands@all-hands.dev>
```

---

## Testing

### Running Tests Locally

#### Rust (Git Hook Plugin)

```bash
# Run unit tests
cargo test

# Run integration tests (requires Docker)
cargo test -- --ignored

# Generate code coverage report (requires `cargo tarpaulin`)
cargo tarpaulin --output-dir ./reports/rust-coverage
```

#### Go (Signature Service)

```bash
# Run unit tests
go test ./...

# Run integration tests (requires external services)
go test ./... -tags=integration

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

#### TypeScript / JavaScript (Desktop UI)

```bash
cd ui
npm test   # Runs Jest tests
```

### CI Configuration

The project uses GitHub Actions to run tests on every push to `develop` and `main`. The workflow (`.github/workflows/qsg-verify.yml`) includes:

- **Linting** (`cargo clippy`, `gofmt -l`, `eslint`)
- **Unit Tests** (`cargo test`, `go test`)
- **Integration Tests** (Docker compose up, then run `qsg-verify`)

You can trigger this manually with:

```bash
# From the repo root
act -j verify   # requires `act` CLI
```

---

## Documentation

All documentation is written in **Markdown** and lives under `docs/`. When you add or modify features:

1. **Add docstrings** in the source code (Rust `///`, Go `//`).
2. **Update relevant `.md` files** (e.g., `USER_GUIDE.md`, `DEPLOYMENT.md`).
3. **Generate API docs** (e.g., `cargo doc --open`, `godoc`).

### Documentation Style

- Use **clear headings** (`##`, `###`).
- Include **code examples** in fenced blocks with language identifiers.
- Add **diagrams** (`graphviz`, `mermaid`) where helpful.
- Reference external standards (NIST, ISO) with proper citations.

---

## Security Considerations

Contributing to a cryptographic project carries special responsibility:

- **No hard-coded secrets** in source code or configuration files.
- **Validate input** for all external requests (e.g., key IDs, payloads).
- **Ensure constant-time algorithms** where timing attacks could be relevant.
- **Use hardware-backed storage** for private keys (HSM, YubiKey).
- **Conduct security reviews** before merging any changes to the signature logic.

If you discover a potential vulnerability, please report it responsibly via the GitHub Security Advisory channel.

---

## Licensing & Attribution

- The project is licensed under **Apache 2.0**.
- All contributors retain copyright to their contributions.
- Third-party dependencies must be listed in `LICENSE` and `THIRD-PARTY.md`.

When contributing, you must include the **Contributor License Agreement (CLA)** (if required) or acknowledge that your contribution is under the project's license.

---

## Acknowledgments

We gratefully acknowledge:

- **Open Quantum Safe (OQS)** – liboqs library enables post-quantum cryptography in Rust.
- **The Rust and Go ecosystems** – for providing robust, memory-safe tooling.
- **The open-source community** – for valuable libraries and continuous learning.
- **All contributors** – without whom this project would not exist.

---

*Version 1.0.0 – February 2025*
