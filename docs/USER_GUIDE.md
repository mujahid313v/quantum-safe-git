# Quantum-Safe Git (QSGit) – User Guide

This guide covers everyday tasks for developers, administrators, and end-users of QSGit.

## Table of Contents
1. [Quick Start](#quick-start)
2. [Signing Commits](#signing-commits)
3. [Verifying Signatures](#verifying-signatures)
4. [Key Management](#key-management)
4.1. [Generating a Key Pair](#generating-a-key-pair)
4.2. [Importing from Hardware Tokens](#importing-from-hardware-tokens)
4.3. [Rotating Keys](#rotating-keys)
5. [Desktop UI](#desktop-ui)
6. [IDE Extensions](#ide-extensions)
7. [CI/CD Integration](#cicd-integration)
8. [Troubleshooting](#troubleshooting)
9. [FAQ](#faq)

---

## Quick Start

1. **Clone the repository** (if it's your own):
   ```bash
   git clone https://github.com/your-org/quantum-safe-git.git my-project
   cd my-project
   ```

2. **Install the Git hook plugin** (one-time setup):
   ```bash
   # Download the latest pre-built binary
   curl -L https://github.com/your-org/quantum-safe-git/releases/download/v1.0.0/git_hook -o ~/.git_ext/git_hook
   chmod +x ~/.git_ext/git_hook
   ```

3. **Start the signature service** (optional, for local verification):
   ```bash
   docker compose up -d signature-service
   ```

4. **Open your project in an IDE** (VS Code, IntelliJ) – the extension will automatically detect QSGit.

You're now ready to commit with quantum-safe signatures!

---

## Signing Commits

When the plugin is active, every `git commit` is automatically signed:

```bash
# Normal commit – QSGit will embed a Dilithium signature
git commit -m "Implement PQC signing flow"
```

**What happens under the hood:**
1. The pre-commit hook extracts the commit tree, author, message, and timestamps.
2. It sends a signing request to the Signature Service.
3. The service fetches the default key (or prompts for authentication) and signs with Dilithium-3.
4. The signature is appended to the commit message as a Git trailer:
   ```
   OQS-Signature: <base64-encoded-signature>
   OQS-Algorithm: Dilithium3
   OQS-Signed-At: 2025-02-12T14:35:00Z
   ```

You can view the signature in the commit log:

```bash
git log --pretty=fuller
```

---

## Verifying Signatures

### From the Command Line

Use the built-in CLI tool:

```bash
# Verify all commits in the repository (non-interactive)
qsg-verify verify-repo .

# Verify a specific commit
qsg-verify verify <commit-hash>
```

If any commit is unsigned or invalid, `qsg-verify` exits with a non-zero code and prints details:

```
❌ Commit abc123… failed verification:
   - Missing OQS signature trailer
   - Invalid signature: bad signature format
```

### Desktop UI

Launch the Electron app (`npm start` from the `ui/` folder). The dashboard shows:

- **Repository status**: % of signed commits.
- **Commit timeline**: Click a commit to view signature details.
- **Key management**: Add, export, or rotate keys.
- **Verification log**: Real-time status of background checks.

---

## Key Management

### Generating a Key Pair

Generate a new Dilithium key pair for a user:

```bash
# Interactive prompt for algorithm, output path, and optional passphrase
qsg-genkey --algorithm dilithium3 --output ./keys/alice
```

The command creates two files in the specified output directory:

- `<output>/public.pem` – Public key (base64 encoded)
- `<output>/private.key.enc` – Encrypted private key (AES-256-GCM, passphrase-protected)

**Example output:**

```
🔑 Generated new key pair:
   ID: alice@company.com
   Algorithm: Dilithium3
   Public Key: MIIBC... (base64)
   Private Key encrypted: saved to ./keys/alice/private.key.enc
```

### Importing from Hardware Tokens

If you already have keys on a YubiKey or Nitrokey, import them:

```bash
# YubiKey (requires YubiKey PIV/OTP support for PQC)
qsg-import --source yubikey://slot01 --key-id hardware1

# Nitrokey (Pro 2 with OpenPGP support)
qsg-import --source nitrokey:// --key-id hardware2
```

Imported keys are stored in a secure keystore and can be used for signing without re-generating.

### Rotating Keys

When a key expires or you suspect a compromise, rotate it:

```bash
# Generate a new key for the same identity
qsg-genkey --rotate --key-id alice --output ./keys/alice_new

# Switch signing to the new key (you can set default via config)
echo "default_key = alice_new" >> ~/.qsgit/config
```

After rotation, you can verify that both old and new keys work by explicitly specifying the key ID.

---

## Desktop UI

### Dashboard

The main window displays three panels:

1. **Repository Overview** – A gauge showing the percentage of signed commits.
2. **Commit Timeline** – A sortable list of recent commits with signature status icons.
3. **Key Management** – Quick actions for adding, exporting, and rotating keys.

### Sign-Status Indicator

When you edit a file and stage it, the UI shows a **small badge** next to the staged file:

```
[🔒 QSG] Ready to sign
```

Clicking the badge opens a preview of the signature that will be attached.

### Verification History

The **Verification** tab shows a chronological log of all `qsg-verify` runs, including:
- Timestamp
- Command used
- Result (✅ PASS / ❌ FAIL)
- Details (error messages, missing trailers)

You can export this log to CSV or JSON for downstream analysis.

---

## IDE Extensions

### VS Code Extension

Install via the VS Code Marketplace (`ext id: quantum-safe.git`).

**Features:**
- **Inline Status** – Shows a green lock icon next to signed commits in the Git history view.
- **Hover Info** – On hover, displays signature algorithm and signer.
- **Light-bulb Actions** – Offers "Sign commit with QSGit" if the commit is unsigned.

**Settings (JSON)** – Open `settings.json`:

```json
{
  "qsgit.autoSign": true,        // Automatically sign commits (default)
  "qsgit.defaultKey": "alice",   // Default signing key
  "qsgit.serviceUrl": "http://localhost:8080"
}
```

### IntelliJ IDEA Plugin

Similar functionality, with a dedicated **QSGit** tool window showing repository status and allowing manual signing of selected commits.

---

## CI/CD Integration

### GitHub Actions

Create a `.github/workflows/qsg-verify.yml`:

```yaml
name: QSGit Verify
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: '0'   # Get full history for verification

      - name: Install QSGit CLI
        run: |
          curl -L https://github.com/your-org/quantum-safe-git/releases/download/v1.0.0/qsg-verify -o qsg-verify
          chmod +x qsg-verify

      - name: Verify signatures
        run: ./qsg-verify verify-repo .
        env:
          QSG_SERVICE_URL: ${{ secrets.QSG_SERVICE_URL }}
```

### GitLab CI

Add `.gitlab-ci.yml`:

```yaml
stages:
  - verify

verify_qsg:
  stage: verify
  image: ubuntu:latest
  before_script:
    - apt-get update && apt-get install -y curl
    - curl -L https://github.com/your-org/quantum-safe-git/releases/download/v1.0.0/qsg-verify -o qsg-verify
    - chmod +x qsg-verify
  script:
    - ./qsg-verify verify-repo .
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Checkout') {
            steps {
                git url: 'https://github.com/your-org/quantum-safe-git.git'
            }
        }
        stage('Verify') {
            steps {
                sh '''
                    curl -L https://github.com/your-org/quantum-safe-git/releases/download/v1.0.0/qsg-verify -o qsg-verify
                    chmod +x qsg-verify
                    ./qsg-verify verify-repo .
                '''
            }
        }
    }
}
```

---

## Troubleshooting

### Common Issues & Solutions

| Symptom | Cause | Fix |
|---------|-------|-----|
| `qsg-verify` not found | Binary not in PATH | Add `./qsg-verify` to PATH or use full path |
| "Permission denied" when signing | Git hook binary not executable | `chmod +x ~/.git_ext/git_hook` |
| "Signature validation failed" | Wrong key or corrupted payload | Verify key ID, re-sign with correct key |
| "Service unavailable" error | Signature Service not running | `docker compose up -d signature-service` |
| IDE extension not showing lock icon | Extension not installed or disabled | Re-install extension, restart IDE |

---

## FAQ

**Q: Do I need to install anything extra for the first commit?**
A: Yes, the Git hook plugin must be installed once. After that, every commit is automatically signed.

**Q: Can I use QSGit with existing GPG-signed repos?**
A: Yes. QSGit coexists with GPG; you can choose which signature to keep. QSGit will add an additional OQS signature.

**Q: What happens if my machine reboots?**
A: The Git hook plugin runs automatically on startup because it's registered as a system service (via `~/.git_ext`). The Signature Service can be started as a Docker container or systemd service.

**Q: How does key storage work in the cloud?**
A: QSGit supports AWS KMS, Azure Key Vault, and GCP KMS. You configure the service URL and credentials; the service calls the cloud provider's API to generate temporary signing credentials.

**Q: Can I audit all signing events?**
A: Absolutely. Every signing event is logged to Elasticsearch (or your chosen log store) and can be queried via the Kibana dashboard or exported as JSON/CSV.

---

## Support & Community

- **GitHub Issues:** `[https://github.com/your-org/quantum-safe-git/issues]`
- **Discussions:** `[https://github.com/your-org/quantum-safe-git/discussions]`
- **Slack/Discord:** Invite links posted on the website.

For enterprise-grade support, contact `support@yourcompany.com`.

---

*Version 1.0.0 – February 2025*
