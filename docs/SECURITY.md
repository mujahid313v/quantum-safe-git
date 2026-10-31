# Quantum-Safe Git (QSGit) – Security Guide

This document outlines security considerations, threat models, and best practices for deploying and operating QSGit in production environments.

## Table of Contents
1. [Security Overview](#security-overview)
2. [Threat Model](#threat-model)
3. [Secure Deployment Checklist](#secure-deployment-checklist)
4. [Key Management Best Practices](#key-management-best-practices)
5. [Compliance & Standards](#compliance--standards)
6. [Incident Response](#incident-response)
7. [Security Testing](#security-testing)
8. [Future Threat Landscape](#future-threat-landscape)

---

## Security Overview

QSGit introduces a **new cryptographic layer** into the Git workflow. While the algorithms themselves (Dilithium, Falcon) are quantum-resistant, the overall security of the system depends on proper configuration, secure coding practices, and operational hygiene.

### Core Security Goals
- **Confidentiality:** Private keys are never exposed in logs or transmitted over unencrypted channels.
- **Integrity:** Signed commits cannot be tampered with without detection.
- **Availability:** The signing service remains operational and responsive to legitimate clients.
- **Non-repudiation:** Signers cannot deny having authored a commit.
- **Forward Secrecy:** Compromise of long-term keys does not jeopardize past signatures.

### Security Layers
1. **Transport Layer:** TLS 1.3 with mutual authentication.
2. **Application Layer:** gRPC with built-in encryption and payload authentication.
3. **Data Store Layer:** Hardware-backed or cloud KMS with strict access controls.
4. **Host Layer:** Container isolation (Docker, Kubernetes), least-privilege OS users.
5. **Operational Layer:** Auditing, logging, key rotation, incident response.

---

## Threat Model

| Threat | Description | Likelihood | Impact | Mitigation |
|--------|-------------|------------|--------|------------|
| **Private Key Exposure** | An attacker obtains the private key (hardware breach, misuse) | Medium | Critical | Hardware security modules, encrypted storage, MFA |
| **Man-in-the-Middle (MITM)** | Intercept or modify signing/verification messages | Medium | High | Mutual TLS, certificate pinning |
| **Replay Attacks** | Replay a previously captured signing request | Low | Medium | Timestamps, nonces, caching |
| **Denial of Service (DoS)** | Overload the signature service | High | Medium | Rate limiting, load balancing, autoscaling |
| **Supply-Chain Compromise** | Malicious build pipeline injecting malicious code | Low | Critical | Sigstore, reproducible builds |
| **Side-Channel Attacks** | Extract secrets via timing, power analysis | Low (hardware) | High | Constant-time implementations, HSMs |
| **Insider Threat** | Rogue admin with privileged access | Medium | High | Separation of duties, audit logs, immutable storage |

---

## Secure Deployment Checklist

### Infrastructure Setup
- [ ] **Network Isolation:** Deploy QSGit in a dedicated VPC/subnet with restricted inbound/outbound rules.
- [ ] **Container Security:** Use minimal base images (`alpine`, `distroless`), run containers as non-root users.
- [ ] **Resource Limits:** Define CPU/memory requests/limits in Kubernetes to prevent noisy neighbors.
- [ ] **TLS/SSL:** Enable TLS 1.3, use CA-signed certificates, and enforce HSTS.
- [ ] **Secrets Management:** Store all credentials in a hardened vault (AWS KMS, Azure Key Vault, HashiCorp Vault).

### Application Hardening
- [ ] **Principle of Least Privilege:** Run Git hooks and Signature Service with limited OS permissions.
- [ ] **Code Review:** Conduct security reviews for all changes to the signing logic.
- [ ] **Dependency Scanning:** Use tools like `npm audit`, `cargo audit`, `go mod tidy` to identify vulnerable dependencies.
- [ ] **Fuzz Testing:** Run fuzz tests on signing/verification endpoints.
- [ ] **Memory Safety:** Rust and Go code are already memory-safe; ensure no unsafe blocks bypass checks.

### Operational Practices
- [ ] **Key Rotation:** Automate periodic key rotation (e.g., every 90 days) with secure backup.
- [ ] **Audit Logging:** Log all signing/verification events to an immutable store (WORM S3, Elasticsearch with retention).
- [ ] **Monitoring & Alerting:** Set up Prometheus alerts for anomalies (high latency, repeated failures).
- [ ] **Incident Response:** Define a documented process for suspected breaches (e.g., key compromise).

---

## Key Management Best Practices

### Generating Keys
- Use strong, randomly generated entropy.
- Store the private key **encrypted** with a strong passphrase.
- Keep a **backup** in a geographically separate location (air-gapped if possible).

```bash
# Example: Generate a Dilithium key pair with a passphrase
qsg-genkey --algorithm dilithium3 --output ./keys/alice \
  --passphrase-file ./keys/alice.pass
```

### Secure Storage
- **Hardware Security Modules (HSM):** YubiKey FIPS series, Nitrokey Pro 2, or dedicated HSM appliances.
- **Cloud KMS:** Leverage managed services that handle key provisioning, rotation, and audit trails.
- **Software Wallets:** If software storage is unavoidable, use OS-level keychains (macOS Keychain, Windows Credential Manager, Linux Secret Service) with additional encryption.

### Key Rotation
1. **Generate new key pair.**
2. **Update configuration** to point to the new key.
3. **Re-sign critical commits** (optional, depending on policy).
4. **Archive old key** securely (encrypt, then destroy after retention period).

### Access Controls
- **Role-Based Access Control (RBAC):** Only authenticated users with specific roles can sign or verify.
- **Multi-Factor Authentication (MFA):** Enforce MFA for any privileged operations.
- **Audit Logs:** Record who accessed keys, when, and for what purpose.

---

## Compliance & Standards

### NIST SP 800-57 Part 1 (Key Management)

QSGit follows the NIST guidelines for key lifecycle management:

- **Key Generation:** Use cryptographically secure random number generators.
- **Key Distribution:** Keys never leave the hardware; cloud KMS handles distribution via secure APIs.
- **Key Storage:** Encrypted at rest; hardware-backed for sensitivity.
- **Key Usage:** Signing operations are logged and auditable.
- **Key Disposal:** Secure deletion of private keys after their lifecycle.

### ISO/IEC 27001 (Information Security Management)

- **Risk Assessment:** QSGit can be integrated into existing ISMS processes.
- **Access Control:** RBAC and MFA align with ISO controls.
- **Incident Management:** Defined procedures for handling security incidents involving signing infrastructure.
- **Continuous Improvement:** Regular security reviews and updates.

### GDPR / CCPA (Data Protection)

- **Data Minimization:** Only necessary metadata (author, timestamp) is logged.
- **Right to be Forgotten:** Users can request deletion of their keys and associated logs.
- **Data Portability:** Public keys can be exported for interoperability.

---

## Incident Response

### Preparation Phase
1. **Define Roles:** Incident response team, security leads, infrastructure engineers.
2. **Communication Plan:** Pre-agreed channels (Slack, email, phone trees).
3. **Tooling:** SIEM (Splunk, Elastic), ticketing (Jira), forensic capture (disk images, logs).

### Detection Phase
- Monitor:
  - Unusual spikes in signing/verification latency.
  - Unexpected `verification_requests_total` failures.
  - Unauthorized access attempts in audit logs.
- Alert triggers → immediate notification to the response team.

### Containment Phase
- Isolate the affected component (e.g., Kubernetes pod).
- Disable the compromised key (revoke, generate new).
- Preserve logs for forensic analysis.

### Eradication & Recovery
- Identify root cause (e.g., malicious code in the signing service).
- Patch vulnerable code, update dependencies.
- Restore services from known-good state (if needed).
- Validate that signatures are still valid (re-sign critical commits).

### Post-Incident Activities
- Conduct a lessons-learned meeting.
- Update security policies and procedures.
- Improve monitoring and alerting based on findings.

---

## Security Testing

### Static Application Security Testing (SAST)
- **Tooling:** `semgrep`, `bandit` (Python), `gosec` (Go), `cargo audit` (Rust).
- **Goal:** Detect potential vulnerabilities (e.g., SQL injection, buffer over-reads) in the codebase.

### Dynamic Application Security Testing (DAST)
- **Tooling:** `owasp zap`, `burpsuite`, `nmap`.
- **Goal:** Test the Signature Service endpoints for common web vulnerabilities (authentication bypass, injection, etc.).

### Fuzz Testing
- **Tooling:** `libfuzzer` (Rust), `go-fuzz`, `radamsa`.
- **Target:** Signing/verification gRPC methods with random inputs to uncover crashes or unexpected behavior.

### Penetration Testing
- **Approach:** Engage an external security firm to simulate real-world attacks (e.g., network intrusion, social engineering).
- **Scope:** Production-grade Kubernetes cluster, cloud KMS integration, on-prem key storage.

### Red Team / Blue Team Exercise
- **Red Team:** Attempt to compromise keys, intercept signing requests, or inject malicious commits.
- **Blue Team:** Detect, respond, and recover from the attempted breach.

---

## Future Threat Landscape

### Quantum Computing Advances
- **Short-term (2025-2030):** Small, specialized quantum computers may pose a theoretical threat to classical signatures but are unlikely to break well-parameterized post-quantum schemes like Dilithium.
- **Long-term (2030+):** General-purpose quantum computers could potentially break certain lattice-based schemes if implementations are flawed. QSGit's architecture allows swapping algorithms with minimal code changes.

### Emerging Standards
- **NIST Post-Quantum Cryptography Standardization (Round 4):** Ongoing evaluations; QSGit will adopt finalized algorithms as they become stable.
- **IETF TLS 1.3 Extensions:** Post-quantum key exchange mechanisms (e.g., HPKE) may be integrated for secure channel establishment.

### Zero-Trust Network Access (ZTNA)
- Future QSGit versions may embed ZTNA capabilities, ensuring that only authenticated and authorized Git clients can reach the signing service.

---

## Appendix

### Glossary

| Term | Definition |
|------|------------|
| **Dilithium** | NIST-selected lattice-based digital signature algorithm. |
| **Falcon** | NIST-selected compact signature scheme. |
| **HSM** | Hardware Security Module – dedicated cryptographic processor. |
| **KMS** | Key Management Service – cloud-based key management. |
| **RBAC** | Role-Based Access Control – permission model based on roles. |
| **WORM** | Write-Once, Read-Many – storage that prevents modification. |
| **SIEM** | Security Information and Event Management – centralized log collection and analysis. |

### References

1. NIST SP 800-57 Part 1 – Key Management.
2. NIST Post-Quantum Cryptography Standardization Round 4.
3. ISO/IEC 27001:2018 – Information security management.
4. TLS 1.3 RFC 8446.
5. Open Quantum Safe (OQS) – liboqs documentation.

---

*Version 1.0.0 – February 2025*
