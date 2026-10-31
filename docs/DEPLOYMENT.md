# Quantum-Safe Git (QSGit) – Deployment Guide

This document covers installation, configuration, and operation of QSGit components in various environments.

## Table of Contents
1. [Local Development Setup](#local-development-setup)
2. [Docker Deployment](#docker-deployment)
3. [Kubernetes Deployment](#kubernetes-deployment)
4. [Production Hardening](#production-hardening)
5. [Monitoring & Alerting](#monitoring--alerting)
6. [Backup & Disaster Recovery](#backup--disaster-recovery)
7. [Troubleshooting Production Issues](#troubleshooting-production-issues)

---

## Local Development Setup

### Prerequisites

- **Rust** (`cargo`) – for the Git hook plugin
- **Go** (`go`) – for the signature service
- **Node.js** (`npm`) – for the desktop UI
- **Docker** – for containerized services

### Step-by-Step

#### Clone the Repository

```bash
git clone https://github.com/your-org/quantum-safe-git.git qsgit
cd qsgit
```

#### Start the Signature Service (Docker)

```bash
# From the project root
docker compose up -d signature-service
```

#### Install the Git Hook Plugin

```bash
# Create the plugin directory
mkdir -p ~/.git_ext

# Download the latest release (replace with your version)
curl -L https://github.com/your-org/quantum-safe-git/releases/download/v1.0.0/git_hook -o ~/.git_ext/git_hook
chmod +x ~/.git_ext/git_hook
```

#### Build the Desktop UI (optional)

```bash
cd ui
npm install
npm start   # Starts the Electron app
```

#### Quick Verification

```bash
# Verify the plugin is loaded
git config --get core.hooksPath
# Should output: /home/user/.git_ext

# Create a test repo and commit
mkdir -p test_repo && cd test_repo
git init
git commit -m "First commit" --allow-empty
```

You should see the commit automatically signed with QSGit.

---

## Docker Deployment

### docker-compose.yml Overview

The repository includes a `docker-compose.yml` that defines:

- `signature-service` – Go microservice exposing the gRPC API.
- `redis` – Optional caching layer (for future scaling).
- `prometheus` & `grafana` – Monitoring stack (exposed on ports 9090 & 3000).

```yaml
version: '3.8'
services:
  signature-service:
    build: ./go
    ports:
      - "50051:50051"
    environment:
      - LOG_LEVEL=info
      - KEY_REPOSITORY_TYPE=local
      - KEY_REPOSITORY_PATH=./keys
    volumes:
      - ./keys:/app/keys:ro   # mount keys (never commit these)
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - ./grafana/provisioning:/etc/grafana/provisioning
```

### Running All Services

```bash
# Start everything in the background
docker compose up -d

# View logs
docker compose logs -f signature-service
```

### Building Custom Images

```bash
# Signature service
docker build -t yourorg/qsg-signature-service ./go

# Desktop UI
docker build -t yourorg/qsg-desktop ./ui
```

---

## Kubernetes Deployment

### Helm Chart

A Helm chart is provided under `helm/qsg`. It supports:

- **Replica counts** for horizontal scaling.
- **Resource limits** (CPU/memory requests/limits).
- **TLS** (cert-manager integration).
- **External Secrets** for cloud KMS credentials.

#### Install the Chart

```bash
helm repo add qsg https://your-org.github.io/qsg-helm
helm install qsg qsg/qsg \
  --namespace qsg-system --create-namespace \
  --set signatureService.image=yourorg/qsg-signature:latest \
  --set signatureService.replicas=3
```

#### Common Commands

```bash
# Upgrade with new changes
helm upgrade qsg qsg/qsg --reuse-values

# Rollback to previous version
helm rollback qsg 1

# Delete the release
helm uninstall qsg --namespace qsg-system
```

### Persistent Keys

If you use a cloud KMS, keys never leave the provider. For on-prem deployments, mount a **Kubernetes CSI driver** (e.g., `csi-driver-ncm` for HSM).

---

## Production Hardening

### 1. Security Best Practices

- **Principle of Least Privilege:** Run containers as non-root users.
- **Network Policies:** Isolate the signature service to only allow connections from Git hooks and CI systems.
- **TLS/SSL:** Enable TLS 1.3, use CA-signed certificates, and enforce HSTS.
- **Secrets Management:** Use Kubernetes Secrets or External Secrets Operator for cloud KMS credentials.

```yaml
# Example NetworkPolicy (kubectl apply -f)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-signature-service
spec:
  podSelector:
    matchLabels:
      app: signature-service
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: git-hook
        ipBlock:
          cidr: 10.0.0.0/8
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
```

### 2. Resource Limits

Set resource requests and limits to prevent noisy neighbors:

```yaml
resources:
  requests:
    cpu: "200m"
    memory: "256Mi"
  limits:
    cpu: "1"
    memory: "1Gi"
```

### 3. Logging & Auditing

All signing/verification events are written to **Elasticsearch**. Ensure logs are:

- **Indexed** with a retention policy (e.g., 30 days for raw events, 1 year for compliance).
- **Encrypted** in transit (TLS) and at rest (AES-256).
- **Immutable** (use Write-Only storage or append-only indices).

### 4. Backup & Restore

Backup the key repository and audit logs regularly:

```bash
# Backup keys (local filesystem example)
tar -czf keys-$(date +%F).tar.gz ./keys/

# Backup Elasticsearch snapshots (via API)
curl -X PUT "https://es-host:9200/_snapshot/my_snapshot?wait_for_completion=true" \
  -H "Content-Type: application/json" \
  -d '{"indices": "logs-*"}'
```

Restore when needed:

```bash
# Restore keys
tar -xzf keys-$(date +%F).tar.gz

# Restore Elasticsearch snapshot
curl -X POST "https://es-host:9200/_snapshot/my_snapshot/restore?wait_for_completion=true"
```

---

## Monitoring & Alerting

### Metrics Exposed

The Signature Service publishes Prometheus metrics under the namespace `qsg`:

| Metric | Description |
|--------|-------------|
| `qsg_signing_requests_total` | Total number of signing requests |
| `qsg_verification_requests_total` | Total verification attempts |
| `qsg_signing_latency_seconds` | Histogram of signing latency |
| `qsg_verification_latency_seconds` | Histogram of verification latency |
| `qsg_key_rotations_total` | Number of automatic key rotations |
| `qsg_audit_log_entries_total` | Number of logged events |

### Alerting Rules

Create `prometheus/alerts.yml`:

```yaml
groups:
- name: qsg_alerts
  rules:
  - alert: HighSigningLatency
    expr: histogram_quantile(0.95, qsg_signing_latency_seconds) > 0.5
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High signing latency detected"
      description: "Average signing latency is {{ $value }} seconds"

  - alert: VerificationFailureRate
    expr: (sum(qsg_verification_requests_total) - sum(qsg_verification_requests_total{status="ok"})) / sum(qsg_verification_requests_total) > 0.05
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "Verification failure rate above threshold"
      description: "{{ $value | humanizePercentage }} of verification requests failed"
```

Deploy alerts with:

```bash
kubectl apply -f prometheus/alerts.yml
```

### Grafana Dashboards

Sample dashboard JSON is provided in `grafana/dashboards/qsg.json`. Import it into Grafana (`/grafana/dashboards`) to visualize:

- Signing & verification throughput over time.
- Key rotation events.
- Error rates per operation.

---

## Backup & Disaster Recovery

### Key Repository Backup

For **hardware security modules**, follow vendor-provided backup procedures (often using PKCS#11 or vendor-specific tools).

For **cloud KMS**, leverage the provider's **backup & restore** APIs (e.g., AWS KMS `ListKeys`, `GetKeyPolicy`, or Azure Key Vault's `backupKey`).

Store backups in **WORM** (Write-Once, Read-Many) storage to ensure immutability.

### Audit Log Backup

Elasticsearch snapshots can be scheduled via the **Snapshot Lifecycle Management (SLM)** API:

```bash
# Create a snapshot policy
curl -X PUT "https://es-host:9200/_slm/policy/my_policy" \
  -H "Content-Type: application/json" \
  -d '{
    "policy": {
      "schedule": "0 0 * * *",
      "repository": "my_repo",
      "snapshots": {
        "delete": {"parameters": {"max_age": "30d"}}
      }
    }
  }'
```

### Disaster Recovery Procedure

1. **Restore the signature service** from a container image or Helm release.
2. **Re-import keys** from backup (hardware or cloud).
3. **Re-index audit logs** from snapshot into a fresh Elasticsearch cluster.
4. **Validate** by running `qsg-verify` against a known good commit.

---

## Troubleshooting Production Issues

### Common Errors & Solutions

| Symptom | Likely Cause | Command to Debug |
|---------|--------------|------------------|
| `connection refused` when signing | Signature Service not running or wrong port | `docker compose logs signature-service` |
| "Signature validation failed" | Wrong key ID, corrupted payload | `qsg-verify verify <commit-hash> --key-id <key_id>` |
| High latency in verification | Resource contention (CPU, network) | `docker stats signature-service` |
| "Permission denied" accessing keys | Key repository path misconfigured | Check file permissions on `./keys` |

### Gathering Debug Information

```bash
# Collect logs from all containers
docker compose logs --tail=1000 signature-service redis

# Export Prometheus metrics for analysis
curl "http://localhost:9090/api/v1/query?query=up{job=\"signature-service\"}" -o prom_metrics.json
```

---

## Appendix

### Release Process

1. **Create a Git tag** (`git tag v1.0.0`).
2. **Build Docker images** for both services and push to a container registry.
3. **Run integration tests** (`make test`).
4. **Generate documentation** (`mkdocs build`).
5. **Publish Helm chart** (`helm package helm/qsg` and push to repo).
6. **Create a GitHub Release** with changelog and assets.

### Roadmap (Beyond v1.0)

- **v1.1:** Add support for `SHA-3` and `Dilithium-4`.
- **v2.0:** Integrate blockchain-based attestation (optional).
- **v2.1:** Mobile app for remote approvals.

---

*Version 1.0.0 – February 2025*
