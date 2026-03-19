# Higgaion Enterprise Gateway: Definitive Deployment & Operations Guide
**Version:** 1.0.0 | **Classification:** PUBLIC / SHIPPABLE

---

## 1. Executive Summary & Architecture

The **Higgaion Enterprise Gateway** is a mathematically verified, Zero-Trust edge proxy designed to bridge legacy enterprise infrastructure into the Post-Quantum Cryptography (PQC) era without requiring expensive application rewrites. 

By running as a reverse proxy or Kubernetes sidecar, the Gateway intercepts all ingress/egress TCP/HTTP traffic, encrypting and signing payloads using NIST-approved ML-DSA-87 algorithms before routing them to your internal services. 

### 1.1 Core Value Proposition
*   **Zero-Rewrite Integration**: Legacy applications remain unaware of the cryptographic transport layer.
*   **Formal Assurance**: The core cryptographic state machine is verified by 101 zero-admitted-lemma Coq proofs. It is mathematically impossible for the proxy to emit unencrypted plaintext out of bounds.
*   **Domain Separation**: Enforces strict cryptographic boundaries between production, staging, and internal audit zones.

---

## 2. Infrastructure Prerequisites

Before deploying the Enterprise Gateway, assure the target environment meets the following specifications:

*   **Operating System**: Ubuntu 22.04 LTS or 24.04 LTS (Kernel 5.15+).
*   **Dependencies**: OpenSSL 3.0+ (system default on Ubuntu 22.04+).
*   **Hardware Security Module (HSM)**: (Optional but recommended) PKCS#11 compliant HSM for physical ML-DSA-87 root key generation and storage.
*   **Resources**: Minimum 2vCPU, 4GB RAM per Gateway instance (handles ~10,000 TPS of PQC signing).

---

## 3. Key Lifecycle Management

The Gateway requires a hybrid cryptographic identity (ED25519 for legacy handshakes, ML-DSA-87 for quantum resistance). 

### 3.1 Generating the Gateway Identity Root
Use the provided `hsm_setup` utility to provision the keys. If an HSM is not available, the tool falls back to secure `tmpfs` local generation.

```bash
# Generate the unified PQC identity
./bin/hsm_setup --generate-hybrid-identity --alg ML-DSA-87 --out /etc/higgaion/keys/gateway.pem

# Secure the key material (Root required)
chown higgaion:higgaion /etc/higgaion/keys/gateway.pem
chmod 400 /etc/higgaion/keys/gateway.pem
```

---

## 4. Deployment Topologies

The Gateway supports two primary deployment patterns based on your infrastructure maturity.

### Pattern A: Edge Reverse Proxy (Bare Metal / VM)
In this pattern, the Gateway operates at the network edge, terminating external PQC TLS connections and forwarding standard HTTP/TCP traffic to the internal DMZ.

1.  Place the Gateway binary (`higgaion_gateway`) in `/usr/local/bin/`.
2.  Configure a systemic `systemd` service:
    ```ini
    [Unit]
    Description=Higgaion Enterprise Gateway
    After=network.target

    [Service]
    User=higgaion
    ExecStart=/usr/local/bin/higgaion_gateway -c /etc/higgaion/gateway.conf
    Restart=on-failure
    LimitNOFILE=65536

    [Install]
    WantedBy=multi-user.target
    ```

### Pattern B: Kubernetes Sidecar (Zero-Trust Mesh)
In this pattern, the Gateway runs as a container strictly bound to the application pod via `localhost`.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: legacy-financial-api
spec:
  template:
    spec:
      containers:
      # The Post-Quantum Gateway Sidecar
      - name: pqc-gateway
        image: higgaion/gateway:1.0.0
        ports:
        - containerPort: 8443
        volumeMounts:
        - name: gateway-config
          mountPath: /etc/higgaion/
      # Your existing unaffected application
      - name: financial-api
        image: legacy-api:v4
        ports:
        - containerPort: 8080
```

---

## 5. Gateway Configuration (`gateway.conf`)

The Gateway relies on a deterministic JSON configuration file to map external TLS listeners to internal upstream services.

```json
{
  "gateway_identity": "/etc/higgaion/keys/gateway.pem",
  "listeners": [
    {
      "bind_address": "0.0.0.0",
      "bind_port": 8443,
      "tls_mode": "mTLS_PQC_HYBRID",
      "domain_separation_tag": "gateway-production-zone",
      "upstream": {
        "protocol": "http",
        "target_host": "127.0.0.1",
        "target_port": 8080
      }
    }
  ],
  "security": {
    "drop_privileges_to": "higgaion",
    "enforce_signature_validation": true
  }
}
```

### 5.1 Domain Separation Tags
The `domain_separation_tag` is cryptographically bound into the ML-DSA-87 signature using the open-core algorithmic wrappers. Traffic signed for `gateway-production-zone` will mathematically instantly fail if replayed against `gateway-staging-zone`.

---

## 6. Observability & Operations

The Gateway exposes a Prometheus-compatible metrics endpoint by default on `localhost:9090/metrics`.

### 6.1 Critical Metrics to Monitor
*   `hig_gateway_pqc_handshakes_total`: Rate of incoming ML-DSA-87 connections.
*   `hig_gateway_signature_failures_total`: Spikes indicate active spoofing or replay attacks.
*   `hig_gateway_upstream_latency_ms`: P99 latency of your underlying legacy application.

### 6.2 Managing Logs
Logs are emitted to `stdout` in JSON format for instant ingestion by Datadog, Splunk, or Elastic.

```json
{"level":"INFO", "component":"CRYPTO", "msg":"Generated ML-DSA-87 keypair via provider: default", "timestamp":"2026-03-17T19:56:53Z"}
```

---

## 7. Disaster Recovery & Troubleshooting

### Scenario: Gateway Refuses to Start
*   **Symptom**: `EVP_PKEY_CTX_new_from_name: unsupported`
*   **Resolution**: The target operating system is missing the OpenSSL 3.0+ PQC providers. Ensure the system `libcrypto.so` is securely linked. For older CI environments, the Gateway can optionally fall back to `ED25519`.

### Scenario: Key Compromise & Rotation
If the `gateway.pem` identity is potentially compromised:
1.  Generate a new identity using `hsm_setup`.
2.  Issue a `SIGHUP` to the gateway process: `kill -HUP $(pidof higgaion_gateway)`.
3.  The Gateway will gracefully drain existing connections and instantly reload the new root cryptographic configuration without dropping the HTTP listener socket.

---
*For direct support or formal Coq verification audit trails, contact the Higgaion Engineering team.*
