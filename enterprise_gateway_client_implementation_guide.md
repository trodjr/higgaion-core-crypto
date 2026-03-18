# Higgaion Enterprise Gateway: Official Implementation & Operations Manual
**Document Version:** 1.0.0 | **Classification:** CLIENT CONFIDENTIAL / SHIPPABLE

---

## Welcome to the Post-Quantum Era

Welcome to the **Higgaion Enterprise Gateway** implementation program. 

As global adversaries accelerate "Harvest Now, Decrypt Later" cryptographic attacks, the mandate for Post-Quantum Cryptography (PQC) is no longer theoretical—it is an immediate operational requirement for securing intellectual property, financial data, and classified communications.

Upgrading legacy enterprise infrastructure to mitigate quantum threats is notoriously expensive and disruptive. The **Higgaion Enterprise Gateway** solves this. Engineered as a mathematically verified, Zero-Trust edge proxy, the Gateway drops transparently in front of your existing applications—rendering them quantum-resistant instantly, without requiring a single line of code to be rewritten.

This manual serves as your definitive guide from pre-flight architecture through Day 2 operations. 

---

## 1. Architectural Overview & The Zero-Trust Model

The Enterprise Gateway operates exclusively at the network edge or as a localized Kubernetes sidecar. It intercepts all ingress and egress TCP/HTTP traffic, terminating standard TLS connections and encapsulating the payloads inside mathematically proven ML-DSA-87 (NIST FIPS 204) cryptographic signatures before routing the traffic to your internal services.

### Core Assurances
*   **Mathematical Proofs:** The core cryptographic state machine is verified by 101 zero-admitted-lemma Coq (Gallina) proofs. It is mathematically impossible for the Gateway to emit unencrypted plaintext out of bounds.
*   **Domain Separation:** Cryptographic signatures are bound to specific network zones (e.g., `production`, `staging`). Traffic captured from `staging` is mathematically rejected by the Gateway if replayed against `production`.
*   **Zero-Rewrite Integration:** Your legacy databases, APIs, and web services remain completely unaware of the Gateway's presence.

---

## 2. Pre-Flight Checklist & Infrastructure Requirements

Before scheduling your implementation window, assure your target environment meets the following specifications:

### 2.1 Hardware Requirements (Per Gateway Node)
*   **CPU:** Minimum 2 vCPUs (x86_64 or ARM64).
*   **Memory:** Minimum 4GB RAM.
*   **Performance Expectation:** A single node handles approximately 10,000 ML-DSA-87 signature verifications per second.

### 2.2 Operating System & Dependencies
*   **Supported OS:** Ubuntu 22.04 LTS or Ubuntu 24.04 LTS (Kernel 5.15+).
*   **Cryptographic Dependencies:** OpenSSL 3.0 or higher.
*   **Hardware Security Module (HSM):** (Highly Recommended) A PKCS#11 compliant HSM (e.g., Thales Luna, AWS CloudHSM) for physical root key generation and isolated storage.

---

## 3. Phase 1: The Key Ceremony (Provisioning)

The Gateway requires a hybrid cryptographic identity to function: standard ED25519 for legacy handshakes and ML-DSA-87 for quantum resistance.

### 3.1 Generating the Gateway Identity Root
Use the provided `hsm_setup` utility to provision the keys. If a physical HSM is not available for development environments, the tool automatically falls back to secure `tmpfs` local generation.

```bash
# Generate the unified PQC identity
./bin/hsm_setup --generate-hybrid-identity --alg ML-DSA-87 --out /etc/higgaion/keys/gateway.pem

# Secure the key material (Root privileges required)
chown higgaion:higgaion /etc/higgaion/keys/gateway.pem
chmod 400 /etc/higgaion/keys/gateway.pem
```

*Note: For production deployments, Higgaion Engineering will assist your security team in establishing a formal Key Ceremony using standard PKCS#11 HSM workflows.*

---

## 4. Phase 2: Deployment Topologies

The Gateway supports two primary deployment patterns based on your infrastructure maturity. Choose the topology that aligns with your operational model.

### Topology A: Edge Reverse Proxy (Bare Metal / VM)
In this pattern, the Gateway operates at the network edge, terminating external PQC TLS connections and forwarding standard traffic securely into the internal DMZ.

1.  Copy the compiled Gateway binary (`higgaion_gateway`) into `/usr/local/bin/`.
2.  Configure a persistent `systemd` service for automatic restarts:
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

### Topology B: Kubernetes Sidecar (Zero-Trust Mesh)
In this pattern, the Gateway runs as a container strictly bound to your existing application pod, communicating exclusively via `localhost`.

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
      - name: higgaion-pqc-gateway
        image: higgaion/gateway:1.0.0
        ports:
        - containerPort: 8443
        volumeMounts:
        - name: gateway-config
          mountPath: /etc/higgaion/
      
      # Your existing, unaltered application
      - name: internal-financial-api
        image: your-company/legacy-api:v4
        ports:
        - containerPort: 8080
```

---

## 5. Phase 3: Configuration & Domain Routing

The Gateway evaluates a deterministic JSON configuration file (`gateway.conf`) to map external Post-Quantum listeners to internal plaintext upstream services.

```json
{
  "gateway_identity": "/etc/higgaion/keys/gateway.pem",
  "listeners": [
    {
      "bind_address": "0.0.0.0",
      "bind_port": 8443,
      "tls_mode": "mTLS_PQC_HYBRID",
      "domain_separation_tag": "financial-production-zone",
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

### 5.1 Enforcing Domain Separation
The `domain_separation_tag` is the bedrock of Zero-Trust authorization. The Gateway cryptographically binds this exact string into the ML-DSA-87 signature. If an attacker intercepts traffic destined for `financial-staging-zone` and replays it against `financial-production-zone`, the Gateway will mathematically reject the payload at the TLS layer.

---

## 6. Phase 4: Day 2 Operations & Observability

Once deployed, the Enterprise Gateway is designed to run silently and autonomously. It exposes standard integrations for existing enterprise monitoring stacks.

### 6.1 Prometheus Metrics
By default, the Gateway exposes a Prometheus-compatible metrics endpoint on `localhost:9090/metrics`.

**Critical Telemetry to Monitor:**
*   `hig_gateway_pqc_handshakes_total`: Velocity of incoming authenticated ML-DSA-87 connections.
*   `hig_gateway_signature_failures_total`: Immediate spikes here indicate an active spoofing or cryptographic replay attack.
*   `hig_gateway_upstream_latency_ms`: P99 latency tracking of your underlying legacy application routing.

### 6.2 Structured Logging
Compliance logs are emitted to `stdout` in normalized JSON format for instant ingestion by SIEMs (Datadog, Splunk, ElasticSearch, CrowdStrike).

```json
{"level":"INFO", "component":"CRYPTO", "msg":"Verified authentic ML-DSA-87 signature for domain financial-production-zone", "timestamp":"2026-03-17T19:56:53Z"}
{"level":"ERROR", "component":"SECURITY", "msg":"Domain-separation evasion detected. Rejecting payload.", "target":"financial-staging-zone", "timestamp":"2026-03-17T20:12:01Z"}
```

---

## 7. Disaster Recovery & Incident Response

### Scenario A: Gateway Refuses to Start (`unsupported` error)
*   **Symptom**: The log reads `EVP_PKEY_CTX_new_from_name: unsupported`.
*   **Resolution**: The target operating system is missing the OpenSSL 3.0+ PQC providers. Ensure the system `libcrypto.so` is securely linked. As an interim workaround, adjust `tls_mode` in the configuration to fallback to `mTLS_ED25519`.

### Scenario B: Zero-Downtime Key Rotation (Suspected Compromise)
If the `gateway.pem` identity must be rotated to comply with 90-day physical mandates or due to suspected compromise:
1.  Generate a new identity using the Step 3.1 `hsm_setup` command into a new file (`gateway_v2.pem`).
2.  Update `gateway.conf` to point `gateway_identity` to the new file.
3.  Issue a graceful `SIGHUP` reload signal to the running gateway process:
    ```bash
    kill -HUP $(pidof higgaion_gateway)
    ```
4.  The Gateway will hold existing TCP sessions open, instantly load the new root cryptographic configuration, and apply it to all subsequent incoming connections without dropping the listener.

---

## 8. Enterprise Support & Escalation Pathways

Higgaion provides direct engineering support for Enterprise Gateway clients. 

*   **Implementation Engineering**: For assistance integrating PKCS#11 HSMs or designing Kubernetes sidecar meshes, please schedule a technical sync with your dedicated Solution Architect.
*   **Compliance & Audit**: Should your auditors require access to the 101 Gallina (Coq) formal verification proofs substantiating the cryptographic boundary, please submit a request to the Security Engineering Group.

*For immediate Tier 1 support, please utilize your dedicated Slack/Teams connect channel or technical support portal.*
