# ISCP_SOC CHALL
Usage - python3 detector_full_candidate_name.py iscp_pii_dataset.csv

# Project Guardian 2.0 – Deployment Strategy

## Objective
Deploy a **real-time PII Detector & Redactor** that protects customer data across Flixkart’s ecosystem by:
- Intercepting and sanitizing sensitive logs and API payloads before storage or transmission.
- Preventing PII leaks from unmonitored assets, API integrations, and internal tools.
- Doing so with **low latency**, **high scalability**, and **cost-effectiveness**.

---

## Deployment Layers Considered

### 1. **API Gateway Plugin (Primary Layer)**
- **Why here?**
  - The majority of PII leakage occurs in API payloads and logs.
  - The gateway is a single choke point through which all external API traffic flows.
  - Redaction can be done *before logs are written* or payloads are forwarded downstream.
- **Implementation**
  - Integrate PII Detector as a **plugin in Kong / NGINX / Envoy API Gateway**.
  - Incoming/outgoing JSON payloads are scanned and sanitized in-stream.
  - Latency impact is minimal (<5ms per request for regex + lightweight NER).
- **Advantages**
  - Immediate protection at ingress/egress.
  - Scalable horizontally by scaling gateway nodes.
  - Centralized enforcement without modifying microservices.

---

### 2. **Sidecar Container (Per Microservice)**
- **Why here?**
  - Some PII originates from internal microservices that generate logs.
  - A sidecar ensures that *all logs/events from that service* are filtered before reaching the central log aggregator.
- **Implementation**
  - Deploy as a **DaemonSet in Kubernetes** or as a **sidecar container** alongside each app pod.
  - The sidecar intercepts stdout logs and scrubs PII before forwarding to ELK/Datadog/Splunk.
- **Advantages**
  - Protects against accidental developer log statements exposing PII.
  - Works even if new microservices are onboarded (sidecar pattern is repeatable).
- **Trade-off**
  - Slightly higher resource cost (memory + CPU overhead for each sidecar).

---

### 3. **Internal Tooling Integration**
- **Why here?**
  - PII sometimes leaks into **customer support dashboards, admin consoles, and BI tools**.
  - Redacting before rendering reduces insider threat and accidental exposure.
- **Implementation**
  - Embed PII Detector as a **middleware library** for Django/Flask/Node.js apps.
  - Ensures PII is masked at the application layer *before being displayed to staff*.

---

## Recommended Hybrid Approach
- **API Gateway Plugin** → First line of defense (real-time external traffic).  
- **Sidecar Container** → Protects logs and internal event streams.  
- **Library Middleware** → Adds redundancy for internal web apps.  

This hybrid ensures **end-to-end coverage**:
- External API traffic ✔️  
- Internal microservice logs ✔️  
- Admin dashboards & tools ✔️  

---

## Scalability & Cost Considerations
- **Scalability**: Each component (gateway, sidecar, middleware) is stateless and can scale horizontally.
- **Latency**: Regex + lightweight NER keeps detection under ~5ms per payload.
- **Cost**: Focused deployment at choke points (API Gateway + Sidecars) avoids blanket infrastructure changes.
- **Integration**: Minimal changes required for existing services, since the plugin/sidecar approach is non-intrusive.

---

## Future Enhancements
1. **Adaptive ML Models** – move from regex-only to hybrid ML/NER models trained on domain-specific logs.
2. **Streaming Redaction** – integrate with Kafka/Fluentd for high-throughput streaming sanitization.
3. **Audit Dashboard** – monitor redaction stats (PII hits, false positives, top leak sources).

---

## Conclusion
The proposed strategy places the **PII Detector at key interception points**:  
- **API Gateway (primary enforcement)**  
- **Sidecars (log scrubbing)**  
- **Middleware (internal UI protection)**  

This layered approach balances **latency, scalability, and cost-effectiveness**, while providing defense-in-depth against PII leaks in Flixkart’s ecosystem.

