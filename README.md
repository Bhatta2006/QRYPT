# Secure Traceable Visual Token (SVT) System

A scalable, cryptographically secure architecture designed to mitigate large-scale QR code forgery, cloning, and malicious token distribution.

## Overview
The SVT System hardens static visual tokens (like QR codes) through robust asymmetric cryptographic algorithms, deterministic binary representations, and strict scanning authentication controls via HMACs, paired alongside comprehensive telemetry-driven anomaly detection pipelines. It features a fully reactive React dashboard equipped for Token Management, Issuer Key creation, and live Server-Sent Event (SSE) Revocation metrics.

## Key Sub-Systems implemented
- **Symmetric/Asymmetric Abstraction (Stage 3):** Generates securely enveloped Elliptic-Curve (Ed25519) keys rotating seamlessly against dynamic KMS envelopes.
- **Token Generation Service (Stage 4):** Produces deterministic CBOR binary structures mapped against SHA-256 for precise `trace_id` assignment before executing digital signatures.
- **Scan Verification Service (Stage 5):** Handles rigorous and strict high-velocity payload validity, TTL, version cache fallbacks and pushes streaming anomaly data direct into Redis pipelines using device-bound hashing.
- **Revocation Engine & SSE Propagation (Stage 7):** Integrates live Server-Sent Events to automatically flush invalid token keys downstream to clients alongside offline Service-Worker cache invalidations.
- **Unified Telemetry & UI Dashboard (Stage 8):** Real-time monitoring metrics built through Prometheus, alongside a performant UI constructed utilizing React, TailwindCSS, and TanStack Virtualization.
- **CI/CD & Hardened Validations (Stage 9):** Production-grade deployment pipelines running flawlessly across Ruff, Mypy (`100% coverage`), and strictest React ESLint constraints (Zero `any` typed assertions block).

## Technical Stack
### Backend & Infrastructure
- **Languages:** Python 3.10+, Async
- **API Engine:** FastAPI
- **Memory & Streams:** Redis (Caching, Queuing, SSE Telemetry)
- **Database:** PostgreSQL / SQLAlchemy (Async Session Patterns)
- **Crypto Toolkit:** python-ecdsa, pynacl (Ed25519), PyJWT
- **Observability:** Prometheus, Grafana, OpenTelemetry

### Frontend Architecture
- **Language:** TypeScript (Strict Mode)
- **Framework:** React
- **Data Fetching:** TanStack Query, `@microsoft/fetch-event-source`
- **Styling:** TailwindCSS
- **Tooling:** ESLint, Playwright

## Running The Platform 
1. **Prepare Environment Configuration**:
    Create `.env` using `.env.example` as a template structure and inject your operational secret variables. 
2. **Launch Docker Instances**
    ```sh
    docker-compose up --build
    ```
3. **Explore REST Specs**
    Interact with system APIs via FastAPI's rendered OpenAPI UI: `http://localhost:8000/docs`
    Access the issuer dashboard on port corresponding to frontend compilation defaults.

## Environment Configuration (`.env.example` vs `.env`)
You will find a `.env.example` within the configuration directory. This file acts as a template for documenting structure and necessary system keys; however, it should NEVER maintain sensitive credentials. 
Instead, developers duplicate this structure into `.env` containing localized sensitive secrets which are then deliberately skipped out of version tracking via the `.gitignore` setup.