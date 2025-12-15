## ITB+ Issuer / Verifier Service

### Introduction

This project provides a Node.js backend that acts as both:

- **Issuer**: Implements OpenID for Verifiable Credential Issuance (OID4VCI) for a variety of credential types (JWT VC, SD-JWT, mdoc-based credentials, etc.).
- **Verifier**: Implements OpenID for Verifiable Presentations (OIDC4VP) and related presentation flows for different relying parties and test scenarios.

It is designed as a flexible testbed for experimenting with credential **issuance** and **verification** workflows, driven by JSON configuration files rather than hard‑coded behavior.

### Main components

- **Issuer configuration** (`data/issuer-config.json`):  
  Defines credential configurations, issuance profiles, and OID4VCI endpoints (including pre-authorized and authorization code flows).
- **Verifier configuration** (`data/verifier-config*.json`):  
  Defines OIDC4VP/OpenID4VP request templates, presentation definitions, and verifier endpoints.
- **Routes**:
  - **Issuance**: under `routes/issue/` (e.g. `codeFlowSdJwtRoutes.js`, `preAuthSDjwRoutes.js`, `vciStandardRoutes.js`).
  - **Verification**: under `routes/verify/` and other verifier-specific routes (standard VP requests, DID-based, x509-based, mDL/PID-specific).
- **Wallet client**: a companion wallet in `wallet-client/` that exercises the issuer and verifier using OID4VCI + OpenID4VP flows (SD-JWT, JWT VC, mdoc).

Additional artifacts:

- **OpenAPI description** (`openapi/conformance-backend-endpoint.yaml`) exposing key issuance and verification endpoints for conformance tooling.
- **OAuth / AS metadata** (`data/oauth-config.json`) and **issuer metadata** (`data/issuer-config.json`) published via `routes/metadataroutes.js`.

### Features

- **OID4VCI Issuer**
  - Supports *code flow* and *pre-authorized* flows.
  - Issues different credential formats (including `dc+sd-jwt` and mdoc) based on `issuer-config.json`.
  - Handles deferred issuance where applicable.
  - Provides standardized `vci/offer` endpoint for dynamic test scenarios (flow, format, signature type, URL scheme).

- **OIDC4VP / Verifier**
  - Serves presentation requests and presentation definitions for multiple relying parties.
  - Verifies incoming presentations (JWT VC, SD-JWT / DC+SD-JWT, mdoc/mDL/PID depending on route).
  - Supports multiple client identifier schemes (redirect URI, x509 SAN DNS, DID-based, payment) and VP response modes.

- **Config-driven behavior**
  - New credentials and verifier scenarios can be added mostly by editing JSON under `data/` and corresponding route wiring.

### Key endpoints (high level)

- **Issuance (examples)**
  - `GET /offer-no-code`, `GET /offer-tx-code`: SD-JWT credential offers (pre-authorized code flow, with and without transaction code).
  - `GET /vci/offer`: standardized VCI offer endpoint (`flow=authorization_code|pre_authorized_code`, `credential_type`, `credential_format`, `signature_type`, `url_scheme`).
  - `GET /pre-offer-jwt-*`: JWT VC pre-authorized offers for various personas and use cases (boarding pass, education ID, alliance ID, passport, PID, etc.).

- **Verification (examples)**
  - `GET /vp-request/*`: OpenID4VP verification requests for different use cases (PID, e-passport, education ID, alliance ID, ferry boarding pass, etc.).
  - Additional verifier flows in `routes/verify/*`:
    - DID-based VP requests (`didRoutes.js`, `didJwkRoutes.js`).
    - x509-based verifier requests (`x509Routes.js`).
    - mDL / PID-specific VP requests and verification (`mdlRoutes.js`).
    - Verifier attestation scenarios (`verifierAttestationRoutes.js`).

- **Metadata**
  - `/.well-known/openid-credential-issuer` (+ suffix variants): credential issuer metadata derived from `data/issuer-config.json`.
  - `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration`: authorization server / OIDC metadata derived from `data/oauth-config.json`.
  - `/.well-known/jwt-vc-issuer`: JWT VC issuer metadata with inline JWKS.

### Running the issuer & verifier

1. **Install dependencies**

```bash
cd rfc-issuer-v1
npm install
```

2. **Start the backend**

```bash
node server.js
```

This starts the HTTP server on the port configured in `server.js` (commonly `3000`).  
Optionally you can expose it via HTTPS or tunneling (e.g. ngrok) and set `SERVER_URL`:

```bash
SERVER_URL="https://your-public-url.example.com" node server.js
```

If you have a `dev` script in `package.json`, you can also use:

```bash
npm run dev
```

### Using the wallet client with the issuer

The `wallet-client/` directory contains a VCI + VP **test wallet** implementation that is able to exercise all main issuer and verifier scenarios (SD-JWT / DC+SD-JWT, JWT VC, mdoc, pre-authorized and authorization-code flows, OpenID4VP with multiple response modes).

To use its CLI mode for a simple pre-authorized SD-JWT issuance:

```bash
# in another terminal
cd wallet-client
npm install

# Example: use a pre-authorized offer from the issuer
node src/index.js --issuer http://localhost:3000 --fetch-offer /offer-no-code --credential VerifiablePortableDocumentA2SDJWT
```

See `wallet-client/README.md` for detailed CLI and HTTP service usage (including `/issue`, `/issue-codeflow`, `/present`, and `/session` flows).

### References

- **OID4VCI**: [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- **OID4VP / OIDC4VP**: [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- **EUDI Wallet ARF**: [Architecture and Reference Framework](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/releases)


