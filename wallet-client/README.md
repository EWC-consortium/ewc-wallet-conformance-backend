## Wallet Client (VCI + VP test wallet)

This package implements a **wallet-holder** for the rest of the `rfc-issuer-v1` project.  
It is not just a simple issuer demo client: it drives **both**:

- **VCI (issuance) flows** against the issuer:
  - Pre-authorized code flow (including HAIP `haip://` links and `tx_code` PIN handling).
  - Authorization code flow using `issuer_state` (via `/issue-codeflow` and `/session`).
  - Support for DPoP, Wallet Instance Attestation (WIA) and Wallet Unit Attestation (WUA) per EUDI specs.
- **VP (presentation) flows** against the verifiers:
  - OpenID4VP deep links (`openid4vp://`) and verifier helper endpoints.
  - Presentation of **SD-JWT / DC+SD-JWT**, **JWT VC**, and **mdoc/mDL/PID** credentials.
  - Response modes: `direct_post`, `direct_post.jwt`, and Digital Credentials API (`dc_api`, `dc_api.jwt`).

Together with Redis-backed storage, this wallet is designed to cover **all issuance and presentation cases exposed by the issuer/verifier routes in this repo**.

### Architecture

- **CLI** (`src/index.js`):
  - Non-interactive helper to obtain `dc+sd-jwt` credentials via **pre-authorized_code** from issuer offer endpoints.
  - Generates proof JWTs, handles `c_nonce` and deferred issuance, and writes issued credentials + key-binding material into Redis.
- **HTTP service** (`src/server.js`):
  - `/issue`: VCI **pre-authorized** flow using an `openid-credential-offer://` (or `haip://`) link.
  - `/issue-codeflow`: VCI **authorization_code** flow using `issuer_state`.
  - `/present`: OpenID4VP presentation using an `openid4vp://` deep link or a verifier fetch path.
  - `/session`: Orchestrated “test session” API that drives both issuance (pre-auth + auth code) and presentation, with status and log tracking.
  - `/health`, `/logs/:sessionId`, `/session-status/:sessionId`: health and observability endpoints.
- **Redis cache** (`src/lib/cache.js`):
  - Stores credentials by `credential_configuration_id` along with key binding material (wallet keys + `did:jwk`).
  - Stores detailed session logs for later inspection by verifiers/tests.

### Credential formats and flows

- **SD-JWT / DC+SD-JWT**
  - Full VCI issuance using OID4VCI (token + credential endpoints, deferred issuance).
  - VP support with:
    - Extraction of SD-JWT tokens from various issuer response envelopes.
    - Key-binding JWT (`openid4vp-proof+jwt`) generation and attachment to SD-JWT (kb-jwt segment).
    - Presentation definition / `presentation_submission` handling for PEX-based verifiers.
- **JWT VC**
  - Issuance and VP handling where credentials are plain JWT VCs.
  - Presentation submission format negotiation (`jwt_vc_json`).
- **mdoc / mDL / PID**
  - Uses custom CBOR-based utilities in `utils/mdlVerification.js` to:
    - Recognize mdoc credentials in multiple encodings (DeviceResponse, Document, IssuerSigned, wrapped structures).
    - Build a proper **DeviceResponse** for presentation (`buildMdocPresentation`).
    - Verify and extract mDL/PID claims for tests.

### Supported VP response modes

The wallet’s presentation engine (`src/lib/presentation.js`) can answer verifiers using:

- **`direct_post`**: `vp_token` (+ optional `presentation_submission`) in form-encoded body.
- **`direct_post.jwt`**:
  - Builds a signed JWT response and, when the verifier publishes JWKS, encrypts it to JWE using the verifier’s preferences.
  - Includes fallbacks to match the verifier behavior in this repo.
- **Digital Credentials API** (`dc_api`, `dc_api.jwt`):
  - Supported when verifiers use the DC API compatible flows and metadata in `verifier-config.json`.

### Quick start (CLI mode – SD-JWT issuance)

```bash
cd wallet-client
npm install
```

Run with an issuer deep link (from `/offer-*` endpoints):

```bash
node src/index.js --issuer http://localhost:3000 --offer 'openid-credential-offer://?credential_offer_uri=ENCODED'
```

Or have the client fetch an offer for you:

```bash
# tx-code
node src/index.js --issuer http://localhost:3000 --fetch-offer /offer-tx-code --credential VerifiablePortableDocumentA2SDJWT

# no-code
node src/index.js --issuer http://localhost:3000 --fetch-offer /offer-no-code --credential VerifiablePortableDocumentA2SDJWT
```

### CLI

```bash
node src/index.js [--issuer URL] [--offer OFFER_URI] [--fetch-offer PATH] [--credential ID] [--key PATH]
```

- **--issuer**: Base URL of issuer (default: `http://localhost:3000`)
- **--offer**: Deep link `openid-credential-offer://?...` from issuer
- **--fetch-offer**: Issuer path to fetch an offer (e.g. `/offer-no-code`, `/offer-tx-code`)
- **--credential**: Desired `credential_configuration_id` (defaults to first in offer)
- **--key**: Optional path to an EC P-256 private JWK. If omitted, a new key is generated in-memory.

Outputs the issued credential JSON to stdout.

### What the CLI does

- Resolves the credential offer URI and downloads the offer JSON.
- Exchanges the pre-authorized code at `/token_endpoint` to get `access_token`.
- Requests a fresh `c_nonce` at `/nonce`.
- Builds a proof JWT (`ES256`, `jwk` in header, `iss` = did:jwk, `aud` = issuer base URL, `nonce` = `c_nonce`).
- Calls `/credential` with `credential_configuration_id` and the proof.
- If issuer responds `202` with `transaction_id`, polls `/credential_deferred` until ready.

### Server mode (full wallet flows)

Start the wallet service:

```bash
cd wallet-client
npm install
npm start
```

Once running (default `http://localhost:4000`), you can:

- **Drive issuance**:
  - `POST /issue` with `{ issuer, offer, fetchOfferPath, credential, keyPath, pin }` for **pre-authorized** flows (incl. HAIP links).
  - `POST /issue-codeflow` with `{ issuer, offer, fetchOfferPath, credential, keyPath }` for **authorization_code** flows.
- **Drive presentation**:
  - `POST /present` with `{ verifier, deepLink, fetchPath, credential, keyPath }` for OpenID4VP requests.
- **Use orchestrated sessions for tests**:
  - `POST /session` with `{ deepLink, sessionId, issuer, verifier, credential, keyPath, fetchOfferPath, clientIdScheme, pin }` to run end‑to‑end VCI or VP flows (status is tracked in Redis).
  - `GET /session-status/:sessionId` to poll session outcome.
  - `GET /logs/:sessionId` to fetch detailed wallet logs for a scenario.

This makes `wallet-client` a **comprehensive test wallet** that should be able to exercise all issuer and verifier scenarios defined in the rest of the project (credential formats, flows, and response modes), while remaining clearly non‑production and focused on conformance experimentation.

