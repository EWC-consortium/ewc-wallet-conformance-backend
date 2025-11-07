## Wallet Client (OpenID4VCI sd-jwt)

This is a minimal Node.js wallet client that calls the issuer endpoints in `rfc-issuer-v1` to obtain `dc+sd-jwt` credentials using the pre-authorized flow. It builds a proof JWT (ES256) with the public JWK embedded in the header, includes `aud` and `nonce`, and handles deferred issuance.

### Quick start

```
cd wallet-client
npm i
```

Run with an issuer deep link (from `/offer-*` endpoints):

```
node src/index.js --issuer http://localhost:3000 --offer 'openid-credential-offer://?credential_offer_uri=ENCODED'
```

Or have the client fetch an offer for you:

```
# tx-code
node src/index.js --issuer http://localhost:3000 --fetch-offer /offer-tx-code --credential VerifiablePortableDocumentA2SDJWT

# no-code
node src/index.js --issuer http://localhost:3000 --fetch-offer /offer-no-code --credential VerifiablePortableDocumentA2SDJWT
```

### CLI

```
node src/index.js [--issuer URL] [--offer OFFER_URI] [--fetch-offer PATH] [--credential ID] [--key PATH]
```

- **--issuer**: Base URL of issuer (default: http://localhost:3000)
- **--offer**: Deep link `openid-credential-offer://?...` from issuer
- **--fetch-offer**: Issuer path to fetch an offer (e.g. `/offer-no-code`, `/offer-tx-code`)
- **--credential**: Desired `credential_configuration_id` (defaults to first in offer)
- **--key**: Optional path to an EC P-256 private JWK. If omitted, a new key is generated in-memory.

Outputs the issued credential JSON to stdout.

### What it does

- Resolves the credential offer URI and downloads the offer JSON.
- Exchanges the pre-authorized code at `/token_endpoint` to get `access_token`.
- Requests a fresh `c_nonce` at `/nonce`.
- Builds a proof JWT (`ES256`, `jwk` in header, `iss`=did:jwk, `aud`=issuer base URL, `nonce`=`c_nonce`).
- Calls `/credential` with `credential_configuration_id` and the proof.
- If issuer responds `202` with `transaction_id`, polls `/credential_deferred` until ready.


