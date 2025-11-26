## mdoc Credential Generation (Issuer Side)

This document describes how this service generates **mdoc credentials (mDL / PID)** on the issuer side, and how that aligns with **ISO/IEC 18013-5** and **OIDC4VCI v1.0** (in particular Appendix A.2, *Mobile Documents or mdocs*).  
It focuses **only** on the credential (mdoc) construction and encoding, not the full OIDC4VCI flow.

---

### 1. High‑Level Overview

- **OIDC4VCI v1.0 role**
  - Defines how the wallet requests a credential (`format: "mso_mdoc"` and `credential_configuration_id` / `doctype`) and how the issuer returns it.
  - Appendix A.2.4 requires that, for `mso_mdoc`, the `credential` claim is:
    - a **string** that is the **base64url‑encoded representation of the CBOR‑encoded `IssuerSigned` structure** from ISO/IEC 18013-5.

- **ISO/IEC 18013-5 role**
  - Defines the **mdoc data model** and cryptographic structures:
    - `IssuerSigned` = `{ nameSpaces, issuerAuth }`
    - `nameSpaces` = attribute values grouped by namespace as `IssuerSignedItem`s
    - `issuerAuth` = COSE_Sign1 over the **Mobile Security Object (MSO)**

This implementation strictly follows this split:

- **Inside**: build a full ISO 18013-5 `IssuerSigned` (MSO + `issuerAuth` + `nameSpaces`).
- **Outside / transport**: follow OIDC4VCI A.2.4 by returning `base64url(CBOR(IssuerSigned))` in the `credential` field.

---

### 2. Inputs from the OIDC4VCI Layer

Before mdoc generation starts, the `/credential` endpoint has already:

- Validated the **credential request** per OIDC4VCI v1.0:
  - `format: "mso_mdoc"` (via the credential configuration).
  - A valid `credential_configuration_id` mapped to an mdoc config with:
    - `format: "mso_mdoc"`
    - `doctype` (e.g. `urn:eu.europa.ec.eudi:pid:1`)
    - `cryptographic_binding_methods_supported: ["cose_key"]`
    - `credential_signing_alg_values_supported: [-7, -9, ...]` (COSE alg identifiers per A.2.2).
- Validated the **proof of possession** (`proofs.jwt`) and extracted:
  - The **wallet’s device key** (COSE_Key / JWK), to be embedded in the MSO `deviceKeyInfo`.

The mdoc generation function then gets:

- The **effective configuration ID** (`credential_configuration_id`) → resolves `doctype`, namespaces, and claim mapping.
- A **claims object** (e.g., PID attributes).
- The **device public key** from the proof (`deviceKey`).

---

### 3. Building `IssuerSigned` per ISO/IEC 18013‑5

The issuer uses the `@auth0/mdl` library to construct the ISO 18013-5 structures, in `utils/credGenerationUtils.js`.

#### 3.1 Creating the `Document` (library abstraction)

Conceptually:

```javascript
const document = new Document(docType); // e.g. "urn:eu.europa.ec.eudi:pid:1"

// Add issuer namespaces and values
document.addIssuerNameSpace(namespace, mappedClaims);

// Configure digest algorithm and validity
document.useDigestAlgorithm("SHA-256");
document.addValidityInfo({
  signed: validFromDate,
  validFrom: validFromDate,
  validUntil: validUntilDate,
});

// Bind to wallet’s device key
document.addDeviceKeyInfo({ deviceKey: devicePublicKeyJwk });
```

This mirrors ISO 18013-5:

- `docType` → `docType` in the MSO and in the logical Document.
- `addIssuerNameSpace`:
  - Creates an `IssuerSignedItem` per attribute:
    - `digestID`, `random` (salt), `elementIdentifier`, `elementValue`.
  - Groups them into `IssuerNameSpaces` (a map from namespace to list of items).
- `useDigestAlgorithm("SHA-256")`:
  - Configures the MSO’s `digestAlgorithm` and how `valueDigests` are computed.
- `addValidityInfo`:
  - Fills the MSO’s `validityInfo` (`signed`, `validFrom`, `validUntil`).
- `addDeviceKeyInfo`:
  - Sets `deviceKeyInfo.deviceKey` to the COSE/JWK derived from the wallet proof, binding the credential to that device key (holder binding).

#### 3.2 Creating the Mobile Security Object (MSO) and `issuerAuth`

When we call `document.sign(...)`:

```javascript
const signedDocument = await document.sign({
  issuerPrivateKey: issuerPrivateKeyJwk,
  issuerCertificate: issuerCertificatePem,
  alg: "ES256", // corresponds to COSE alg -7 for IssuerAuth
});
```

The library performs the ISO 18013‑5 steps:

1. **MSO construction**  
   Builds the `MobileSecurityObject`:

   ```text
   MobileSecurityObject = {
     version: "1.0",
     digestAlgorithm: "SHA-256",
     docType,
     valueDigests: { namespace -> digestID -> hash(IssuerSignedItem) },
     deviceKeyInfo: { deviceKey: ... },
     validityInfo: { signed, validFrom, validUntil }
   }
   ```

2. **COSE_Sign1 (`issuerAuth`)**  
   Signs the CBOR-encoded MSO as a **COSE_Sign1** structure (`issuerAuth`):

   - Protected header:
     - `alg: -7` (ECDSA w/ SHA‑256) or other COSE alg, matching `credential_signing_alg_values_supported`.
     - `x5chain`: optional certificate chain (DSC + root).
   - Payload:
     - CBOR encoding of the MSO.
   - Signature:
     - ECDSA over the `Signature1` structure per COSE.

3. **IssuerSigned assembly**  
   Produces an `IssuerSignedDocument` instance, conceptually:

   ```javascript
   signedDocument.issuerSigned = {
     nameSpaces: { /* IssuerNameSpaces */ },
     issuerAuth: /* COSE_Sign1 Tag 18 */
   };
   ```

At this point we have a full ISO 18013‑5 `IssuerSigned` structure.

---

### 4. Encoding `IssuerSigned` for OIDC4VCI v1.0

OIDC4VCI v1.0 Appendix A.2.4 states:

> *“The value of the `credential` claim in the Credential Response MUST be a string that is the base64url-encoded representation of the CBOR-encoded IssuerSigned structure…”*

Our implementation does exactly that.

#### 4.1 Preparing the structure with `prepare()`

Instead of directly CBOR-encoding the in‑memory JS object, we use the library’s `IssuerSignedDocument.prepare()`:

```javascript
const preparedDoc = signedDocument.prepare();       // Map { "docType", "issuerSigned" }
const preparedIssuerSigned = preparedDoc.get("issuerSigned");
```

`prepare()` ensures:

- `issuerAuth` is converted to the proper **COSE_Sign1 array** for Tag 18:  
  `[ protectedHeaders, unprotectedHeaders, payload, signature ]`.
- `nameSpaces` is converted to the correct **Map** with Tag 24‑wrapped `IssuerSignedItem` CBOR blobs.

This is critical for **ISO 18013‑5 compliance**: wallets expect `issuerAuth[2]` to be the MSO payload, not a JS object with named fields.

#### 4.2 CBOR encoding with the library encoder

We then call the `@auth0/mdl` CBOR encoder on the **prepared IssuerSigned**:

```javascript
import { cborEncode } from "@auth0/mdl/lib/cbor/index.js";

const encoded = cborEncode(preparedIssuerSigned);   // CBOR(IssuerSigned)
```

#### 4.3 Base64url encoding for transport

Finally, we return:

```javascript
const credential = Buffer.from(encoded).toString("base64url");
```

This `credential` string is what goes into the OIDC4VCI **Credential Response**:

```json
{
  "credentials": [
    {
      "credential": "<base64url(CBOR(IssuerSigned))>"
    }
  ]
}
```

This matches OIDC4VCI v1.0 A.2.4 while preserving the full ISO 18013‑5 `IssuerSigned` semantics.

---

### 5. Metadata & Algorithm Alignment

For the mdoc configuration (e.g. EUDI PID), in `credential_configurations_supported` for `format: "mso_mdoc"`:

- `doctype`: set to the ISO 18013‑5 mdoc identifier (e.g. `urn:eu.europa.ec.eudi:pid:1`).
- `credential_signing_alg_values_supported`: uses **COSE numeric alg IDs** as required by OIDC4VCI A.2.2, e.g.:

```json
"credential_signing_alg_values_supported": [-7, -9]
```

where:

- `-7` = ECDSA w/ P‑256 and SHA‑256 (IANA COSE)
- `-9` = fully specified ECDSA + P‑256 + SHA‑256 (per `I-D.ietf-jose-fully-specified-algorithms`)

The `IssuerAuth` header `alg` value (e.g. `-7`) is consistent with:

- The advertised `credential_signing_alg_values_supported`.
- The certificate key type used for signing the MSO.

This aligns both:

- **ISO 18013‑5** (COSE_Sign1 over MSO with COSE alg).
- **OIDC4VCI v1.0 A.2.2** (metadata must advertise the **numeric COSE alg identifiers** securing `IssuerAuth`).

---

### 6. Summary

- The issuer builds a full **ISO/IEC 18013‑5 `IssuerSigned`** structure using `@auth0/mdl`:
  - Attributes as `IssuerSignedItem` grouped in `IssuerNameSpaces`.
  - MSO with `valueDigests`, `deviceKeyInfo`, `validityInfo`.
  - `issuerAuth` as a COSE_Sign1 over the MSO, signed with the DSC.
- The issuer then:
  - Uses `IssuerSignedDocument.prepare()` to get a CBOR‑ready `IssuerSigned`.
  - Encodes it with the library’s CBOR encoder.
  - Base64url‑encodes the result and returns it as the `credential` claim.

This makes the **credential generation** path compliant with:

- **ISO/IEC 18013‑5** for mdoc structure and cryptography.
- **OIDC4VCI v1.0** (Appendix A.2) for `mso_mdoc` transport and metadata.


