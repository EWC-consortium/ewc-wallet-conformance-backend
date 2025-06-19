# RFC: Batch Verifiable Credential Issuance

## Abstract

This RFC extends the OpenID for Verifiable Credential Issuance (OID4VCI) protocol to support batch issuance of verifiable credentials. It defines the necessary endpoints, message formats, and flows for issuing multiple credentials in a single transaction.

## Status

This document is a draft specification.

## 1. Introduction

The European Digital Identity (EUDI) Wallet ecosystem requires efficient mechanisms for issuing multiple verifiable credentials simultaneously. This RFC extends the existing OID4VCI protocol to support batch operations, reducing the number of round trips and improving the overall efficiency of credential issuance.

### 1.1 Terminology

- **Batch Issuance**: The process of issuing multiple verifiable credentials in a single transaction
- **Credential Offer**: A message containing the necessary information to initiate the credential issuance process
- **Pre-authorized Code**: A code that allows the holder to obtain an access token without user interaction
- **Authorization Code**: A code that allows the holder to obtain an access token after user authorization
- **Session ID**: A unique identifier for tracking the batch issuance process
- **Credential Configuration ID**: An identifier that references a specific credential configuration in the issuer's metadata

## 2. Protocol Overview

The batch issuance protocol follows these main steps:

1. Issuer generates a batch credential offer
2. Holder receives the credential offer (via QR code or deep link)
3. Holder requests credentials using either:
   - Pre-authorized code flow: Holder obtains an access token using a pre-authorized code
   - Authorization code flow: Holder obtains an access token using an authorization code after user authorization
4. Issuer validates and issues multiple credentials in a single response

## 3. Batch Credential Endpoint

The Batch Credential Endpoint is used to request and receive multiple credentials in a single transaction. This endpoint follows the same security requirements as the standard Credential Endpoint defined in OID4VCI.

### 3.1 Batch Credential Request

The Batch Credential Request is sent to the Batch Credential Endpoint. The request format is similar to the standard Credential Request but includes an array of credential configurations to be issued.

```
POST /batch-credential
Content-Type: application/json
Authorization: Bearer <access_token>
```

Request body:
```json
{
  "format": "jwt_vc_json",
  "credential_definition": {
    "type": [
      "VerifiableCredential",
      "BatchCredential"
    ]
  },
  "credential_configuration_ids": [
    "urn:eu.europa.ec.eudi:pid:1",
    "PhotoID"
  ],
  "proof": {
    "proof_type": "jwt",
    "jwt": "..."
  }
}
```

### 3.2 Batch Credential Response

The Batch Credential Response contains an array of issued credentials.

```json
{
  "credentials": [
    {
      "credential": "eyJ0eXAiOi...",
      "c_nonce": "fGFF7UkhLa",
      "c_nonce_expires_in": 86400
    },
    {
      "credential": "eyJ0eXAiOi...",
      "c_nonce": "wlbQc6pCJp",
      "c_nonce_expires_in": 86400
    }
  ]
}
```

### 3.3 Batch Credential Error Response

Error responses follow the standard OID4VCI error format:

```json
{
  "error": "invalid_request",
  "error_description": "Description of the error"
}
```

Common error codes:
- `invalid_request`: Malformed request
- `invalid_grant`: Invalid or expired access token
- `invalid_credential_type`: Unsupported credential type
- `batch_processing_error`: Error processing the batch request

## 4. Credential Offer for Batch Issuance

The Credential Offer for batch issuance follows the same format as the standard Credential Offer but includes multiple credential configuration IDs.

### 4.1 Credential Offer by Value

```json
{
  "credential_issuer": "https://issuer.example.com",
  "credential_configuration_ids": [
    "urn:eu.europa.ec.eudi:pid:1",
    "PhotoID"
  ],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "session-id"
    },
    "authorization_code": {
      "issuer_state": "state-value"
    }
  }
}
```

### 4.2 Credential Offer by Reference

The Credential Offer can also be provided by reference using a URI:

```
openid-credential-offer://?credential_offer_uri=https://issuer.example.com/credential-offer/123
```

## 5. Authorization Flows for Batch Issuance

Batch issuance is supported in both the Pre-authorized Code Flow and the Authorization Code Flow as defined in the OID4VCI specification.

### 5.1 Pre-authorized Code Flow

In the Pre-authorized Code Flow, the holder obtains an access token using a pre-authorized code without user interaction. This flow is suitable for scenarios where the holder has already been authenticated or where user interaction is not required.

1. Issuer generates a credential offer with a pre-authorized code
2. Holder receives the credential offer
3. Holder requests an access token using the pre-authorized code
4. Holder requests batch credentials using the access token
5. Issuer validates and issues multiple credentials

### 5.2 Authorization Code Flow

In the Authorization Code Flow, the holder obtains an access token using an authorization code after user authorization. This flow is suitable for scenarios where user interaction is required or where additional security is needed.

1. Issuer generates a credential offer with an authorization code grant
2. Holder receives the credential offer
3. Holder is redirected to the authorization endpoint
4. User authorizes the request
5. Holder receives an authorization code
6. Holder requests an access token using the authorization code
7. Holder requests batch credentials using the access token
8. Issuer validates and issues multiple credentials

## 6. Implementation Examples

The following are examples of how implementers might structure their endpoints. These are provided for illustration purposes only and are not prescriptive requirements.

### 6.1 Batch Credential Offer Endpoint Example (Pre-authorized Code Flow)

```
GET /offer-no-code-batch
```

Query Parameters:
- `sessionId` (optional): Existing session identifier
- `credentialType` (optional): Type of credentials to be issued

Response:
```json
{
  "qr": "data:image/png;base64,...",
  "deepLink": "openid-credential-offer://?credential_offer_uri=...",
  "sessionId": "uuid"
}
```

### 6.2 Batch Credential Offer URI Endpoint Example (Pre-authorized Code Flow)

```
GET /credential-offer-no-code-batch/:id
```

Response:
```json
{
  "credential_issuer": "https://issuer.example.com",
  "credential_configuration_ids": [
    "urn:eu.europa.ec.eudi:pid:1",
    "PhotoID"
  ],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "session-id"
    }
  }
}
```

### 6.3 Batch Credential Offer Endpoint Example (Authorization Code Flow)

```
GET /offer-code-batch
```

Query Parameters:
- `sessionId` (optional): Existing session identifier
- `credentialType` (optional): Type of credentials to be issued

Response:
```json
{
  "qr": "data:image/png;base64,...",
  "deepLink": "openid-credential-offer://?credential_offer_uri=...",
  "sessionId": "uuid"
}
```

### 6.4 Batch Credential Offer URI Endpoint Example (Authorization Code Flow)

```
GET /credential-offer-code-batch/:id
```

Response:
```json
{
  "credential_issuer": "https://issuer.example.com",
  "credential_configuration_ids": [
    "urn:eu.europa.ec.eudi:pid:1",
    "PhotoID"
  ],
  "grants": {
    "authorization_code": {
      "issuer_state": "state-value"
    }
  }
}
```

## 7. Security Considerations

1. The pre-authorized code must be single-use and time-limited
2. All credentials in a batch must be validated before issuance
3. The session state must be properly maintained and secured
4. Rate limiting should be implemented to prevent abuse
5. Implementers should follow the security considerations outlined in the OID4VCI specification

## 8. Implementation Guidelines

1. Implementers should use secure session management
2. QR codes should be generated with appropriate error correction
3. Batch operations should be atomic where possible
4. Implementers should handle timeouts and retries appropriately
5. Implementers should follow the implementation considerations outlined in the OID4VCI specification

## 9. References

1. OpenID for Verifiable Credential Issuance (OID4VCI) - https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html
2. EUDI Wallet Architecture and Reference Framework
3. OAuth 2.0 Authorization Framework 