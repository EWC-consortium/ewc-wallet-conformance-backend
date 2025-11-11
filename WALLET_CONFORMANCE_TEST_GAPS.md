# Wallet Conformance Test Coverage Analysis

## Current Coverage Assessment

Your Insomnia collection provides **good coverage for request generation** but has **gaps for wallet conformance validation**. Here's what's missing:

## Missing Test Cases for OIDC4VCI v1.0 Wallet Conformance

### 1. Missing client_id_scheme Combinations
**Current:** Only `x509_san_dns` for authorization_code flows  
**Missing:**
- `client_id_scheme=redirect_uri` for authorization_code offers
- `client_id_scheme=did` for authorization_code offers  
- `client_id_scheme=payment` (if you support it)

**Recommendation:** Add these test cases:
```
GET /offer-code-sd-jwt?credentialType=urn:eu.europa.ec.eudi:pid:1&sessionId=XXX&client_id_scheme=redirect_uri&signatureType=x509
GET /offer-code-sd-jwt?credentialType=urn:eu.europa.ec.eudi:pid:1&sessionId=XXX&client_id_scheme=did&signatureType=x509
```

### 2. Missing Signature Type Combinations for Pre-Auth Flows
**Current:** Only `signatureType=x509` for pre-auth offers  
**Missing:**
- Pre-auth offers with `signatureType=did:web`
- Pre-auth offers with `signatureType=jwk`
- Pre-auth offers with `signatureType=kid-jwk`
- Pre-auth tx-code offers with non-x509 signature types

**Recommendation:** Add:
```
GET /offer-no-code?credentialType=urn:eu.europa.ec.eudi:pid:1&sessionId=XXX&signatureType=did:web
GET /offer-no-code?credentialType=urn:eu.europa.ec.eudi:pid:1&sessionId=XXX&signatureType=jwk
GET /offer-tx-code?credentialType=urn:eu.europa.ec.eudi:pid:1&sessionId=XXX&signatureType=did:web
```

### 3. Missing Wallet Submission Endpoints
**Current:** No tests for endpoints wallets POST to  
**Missing:**
- POST to `/token_endpoint` with pre-authorized_code
- POST to `/token_endpoint` with authorization_code + PKCE
- POST to `/credential` endpoint with proof JWT
- GET/POST to nonce endpoint (if separate)

**Note:** These are typically tested by having wallets execute flows, but you should have test cases to validate wallet responses programmatically.

### 4. Missing Algorithm Coverage
**Current:** No explicit tests for different algorithms  
**Missing:**
- Tests explicitly requesting ES256 vs ES384
- Tests for unsupported algorithm rejection

**Your config supports:** ES256, ES384 (per verifier-config.json)

## Missing Test Cases for OIDC4VP v1.0 Wallet Conformance

### 1. Missing VP Request POST Endpoints
**Current:** Only GET endpoints for VP request generation  
**Missing:**
- POST to `/x509/VPrequest/:id` with `wallet_nonce` and `wallet_metadata` in body
- POST to `/did/VPrequest/:id` with wallet metadata
- POST to `/did-jwk/VPrequest/:id` with wallet metadata
- POST to `/mdl/VPrequest/:id` with wallet metadata

**Why important:** OIDC4VP v1.0 allows wallets to send `wallet_nonce` and `wallet_metadata` when fetching VP requests. This tests wallet's ability to provide this data.

### 2. Missing VP Submission Validation Tests
**Current:** No tests for wallet VP submissions  
**Missing:**
- POST to `/direct_post/:id` with valid VP (to validate wallet can submit correctly)
- POST to `/direct_post_jwt/:id` with valid VP JWT
- POST with missing `state` parameter (error case)
- POST with wrong `state` parameter (error case)
- POST with missing/wrong `nonce` (error case)
- POST with wallet error response (`error` parameter)

**Why important:** These validate that wallets:
- Correctly format VP responses
- Include required parameters (state, nonce)
- Handle errors correctly

### 3. Missing client_id_scheme Variants for VP Requests
**Current:** VP requests don't explicitly test different client_id_schemes  
**Missing:**
- VP requests with `client_id_scheme=redirect_uri` (if supported)
- VP requests with different client_id_schemes per signature type

### 4. Missing Edge Cases
**Missing:**
- Unsatisfied presentation definition (wallet doesn't have required credentials)
- Malformed VP request handling
- Transaction data validation (for payment flows)
- Selective disclosure validation (for SD-JWT VPs)

## Recommendations

### High Priority (Essential for Conformance)

1. **Add client_id_scheme matrix:**
   - Authorization code offers: `redirect_uri`, `x509_san_dns`, `did`
   - VP requests: Test all supported schemes

2. **Add signature type matrix:**
   - Pre-auth offers: All signature types (x509, did:web, jwk, kid-jwk)
   - Authorization code offers: All signature types

3. **Add VP request POST endpoints:**
   - POST to `/x509/VPrequest/:id` with `wallet_nonce`/`wallet_metadata`
   - POST to `/did/VPrequest/:id` with wallet metadata
   - POST to `/did-jwk/VPrequest/:id` with wallet metadata
   - POST to `/mdl/VPrequest/:id` with wallet metadata

4. **Add VP submission test cases:**
   - Valid submissions (to verify wallet can submit correctly)
   - Error cases (missing state, wrong state, missing nonce, etc.)

### Medium Priority (Important for Robust Testing)

5. **Add algorithm coverage:**
   - Explicit tests for ES256 vs ES384
   - Unsupported algorithm rejection

6. **Add edge cases:**
   - Unsatisfied presentation definitions
   - Malformed requests/responses
   - Transaction data validation

### Low Priority (Nice to Have)

7. **Add metadata discovery tests:**
   - GET `/.well-known/openid-credential-issuer` validation
   - GET `/.well-known/openid-verifier` validation (if you have this)

## Testing Strategy

When testing wallet conformance:

1. **Use Insomnia to generate requests/offers** (you have this)
2. **Have wallets execute flows** (manual or automated)
3. **Validate wallet responses** using:
   - Your verifier's `/direct_post` endpoints
   - Your issuer's `/token_endpoint` and `/credential` endpoints
   - Session status endpoints (`/verificationStatus`, etc.)

4. **For automated testing**, consider:
   - Adding test cases that simulate wallet POSTs to your endpoints
   - Using environment variables in Insomnia to chain requests (e.g., get offer → extract code → POST to token endpoint)

## Conclusion

Your current collection is **good for generating test scenarios** but needs **additional test cases** to fully validate wallet conformance. The missing pieces are primarily:

1. **Complete client_id_scheme and signature type matrices**
2. **VP request POST endpoints** (with wallet metadata)
3. **VP submission validation** (both success and error cases)
4. **Algorithm coverage**

Adding these will give you comprehensive coverage for OIDC4VCI and OIDC4VP v1.0 wallet conformance testing.

