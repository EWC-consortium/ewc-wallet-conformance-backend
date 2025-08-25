# Status List Implementation Alignment Fix

## Problem Statement

The original status list implementation had several issues that violated the IETF Token Status List specification:

1. **Issuer Mismatch**: Status list tokens used different issuer values than credentials
2. **Header Inconsistency**: Status list tokens didn't use the same `kid` headers as credentials
3. **Missing Key Resolution**: No proper key resolution mechanisms
4. **Trust Management Issues**: Status list issuer wasn't the same as credential issuer
5. **Signature Type Mismatch**: Status list didn't use the same signature type as the issued credential

## Example of the Problem

**Original Status List Token:**
```json
{
  "alg": "ES256",
  "typ": "statuslist+jwt"
}
{
  "iss": "https://itb.ilabs.ai/rfc-issuer",
  "iat": 1755841917,
  "exp": 1755928317,
  "status_list": {
    "bits": 1,
    "lst": "eJxjYBhAAAAAfQAB"
  }
}
```

**Issues:**
- Uses `https://` issuer instead of `did:web:` 
- Missing `kid` header for key resolution
- No alignment with credential issuance
- Doesn't match the signature type used in the credential

## Solution: Aligned Status Lists

### 1. Fixed Status List Token Structure

**Correct Status List Token (did:web):**
```json
{
  "alg": "ES256",
  "typ": "statuslist+jwt",
  "kid": "did:web:itb.ilabs.ai:rfc-issuer#keys-1"
}
{
  "iss": "did:web:itb.ilabs.ai:rfc-issuer",
  "iat": 1755841917,
  "exp": 1755928317,
  "status_list": {
    "bits": 1,
    "lst": "eJxjYBhAAAAAfQAB"
  }
}
```

**Correct Status List Token (did:jwk):**
```json
{
  "alg": "ES256",
  "typ": "statuslist+jwt",
  "kid": "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IiIsInkiOiIifQ#0"
}
{
  "iss": "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IiIsInkiOiIifQ",
  "iat": 1755841917,
  "exp": 1755928317,
  "status_list": {
    "bits": 1,
    "lst": "eJxjYBhAAAAAfQAB"
  }
}
```

**Correct Status List Token (x509):**
```json
{
  "alg": "ES256",
  "typ": "statuslist+jwt",
  "x5c": ["MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."]
}
{
  "iss": "https://itb.ilabs.ai/rfc-issuer",
  "iat": 1755841917,
  "exp": 1755928317,
  "status_list": {
    "bits": 1,
    "lst": "eJxjYBhAAAAAfQAB"
  }
}
```

**Improvements:**
- ✅ Same signature type as credential (did:web, did:jwk, or x509)
- ✅ Same `did:web:` issuer as credentials (when using did:web)
- ✅ Same `kid` header as credentials (when using did:web/did:jwk)
- ✅ Same `x5c` header as credentials (when using x509)
- ✅ Proper key resolution support
- ✅ Trust establishment through same entity

### 2. Signature Type Alignment

The implementation now uses the **exact same signature type determination logic** as credential generation:

```javascript
// Same logic as credential generation
const effectiveSignatureType = sessionObject.isHaip && process.env.ISSUER_SIGNATURE_TYPE === "x509"
  ? "x509"
  : sessionObject.signatureType;
```

This ensures that:
- **did:web credentials** → **did:web status lists**
- **did:jwk credentials** → **did:jwk status lists**  
- **x509 credentials** → **x509 status lists**
- **HAIP x509 credentials** → **x509 status lists**

### 3. IETF Spec Compliance

The implementation now follows the IETF specification recommendations:

> **11.3. Key Resolution and Trust Management**
> 
> If the Issuer of the Referenced Token is the same entity as the Status Issuer, then the same key that is embedded into the Referenced Token may be used for the Status List Token. In this case the Status List Token may use:
> - the same x5c value or an x5t, x5t#S256 or kid parameter referencing to the same key as used in the Referenced Token for JOSE.

### 4. Implementation Changes

#### New Methods Added:

1. **`createAlignedStatusList(sessionObject)`**: Creates status lists with signature type alignment
2. **`generateStatusListToken(sessionObject)`**: Generates tokens with signature type alignment
3. **Enhanced signature type determination**: Uses same logic as credential generation

#### Updated API Endpoints:

1. **`POST /status-list/aligned`**: Now accepts `session_type` and `is_haip` parameters
2. **`GET /status-list/:id`**: Now accepts `session_type` and `is_haip` query parameters

### 5. Usage Examples

#### Creating Aligned Status Lists with Signature Type

```bash
# Create status list aligned with did:web credentials
curl -X POST http://localhost:3000/status-list/aligned \
  -H "Content-Type: application/json" \
  -d '{
    "size": 1000,
    "bits": 1,
    "credentialType": "VerifiablePIDSDJWT",
    "session_type": "did:web",
    "is_haip": false
  }'

# Create status list aligned with did:jwk credentials
curl -X POST http://localhost:3000/status-list/aligned \
  -H "Content-Type: application/json" \
  -d '{
    "size": 1000,
    "bits": 1,
    "credentialType": "VerifiablePIDSDJWT",
    "session_type": "did:jwk",
    "is_haip": false
  }'

# Create status list aligned with x509 credentials
curl -X POST http://localhost:3000/status-list/aligned \
  -H "Content-Type: application/json" \
  -d '{
    "size": 1000,
    "bits": 1,
    "credentialType": "VerifiablePIDSDJWT",
    "session_type": "x509",
    "is_haip": true
  }'
```

#### Getting Status List Tokens with Signature Type Alignment

```bash
# Get status list token aligned with did:web
curl -H "Accept: application/statuslist+jwt" \
  "http://localhost:3000/status-list/{status-list-id}?session_type=did:web&is_haip=false"

# Get status list token aligned with did:jwk
curl -H "Accept: application/statuslist+jwt" \
  "http://localhost:3000/status-list/{status-list-id}?session_type=did:jwk&is_haip=false"

# Get status list token aligned with x509
curl -H "Accept: application/statuslist+jwt" \
  "http://localhost:3000/status-list/{status-list-id}?session_type=x509&is_haip=true"
```

### 6. Automatic Integration

The credential issuance flow now automatically creates aligned status lists with the correct signature type:

```javascript
// In sharedIssuanceFlows.js
const statusListId = await getOrCreateStatusListForCredentialType(effectiveConfigurationId, sessionObject);
if (statusListId) {
  const tokenIndex = await findAvailableStatusListIndex(statusListId);
  if (tokenIndex !== null) {
    statusReference = statusListManager.createStatusReference(statusListId, tokenIndex);
    // Status reference is automatically aligned with credential issuance signature type
  }
}
```

### 7. Key Resolution Support

The implementation now supports proper key resolution for all signature types:

1. **DID Resolution (did:web/did:jwk)**: Uses `kid` headers that can be resolved via DID documents
2. **X.509 Support**: Uses `x5c` headers for certificate-based verification
3. **Fallback Mechanisms**: Local key verification when DID resolution fails

### 8. Trust Management

Trust is established through signature type alignment:

1. **Same Signature Type**: Status list and credential use same signing method
2. **Same Issuer**: Status list and credential use same `iss` value
3. **Same Key**: Status list and credential use same signing key
4. **Same DID**: Both reference the same DID for key resolution (when applicable)

### 9. Testing

Run the comprehensive test suite:

```bash
npm test tests/statusListTest.js
```

The tests validate:
- ✅ IETF spec compliance
- ✅ Signature type alignment
- ✅ Issuer alignment
- ✅ Key resolution
- ✅ Trust management
- ✅ Token structure
- ✅ Revocation functionality

### 10. Configuration

The alignment is controlled by the same environment variables and session objects as credential issuance:

```bash
# For did:web (default)
ISSUER_SIGNATURE_TYPE=did:web
SERVER_URL=https://itb.ilabs.ai/rfc-issuer

# For did:jwk
ISSUER_SIGNATURE_TYPE=did:jwk

# For x509
ISSUER_SIGNATURE_TYPE=x509
```

### 11. Benefits

1. **Spec Compliance**: Follows IETF Token Status List specification
2. **Signature Type Alignment**: Same signature type as issued credential
3. **Trust Establishment**: Same issuer and key for credentials and status lists
4. **Key Resolution**: Proper DID-based key resolution
5. **Wallet Compatibility**: Wallets can verify trust relationships
6. **Security**: Consistent cryptographic binding
7. **Interoperability**: Standard-compliant implementation

## Migration Guide

### For Existing Status Lists

1. **Check Current Status Lists**:
   ```bash
   curl http://localhost:3000/status-lists
   ```

2. **Create New Aligned Status Lists**:
   ```bash
   curl -X POST http://localhost:3000/status-list/aligned \
     -H "Content-Type: application/json" \
     -d '{"size": 1000, "bits": 1, "session_type": "did:web"}'
   ```

3. **Migrate Credentials**: Update credential issuance to use new aligned status lists

4. **Clean Up**: Remove old status lists after migration

### For New Implementations

1. **Use Aligned Status Lists by Default**:
   ```javascript
   const statusList = await statusListManager.createAlignedStatusList(1000, 1, {}, sessionObject);
   ```

2. **Automatic Integration**: The credential issuance flow automatically creates aligned status lists

3. **No Configuration Changes**: Uses same issuer configuration as credentials

## Conclusion

The status list implementation now properly aligns with credential issuance, follows the IETF specification, and establishes proper trust relationships. This ensures that wallets can verify that the same entity that issued a credential can also revoke it, which is essential for the security and trust model of verifiable credentials.

**Key Improvement**: The status list now uses the **exact same signature type** as the issued credential, ensuring complete alignment and compliance with the IETF specification recommendations.
