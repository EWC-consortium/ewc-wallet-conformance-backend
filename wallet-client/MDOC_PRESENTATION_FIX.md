# mDL/mdoc Presentation Fix - Summary

## Problem
The wallet-client was not properly sending mdoc credentials during presentation/verification. It was sending the raw IssuerSigned structure instead of wrapping it in a proper **DeviceResponse** as required by ISO/IEC 18013-5.

## Solution Implemented

### 1. Added mdoc Presentation Functions (`utils/mdlVerification.js`)

#### `buildMdocPresentation(storedCredential, options)`
- Constructs a proper **DeviceResponse** structure for presentation
- Handles multiple input formats:
  - ✅ **IssuerSigned** (nameSpaces + issuerAuth) - most common during issuance
  - ✅ **Document** (docType + issuerSigned) - full document format
  - ✅ **DeviceResponse** (version + documents) - already correct format
- Wraps credentials properly in the DeviceResponse structure:
  ```javascript
  {
    version: "1.0",
    documents: [{
      docType: "org.iso.18013.5.1.mDL",
      issuerSigned: { nameSpaces, issuerAuth }
    }],
    status: 0
  }
  ```
- CBOR encodes and base64url encodes the result

#### `isMdocCredential(credential)`
- Detects if a credential is an mdoc by:
  - Excluding SD-JWT (contains `~`)
  - Excluding JWT (3 dot-separated parts)
  - Attempting CBOR decode
  - Checking for mdoc structure fields

### 2. Updated Presentation Logic (`src/lib/presentation.js`)

#### Changes to `performPresentation()`:
1. **Import mdoc utilities**
   ```javascript
   import { buildMdocPresentation, isMdocCredential } from "../../utils/mdlVerification.js";
   ```

2. **Detect credential type**
   ```javascript
   const isMdoc = isMdocCredential(vpToken);
   ```

3. **Handle mdoc presentation**
   - Infers `docType` from presentation definition
   - Calls `buildMdocPresentation()` to construct DeviceResponse
   - Properly formats for verifier

4. **Set correct format in presentation_submission**
   - mdoc → `"mso_mdoc"`
   - SD-JWT → `"dc+sd-jwt"`
   - JWT VC → `"jwt_vc_json"`

#### Updated `buildPresentationSubmission()`:
- Added `credentialFormat` parameter
- Uses detected format instead of always inferring from presentation definition

#### Updated `inferRootFormat()`:
- Added support for `"mso_mdoc"` format

## Spec Compliance

### ✅ ISO/IEC 18013-5 (mdoc) Compliance

**Issuance (Receiving):**
- Issuer sends: **IssuerSigned** (`nameSpaces` + `issuerAuth`)
- Wallet accepts: IssuerSigned, Document, or DeviceResponse
- Wallet stores: As received (any format)

**Presentation (Sending):**
- Wallet sends: **DeviceResponse** (proper structure)
  - `version`: "1.0"
  - `documents`: array of Documents
  - `status`: 0
- Each Document contains:
  - `docType`: document type identifier
  - `issuerSigned`: the IssuerSigned from issuance
  - `deviceSigned`: (optional, not implemented yet)

### ✅ OpenID4VP Compliance
- Proper `vp_token` format for mdoc
- Correct `presentation_submission` with `format: "mso_mdoc"`
- Supports DIF Presentation Exchange v2.0

## Testing

To test the fix:

1. **Issue an mdoc credential**
   ```bash
   curl -X POST http://localhost:4000/issue \
     -H "Content-Type: application/json" \
     -d '{"issuer": "http://localhost:3000", "credential": "org.iso.18013.5.1.mDL"}'
   ```

2. **Present the credential**
   ```bash
   curl -X POST http://localhost:4000/present \
     -H "Content-Type: application/json" \
     -d '{"verifier": "http://localhost:3000", "deepLink": "openid4vp://..."}'
   ```

3. **Check logs for:**
   - `[mdoc-present] Building DeviceResponse for presentation`
   - `[mdoc-present] Constructed DeviceResponse with docType: ...`
   - `[present] Credential format for submission: mso_mdoc`

## What Works Now

✅ **Issuance Flow:**
- Receives IssuerSigned format from issuer
- Validates structure properly
- Stores credential in wallet cache

✅ **Presentation Flow:**
- Detects mdoc credentials
- Wraps IssuerSigned in proper DeviceResponse
- CBOR encodes the structure
- Sends base64url encoded DeviceResponse to verifier
- Sets correct format in presentation_submission

✅ **Multi-Format Support:**
- SD-JWT credentials (with kb-jwt binding)
- JWT VC credentials
- mdoc/mDL credentials

## Future Enhancements (Optional)

1. **DeviceAuth/DeviceSigned:**
   - Add MAC or signature over session transcript
   - Required for higher security profiles

2. **Selective Disclosure:**
   - Filter `nameSpaces` based on requested fields
   - Only send what verifier requests

3. **Multiple Documents:**
   - Support presenting multiple credentials in one DeviceResponse

4. **Session Transcript:**
   - Implement proper session transcript construction
   - Bind presentation to specific verifier session

## Files Changed

1. **`wallet-client/utils/mdlVerification.js`**
   - Added `buildMdocPresentation()` function
   - Added `isMdocCredential()` function
   - Exported new functions in default export

2. **`wallet-client/src/lib/presentation.js`**
   - Imported mdoc utilities
   - Added mdoc detection logic
   - Added DeviceResponse construction
   - Updated format handling
   - Enhanced presentation_submission building

## Related Specs

- **ISO/IEC 18013-5** - Personal identification — ISO-compliant driving license
- **ISO/IEC 18013-7** - Mobile driving license (mDL) application
- **OpenID4VP** - OpenID for Verifiable Presentations
- **DIF Presentation Exchange v2.0** - Presentation Definition format


