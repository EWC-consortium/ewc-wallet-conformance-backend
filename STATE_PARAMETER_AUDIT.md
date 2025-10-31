# OpenID4VP State Parameter Audit

## Overview
This document traces the complete lifecycle of the `state` parameter through the OpenID4VP presentation flow to verify spec compliance with [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).

## OpenID4VP 1.0 Spec Requirements for `state`

Per **Section 5.1** (Authorization Request):
> `state` - RECOMMENDED. Opaque value used by the Verifier to maintain state between the request and the callback.

Per **Section 6.2** (Response Mode `direct_post`):
> The Wallet MUST send the Authorization Response to the Response URI using the HTTP POST method. The Wallet MUST include the `state` parameter in the Authorization Response.

**Key Point**: The wallet MUST echo back the exact `state` value it received in the Authorization Request.

---

## Flow Analysis: DID-based VP Request (Main Flow)

### 1. ✅ Generation (Step 1)
**Endpoint**: `GET /did/generateVPRequest`
**File**: `routes/verify/didRoutes.js` (lines 48-88)

```javascript
const result = await generateVPRequest({
  sessionId,
  responseMode,
  presentationDefinition,
  clientId: client_id,
  privateKey,
  clientMetadata,
  kid,
  serverURL: CONFIG.SERVER_URL,
  usePostMethod: true,
  routePath: "/did/VPrequest",
});
```

**Inside `generateVPRequest`** (`utils/routeUtils.js`, lines 664-665):
```javascript
const nonce = generateNonce(CONFIG.DEFAULT_NONCE_LENGTH); // 16 characters
const state = generateNonce(CONFIG.DEFAULT_NONCE_LENGTH); // 16 characters
```

**✅ CORRECT**: `state` is generated as a 16-character random hex string using `crypto.randomBytes()`

---

### 2. ✅ Caching (Step 2)
**Function**: `storeVPSessionData` → `storeVPSession`
**File**: `utils/routeUtils.js` (lines 882-907)

```javascript
await storeVPSession(sessionId, {
  uuid: sessionId,
  status: CONFIG.SESSION_STATUS.PENDING,
  claims: null,
  ...sessionData, // includes: nonce, state, response_mode, presentation_definition
});
```

**Redis Storage** (`services/cacheServiceRedis.js`, lines 211-220):
```javascript
const key = `vp-sessions:${sessionKey}`;
const ttlInSeconds = 180; // 3 minutes
await client.setEx(key, ttlInSeconds, JSON.stringify(sessionValue));
```

**✅ CORRECT**: 
- `state` is stored in Redis under key `vp-sessions:{sessionId}`
- TTL is 3 minutes
- Full session object including `state` is JSON-serialized

---

### 3. ✅ Transmission to Wallet (Step 3)

#### 3a. Request URI Flow
**QR Code contains**: `openid4vp://?request_uri=https://server/did/VPrequest/{sessionId}&client_id={client_id}&request_uri_method=post`

**Wallet fetches**: `POST /did/VPrequest/{sessionId}` (or GET for non-POST)
**File**: `routes/verify/didRoutes.js` (lines 236-289)

```javascript
const result = await processVPRequest({
  sessionId,
  clientMetadata,
  serverURL: CONFIG.SERVER_URL,
  clientId: client_id,
  privateKey,
  kid,
  walletNonce,
  walletMetadata,
});
```

**Inside `processVPRequest`** (`utils/routeUtils.js`, lines 782-823):
```javascript
const vpSession = await getVPSession(sessionId); // Retrieve from Redis

const vpRequestJWT = await buildVpRequestJWT(
  clientId,
  responseUri,
  vpSession.presentation_definition,
  privateKey,
  clientMetadata,
  kid,
  serverURL,
  "vp_token",
  vpSession.nonce,        // ✅ From session
  vpSession.dcql_query || null,
  vpSession.transaction_data || null,
  vpSession.response_mode,
  audience,
  walletNonce,
  walletMetadata,
  vpSession.state         // ✅ CRITICAL: From session
);
```

**Inside `buildVpRequestJWT`** (`utils/cryptoUtils.js`, lines 156-162):
```javascript
let jwtPayload = {
  response_type: response_type,
  response_mode: response_mode,
  client_id: client_id,
  nonce: nonce,
  state: state,  // ✅ Added to JWT payload
  ...
};
```

**✅ CORRECT**: 
- `state` from Redis session is passed to `buildVpRequestJWT`
- `state` is included in the signed JWT payload
- Wallet receives the JWT with `state` inside

---

### 4. ✅ Retrieval & Comparison (Step 4)
**Endpoint**: `POST /direct_post/{sessionId}`
**File**: `routes/verify/verifierRoutes.js` (lines 192-760)

#### 4a. Session Retrieval
```javascript
const vpSession = await getVPSession(sessionId); // Line 200
```

**Redis Retrieval** (`services/cacheServiceRedis.js`, lines 222-236):
```javascript
const key = `vp-sessions:${sessionKey}`;
const result = await client.get(key);
if (result) {
  return JSON.parse(result); // ✅ Deserializes full session including state
}
```

#### 4b. State Extraction from Wallet Response
For `direct_post` mode (lines 652-664):
```javascript
const submittedState = req.body.state; // ✅ From form body

if (!submittedState) {
  await logError(sessionId, "state parameter missing in direct_post");
  return res.status(400).json({ error: 'state parameter missing' });
}

if (submittedState !== vpSession.state) {  // ✅ String comparison
  await logError(sessionId, "state mismatch in direct_post", {
    expected: vpSession.state,
    received: submittedState
  });
  return res.status(400).json({ error: 'state mismatch' });
}
```

**✅ CORRECT**:
- Expected `state` retrieved from `vpSession.state`
- Submitted `state` extracted from `req.body.state`
- Direct string comparison using `!==`
- Detailed error logging with both values

---

## Verification Checklist

| Step | Requirement | Status | Evidence |
|------|-------------|--------|----------|
| 1 | Generate random `state` | ✅ PASS | `generateNonce(16)` uses `crypto.randomBytes()` |
| 2 | Store `state` in session | ✅ PASS | Stored in Redis via `storeVPSession` with 180s TTL |
| 3 | Include `state` in JWT payload per OpenID4VP 1.0 | ✅ PASS | `jwtPayload.state = state` (line 162 in cryptoUtils.js) |
| 4 | Wallet receives JWT with `state` | ✅ PASS | Signed JWT returned from `/VPrequest/:id` |
| 5 | Wallet echoes `state` in POST body | ✅ EXPECTED | Per OpenID4VP spec section 6.2 |
| 6 | Retrieve `state` from session | ✅ PASS | `vpSession.state` from Redis |
| 7 | Compare submitted vs expected | ✅ PASS | `submittedState !== vpSession.state` |
| 8 | Log mismatch with both values | ✅ PASS | Logs expected & received values |

---

## Other VP Request Flows

### Flow 2: redirect_uri Scheme (redirectUriRoutes.js)
**Status**: ✅ FIXED in recent update
- Generates `state` with `generateNonce(16)`
- Stores `state` in session
- Includes `state` in VP request (by value, not JWT)

### Flow 3: Legacy `/vpRequest/:type/:id`
**Status**: ✅ FIXED in recent update
- Now generates `state` with `generateNonce(16)`
- Stores in Redis via `storeVPSession`
- Passes `state` explicitly to `buildVpRequestJWT`
- Changed response_uri to `/direct_post/{uuid}` (was `/direct_post_jwt/{uuid}`)

### Flow 4: Payment Routes
**Status**: ✅ FIXED in recent update
- `buildPaymentVpRequestJWT` generates and returns `state`
- Route stores `state` in session
- Includes `state` in JWT payload

---

## Potential Issues to Investigate

### Issue 1: Session ID vs State Mismatch
**Question**: Is the wallet posting to the correct sessionId?

**Check**: The `response_uri` in the JWT must match the POST endpoint:
```javascript
// Generated response_uri
const responseUri = `${serverURL}/direct_post/${sessionId}`;

// Wallet should POST to exactly this URL
POST /direct_post/{sessionId}
```

**Verification**: Check your logs for:
```
[sessionId] INFO: Processing direct_post VP response
[sessionId] ERROR: state mismatch in direct_post { expected: 'X', received: 'Y' }
```

If the sessionIds are different between these logs, the wallet is posting to the wrong session!

---

### Issue 2: Multiple Request Fetches
**Question**: Is the wallet fetching the request_uri multiple times?

**Problem**: If the wallet calls `/VPrequest/:id` multiple times, and the route REGENERATES a new state each time (as it did before our fix), the wallet might have received different states.

**Current Status**: ✅ FIXED - `processVPRequest` now retrieves state from session, doesn't regenerate

---

### Issue 3: Wallet Using Wrong State Source
**Question**: Are wallets reading `state` from the URL instead of the JWT?

**Spec Requirement**: Per OpenID4VP 1.0, when using `request_uri`, ALL parameters MUST come from the JWT, NOT the URL.

**Check**: The QR code URL should be:
```
openid4vp://?request_uri=https://server/path&client_id=...
```

NOT:
```
openid4vp://?request_uri=...&state=X&nonce=Y  ❌ WRONG
```

**Current Status**: ✅ CORRECT - `buildVP` only includes `request_uri` and `client_id` in URL

---

## Debugging Steps for Current Error

Given that you're seeing:
```
ERROR: state mismatch in direct_post {
  expected: '87faebb49214bd8b6e45781df7a704e0',
  received: '9688d25da15062fdc5361cec0e51ae54'
}
```

### Step 1: Add Enhanced Logging

Add this to `routes/verify/verifierRoutes.js` after line 200:

```javascript
const vpSession = await getVPSession(sessionId);

// ADD THIS DEBUG LOGGING
console.log(`=== STATE DEBUG for session ${sessionId} ===`);
console.log(`Session from Redis:`, JSON.stringify(vpSession, null, 2));
console.log(`Expected state: ${vpSession.state}`);
console.log(`Request body:`, JSON.stringify(req.body, null, 2));
console.log(`Received state: ${req.body.state}`);
console.log(`=== END STATE DEBUG ===`);
```

### Step 2: Log JWT Generation

Add this to `utils/routeUtils.js` after line 823:

```javascript
const vpRequestJWT = await buildVpRequestJWT(...);

// ADD THIS DEBUG LOGGING
const decoded = require('jsonwebtoken').decode(vpRequestJWT, { complete: true });
console.log(`=== JWT STATE DEBUG for session ${sessionId} ===`);
console.log(`State in JWT payload: ${decoded.payload.state}`);
console.log(`State in session: ${vpSession.state}`);
console.log(`Match: ${decoded.payload.state === vpSession.state}`);
console.log(`=== END JWT STATE DEBUG ===`);
```

### Step 3: Check Request URI Calls

The wallet should call the request_uri ONCE. If it calls it multiple times and gets different JWTs, that would explain the mismatch (though our fix should prevent this).

Add to `/VPrequest/:id` endpoints:

```javascript
console.log(`=== REQUEST URI FETCH for session ${sessionId} ===`);
console.log(`Timestamp: ${new Date().toISOString()}`);
console.log(`Session state: ${vpSession.state}`);
console.log(`=== END REQUEST URI FETCH ===`);
```

---

## Conclusion

**All 4 verification points are now CORRECT**:

1. ✅ **Generation**: `state` is generated using `crypto.randomBytes(16).toString('hex')`
2. ✅ **Transmission**: `state` is included in the JWT payload per OpenID4VP 1.0
3. ✅ **Caching**: `state` is stored in Redis session with 180s TTL
4. ✅ **Comparison**: `state` is correctly retrieved from session and compared with `!==`

**If the error persists**, it suggests one of these scenarios:

1. **Wallet implementation bug**: The wallet is using the wrong `state` (possibly from a previous request or generating its own)
2. **Session desync**: The wallet is posting to a different sessionId than where the state was stored
3. **Multiple fetches**: The wallet fetched the request_uri multiple times before our fix was deployed
4. **Cache issue**: Redis hasn't been flushed after code deployment, causing old sessions to persist

**Recommendation**: 
1. Restart your server with the fixes
2. Clear Redis: `redis-cli FLUSHDB`
3. Generate a NEW QR code
4. Add the debug logging above
5. Test with one wallet
6. Share the debug logs

