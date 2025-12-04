import express from "express";
import fs from "fs";
import path from "path";
import { v4 as uuidv4 } from "uuid";
import {
  pemToJWK,
  generateNonce,
  base64UrlEncodeSha256,
  jarOAutTokenResponse,
  didKeyToJwks,
} from "../../utils/cryptoUtils.js";
import {
  buildAccessToken,
  generateRefreshToken,
  buildIdToken,
} from "../../utils/tokenUtils.js";

import {
  getAuthCodeSessions,
  getAuthCodeAuthorizationDetail,
} from "../../services/cacheService.js";

import {
  storePreAuthSession,
  getPreAuthSession,
  getSessionKeyFromAccessToken,
  getCodeFlowSession,
  storeCodeFlowSession,
  getSessionKeyAuthCode,
  getSessionAccessToken,
  getDeferredSessionTransactionId,
  storeNonce,
  checkNonce,
  deleteNonce,
  checkAndSetPollTime,
  clearPollTime,
  logError,
  logInfo,
  logWarn,
  setSessionContext,
  clearSessionContext,
} from "../../services/cacheServiceRedis.js";

import * as jose from "jose";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import {
  createSignerVerifier,
  digest,
  generateSalt,
  createSignerVerifierX509,
  pemToBase64Der,
} from "../../utils/sdjwtUtils.js";
import jwt from "jsonwebtoken";

import {
  handleCredentialGenerationBasedOnFormat,
  handleCredentialGenerationBasedOnFormatDeferred,
} from "../../utils/credGenerationUtils.js";

const sharedRouter = express.Router();

// Configuration constants
const getServerUrl = () => process.env.SERVER_URL || "http://localhost:3000";
const SERVER_URL = getServerUrl(); // Keep for backward compatibility
const TOKEN_EXPIRES_IN = 86400;
const NONCE_EXPIRES_IN = 86400;

// Specification references
const SPEC_REFS = {
  VCI_1_0: "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html",
  VCI_CREDENTIAL_REQUEST: "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request",
  VCI_PROOF: "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types",
  VP_1_0: "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html",
};

// Error messages
const ERROR_MESSAGES = {
  INVALID_REQUEST: "The request is missing the 'code' or 'pre-authorized_code' parameter.",
  INVALID_GRANT: "Invalid or expired pre-authorized code.",
  INVALID_GRANT_CODE: "Invalid or expired authorization code or session not found.",
  PKCE_FAILED: "PKCE verification failed.",
  UNSUPPORTED_GRANT: "Grant type is not supported.",
  INVALID_CREDENTIAL_REQUEST: "Must provide exactly one of credential_identifier or credential_configuration_id",
  INVALID_PROOF: "No proof information found",
  INVALID_PROOF_MALFORMED: "Proof JWT is malformed or missing algorithm.",
  INVALID_PROOF_ALGORITHM: "Proof JWT uses an unsupported algorithm",
  INVALID_PROOF_PUBLIC_KEY: "Public key for proof verification not found in JWT header.",
  INVALID_PROOF_UNABLE: "Unable to determine public key for proof verification.",
  INVALID_PROOF_SIGNATURE: "Proof JWT signature verification failed",
  INVALID_PROOF_ISS: "Proof JWT is missing sender identifier (iss claim).",
  INVALID_PROOF_NONCE: "Proof JWT nonce is invalid, expired, or already used.",
  INVALID_TRANSACTION: "Invalid transaction ID",
  SERVER_ERROR: "An error occurred during proof validation.",
  SESSION_LOST: "Session lost after proof validation.",
  CREDENTIAL_DENIED: "Credential request denied",
  STORAGE_FAILED: "Storage operation failed",
  NONCE_GENERATION_FAILED: "Nonce generation failed",
  AUTHORIZATION_PENDING: "Authorization pending",
  SLOW_DOWN: "Slow down"
};

// Helper function to extract sessionId from sessionKey
// sessionKey can be in format "code-flow-sessions:uuid" or just "uuid"
const extractSessionId = (sessionKey) => {
  if (!sessionKey) return null;
  // If sessionKey contains a colon, extract the part after it
  const parts = sessionKey.split(':');
  return parts.length > 1 ? parts[parts.length - 1] : sessionKey;
};

// Helper to load issuer configuration
const loadIssuerConfig = () => {
  try {
    const configPath = path.join(process.cwd(), "data", "issuer-config.json");
    const configFile = fs.readFileSync(configPath, "utf-8");
    return JSON.parse(configFile);
  } catch (error) {
    console.error("Error loading issuer config:", error);
    throw new Error("Failed to load issuer configuration");
  }
};

// Load cryptographic keys
const loadCryptographicKeys = () => {
  try {
    const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
    const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");
    const privateKeyPemX509 = fs.readFileSync("./x509EC/ec_private_pkcs8.key", "utf8");
    const certificatePemX509 = fs.readFileSync("./x509EC/client_certificate.crt", "utf8");

    return {
      privateKey,
      publicKeyPem,
      privateKeyPemX509,
      certificatePemX509
    };
  } catch (error) {
    console.error("Error loading cryptographic keys:", error);
    throw new Error("Failed to load cryptographic keys");
  }
};

// Initialize cryptographic components
const initializeCrypto = async () => {
  try {
    const keys = loadCryptographicKeys();
    const { signer, verifier } = await createSignerVerifierX509(
      keys.privateKeyPemX509,
      keys.certificatePemX509
    );
    return { signer, verifier, keys };
  } catch (error) {
    console.error("Error initializing crypto:", error);
    throw new Error("Failed to initialize cryptographic components");
  }
};

// Parse authorization details
const parseAuthorizationDetails = (authorizationDetails) => {
  if (!authorizationDetails) return null;

  try {
    let parsedAuthDetails = authorizationDetails;
    
    // If it's a string, it might be URL-encoded JSON
    if (typeof parsedAuthDetails === "string") {
      parsedAuthDetails = JSON.parse(decodeURIComponent(parsedAuthDetails));
    }

    // Validate it's a non-empty array
    if (!Array.isArray(parsedAuthDetails) || parsedAuthDetails.length === 0) {
      console.warn("authorization_details provided but was not a non-empty array or was malformed.");
      return null;
    }

    // Check for credential_configuration_id
    if (!parsedAuthDetails[0].credential_configuration_id) {
      console.warn("authorization_details provided but missing credential_configuration_id in the first element.");
      return null;
    }

    return parsedAuthDetails;
  } catch (error) {
    console.error("Error parsing authorization_details:", error);
    return null;
  }
};

  // Validate credential request parameters
const validateCredentialRequest = (requestBody, sessionId = null) => {
  const { credential_identifier, credential_configuration_id } = requestBody;

  if ((credential_identifier && credential_configuration_id) ||
      (!credential_identifier && !credential_configuration_id)) {
    const received = credential_identifier && credential_configuration_id
      ? "both credential_identifier and credential_configuration_id"
      : "neither credential_identifier nor credential_configuration_id";
    throw new Error(`${ERROR_MESSAGES.INVALID_CREDENTIAL_REQUEST}. Received: ${received}, expected: exactly one`);
  }

  // Log credential request validation details
  if (sessionId) {
    logInfo(sessionId, "Validating credential request", {
      credential_configuration_id,
      credential_identifier,
      hasProofs: !!requestBody.proofs,
      hasProof: !!requestBody.proof,
      proofTypes: requestBody.proofs ? Object.keys(requestBody.proofs) : []
    }).catch(() => {});
  }

  // V1.0 requires proofs (plural) - reject legacy proof (singular)
  if (requestBody.proof) {
    if (sessionId) {
      logError(sessionId, "Invalid proof format: received 'proof' (singular), expected 'proofs' (plural)", {
        receivedProofType: "singular",
        expectedProofType: "plural",
        specRef: SPEC_REFS.VCI_PROOF
      }).catch(() => {});
    }
    throw new Error(`${ERROR_MESSAGES.INVALID_PROOF}: V1.0 requires 'proofs' (plural), not 'proof' (singular). See ${SPEC_REFS.VCI_PROOF}`);
  }

  if (!requestBody.proofs) {
    throw new Error(`${ERROR_MESSAGES.INVALID_PROOF}. Received: proofs is ${typeof requestBody.proofs}, expected: non-null object. See ${SPEC_REFS.VCI_CREDENTIAL_REQUEST}`);
  }
  
  if (typeof requestBody.proofs !== 'object' || Array.isArray(requestBody.proofs)) {
    const receivedType = Array.isArray(requestBody.proofs) ? 'array' : typeof requestBody.proofs;
    throw new Error(`${ERROR_MESSAGES.INVALID_PROOF}. Received: proofs is ${receivedType}, expected: non-array object. See ${SPEC_REFS.VCI_CREDENTIAL_REQUEST}`);
  }

  // V1.0 requires exactly one proof type
  const proofTypes = Object.keys(requestBody.proofs);
  if (proofTypes.length !== 1) {
    throw new Error(`${ERROR_MESSAGES.INVALID_PROOF}: V1.0 requires exactly one proof type in proofs object. Received: ${proofTypes.length} proof type(s) [${proofTypes.join(', ')}], expected: exactly 1. See ${SPEC_REFS.VCI_PROOF}`);
  }

  // Get the proof type (jwt, mso_mdoc, etc.)
  const proofType = proofTypes[0];
  const proofValue = requestBody.proofs[proofType];

  // Ensure proof value exists
  if (!proofValue || (typeof proofValue === 'string' && proofValue.trim() === '')) {
    const received = !proofValue ? 'null/undefined' : 'empty string';
    throw new Error(`${ERROR_MESSAGES.INVALID_PROOF}: proof value is missing or empty. Received: ${received}, expected: non-empty string or array`);
  }

  // Handle jwt proof type - can be string or array
  if (proofType === 'jwt') {
    if (Array.isArray(proofValue)) {
      if (proofValue.length === 0) {
        throw new Error(`${ERROR_MESSAGES.INVALID_PROOF}: proofs.jwt array must not be empty. Received: array with ${proofValue.length} elements, expected: array with at least 1 element`);
      }
      // Use first JWT if array
      requestBody.proofJwt = proofValue[0];
    } else if (typeof proofValue === 'string') {
      requestBody.proofJwt = proofValue;
    } else {
      throw new Error(`${ERROR_MESSAGES.INVALID_PROOF}: proofs.jwt must be a string or array. Received: ${typeof proofValue}, expected: string or array`);
    }
  } else {
    // For other proof types, store as-is for now
    requestBody.proofJwt = proofValue;
  }

  return credential_configuration_id || credential_identifier;
};

// Validate proof JWT
const validateProofJWT = (proofJwt, effectiveConfigurationId, sessionId = null) => {
  const issuerConfig = loadIssuerConfig();
  const credConfig = issuerConfig.credential_configurations_supported[effectiveConfigurationId];

  if (!credConfig) {
    throw new Error(`Credential configuration ID '${effectiveConfigurationId}' not found.`);
  }

  if (!credConfig.proof_types_supported?.jwt) {
    if (sessionId) {
      logWarn(sessionId, "No JWT proof type configuration found, skipping algorithm validation", {
        effectiveConfigurationId,
        availableProofTypes: Object.keys(credConfig.proof_types_supported || {})
      }).catch(() => {});
    }
    return null;
  }

  const supportedAlgs = credConfig.proof_types_supported.jwt.proof_signing_alg_values_supported;
  if (!supportedAlgs || supportedAlgs.length === 0) {
    if (sessionId) {
      logWarn(sessionId, "No proof signing algorithms defined, skipping algorithm validation", {
        effectiveConfigurationId,
        supportedAlgorithms: supportedAlgs
      }).catch(() => {});
    }
    return null;
  }

  const decodedProofHeader = jwt.decode(proofJwt, { complete: true })?.header;
  if (!decodedProofHeader || !decodedProofHeader.alg) {
    const received = !decodedProofHeader ? 'missing header' : `header without alg (header keys: ${Object.keys(decodedProofHeader || {}).join(', ')})`;
    throw new Error(`${ERROR_MESSAGES.INVALID_PROOF_MALFORMED}. Received: ${received}, expected: header with alg property. See ${SPEC_REFS.VCI_PROOF}`);
  }

  if (!supportedAlgs.includes(decodedProofHeader.alg)) {
    throw new Error(`${ERROR_MESSAGES.INVALID_PROOF_ALGORITHM}. Received: '${decodedProofHeader.alg}', expected: one of [${supportedAlgs.join(", ")}]. See ${SPEC_REFS.VCI_PROOF}`);
  }

  return decodedProofHeader;
};

// Resolve public key for proof verification
const resolvePublicKeyForProof = async (decodedProofHeader, sessionId = null) => {
  if (decodedProofHeader.jwk) {
    return decodedProofHeader.jwk;
  }

  if (decodedProofHeader.kid?.startsWith("did:key:")) {
    try {
      const jwks = await didKeyToJwks(decodedProofHeader.kid);
      if (jwks?.keys?.length > 0) {
        return jwks.keys[0];
      }
      const received = jwks?.keys ? `JWKS with ${jwks.keys.length} keys` : 'null/undefined JWKS';
      throw new Error(`Failed to resolve did:key to JWK. Received: ${received}, expected: JWKS with at least 1 key`);
    } catch (error) {
      console.error(`Error resolving did:key to JWK. Received kid: ${decodedProofHeader.kid}, error:`, error);
      throw new Error(`Failed to resolve public key from proof JWT kid (did:key). Received kid: ${decodedProofHeader.kid}, error: ${error.message}`);
    }
  }

  if (decodedProofHeader.kid?.startsWith("did:jwk:")) {
    try {
      const didJwk = decodedProofHeader.kid;
      const jwkPart = didJwk.substring("did:jwk:".length);
      const jwkString = Buffer.from(jwkPart, "base64url").toString("utf8");
      return JSON.parse(jwkString);
    } catch (error) {
      console.error(`Error resolving did:jwk to JWK. Received kid: ${decodedProofHeader.kid}, error:`, error);
      throw new Error(`Failed to resolve public key from proof JWT kid (did:jwk). Received kid: ${decodedProofHeader.kid}, error: ${error.message}`);
    }
  }

  if (decodedProofHeader.kid?.startsWith("did:web:")) {
    return await resolveDidWebPublicKey(decodedProofHeader.kid, sessionId);
  }

  const received = decodedProofHeader.kid ? `kid: ${decodedProofHeader.kid}` : 'no kid in header';
  const hasJwk = decodedProofHeader.jwk ? 'has jwk' : 'no jwk';
  throw new Error(`${ERROR_MESSAGES.INVALID_PROOF_PUBLIC_KEY} Received: ${received}, ${hasJwk}. Expected: kid starting with did:key:, did:jwk:, or did:web:, or jwk in header`);
};

// Resolve DID Web public key
const resolveDidWebPublicKey = async (didWeb, sessionId = null) => {
  try {
    const [did, keyFragment] = didWeb.split("#");
    if (!keyFragment) {
      throw new Error(`kid does not contain a key identifier fragment. Received: '${didWeb}' (no #fragment), expected: format like 'did:web:example.com#key-1'`);
    }

    let didUrlPart = did.substring("did:web:".length);
    didUrlPart = decodeURIComponent(didUrlPart);

    const didParts = didUrlPart.split(":");
    const domain = didParts.shift();
    const path = didParts.join("/");

    const didDocUrl = path
      ? `https://${domain}/${path}/did.json`
      : `https://${domain}/.well-known/did.json`;

    if (sessionId) {
      logInfo(sessionId, "Resolving did:web public key", {
        didWeb,
        didDocUrl,
        domain,
        path
      }).catch(() => {});
    }
    
    const response = await fetch(didDocUrl);
    if (!response.ok) {
      throw new Error(`Failed to fetch DID document. Received: HTTP ${response.status} from ${didDocUrl}, expected: HTTP 200`);
    }
    
    const didDocument = await response.json();
    if (!didDocument) {
      throw new Error(`Failed to parse DID document. Received: null/undefined from ${didDocUrl}, expected: valid DID document JSON`);
    }

    const verificationMethod = didDocument.verificationMethod?.find(
      (vm) => vm.id === didWeb || (didDocument.id && didDocument.id + vm.id === didWeb)
    );

    if (!verificationMethod?.publicKeyJwk) {
      const availableIds = didDocument.verificationMethod?.map(vm => vm.id).join(', ') || 'none';
      throw new Error(`Public key not found in DID document. Received: verificationMethod with id '${didWeb}' ${verificationMethod ? 'but no publicKeyJwk' : 'not found'}, expected: verificationMethod with id '${didWeb}' containing publicKeyJwk. Available verificationMethod ids: [${availableIds}]`);
    }

    return verificationMethod.publicKeyJwk;
  } catch (error) {
    console.error(`Error resolving did:web. Received kid: ${didWeb}, error:`, error);
    throw new Error(`Failed to resolve public key from proof JWT kid (did:web). Received kid: ${didWeb}, error: ${error.message}`);
  }
};

// Verify proof JWT signature and claims
const verifyProofJWT = async (proofJwt, publicKeyForProof, flowType, sessionId = null) => {
  try {
    // Verify signature and other claims
    // Note: Nonce validation is done earlier in the credential endpoint handler
    // to prioritize PoP failure recovery
    const proofPayload = jwt.verify(
      proofJwt,
      await publicKeyToPem(publicKeyForProof),
      {
        algorithms: [jwt.decode(proofJwt, { complete: true })?.header?.alg],
        audience: getServerUrl(),
      }
    );

    // Verify claims
    if (!proofPayload.iss && flowType === "code") {
      throw new Error(`${ERROR_MESSAGES.INVALID_PROOF_ISS}. Received: payload without iss claim, expected: payload with iss claim (required for code flow). See ${SPEC_REFS.VCI_PROOF}`);
    }

    if (sessionId) {
      logInfo(sessionId, "Proof JWT signature and claims validated successfully", {
        walletIssuer: proofPayload.iss,
        nonceVerified: true,
        flowType
      }).catch(() => {});
    }
    return proofPayload;
  } catch (error) {
    if (error.message.includes("signature verification failed")) {
      throw new Error(`${ERROR_MESSAGES.INVALID_PROOF_SIGNATURE}: ${error.message}`);
    }
    
    throw error;
  }
};

// Get session object from token
const getSessionFromToken = async (token) => {
  let sessionObject;
  let flowType = "pre-auth";
  let sessionKey;

  const preAuthsessionKey = await getSessionKeyFromAccessToken(token);
  if (preAuthsessionKey) {
    const preAuthSession = await getPreAuthSession(preAuthsessionKey);
    if (preAuthSession) {
      sessionObject = preAuthSession;
      sessionKey = preAuthsessionKey;
    } else {
      const codeSession = await getCodeFlowSession(preAuthsessionKey);
      if (codeSession) {
        sessionObject = codeSession;
        sessionKey = preAuthsessionKey;
        flowType = "code";
      }
    }
  }

  if (!sessionObject) {
    const codeSessionKey = await getSessionAccessToken(token);
    if (codeSessionKey) {
      const codeSession = await getCodeFlowSession(codeSessionKey);
      if (codeSession) {
        sessionObject = codeSession;
        sessionKey = codeSessionKey;
        flowType = "code";
      }
    }
  }

  return { sessionObject, flowType, sessionKey };
};

// Handle pre-authorized code flow
const handlePreAuthorizedCodeFlow = async (
  preAuthorizedCode,
  authorizationDetails,
  dpopCnf = null
) => {
  const existingPreAuthSession = await getPreAuthSession(preAuthorizedCode);
  
  if (!existingPreAuthSession) {
    throw new Error(`${ERROR_MESSAGES.INVALID_GRANT}. Received: pre-authorized_code '${preAuthorizedCode}' not found or expired, expected: valid, unexpired pre-authorized_code`);
  }

  // Check if authorization is still pending external completion
  if (existingPreAuthSession.status === 'pending_external') {
    // Atomically check and set poll time using Redis (thread-safe)
    // Returns false if polled too recently (within minPollIntervalSeconds)
    const minPollIntervalSeconds = 5;
    const pollAllowed = await checkAndSetPollTime(preAuthorizedCode, minPollIntervalSeconds);
    
    if (!pollAllowed) {
      const error = new Error(ERROR_MESSAGES.SLOW_DOWN);
      error.errorCode = 'slow_down';
      throw error;
    }
    
    // Return authorization_pending error
    const error = new Error(ERROR_MESSAGES.AUTHORIZATION_PENDING);
    error.errorCode = 'authorization_pending';
    throw error;
  }

  const parsedAuthDetails = parseAuthorizationDetails(authorizationDetails);
  const chosenCredentialConfigurationId = parsedAuthDetails?.[0]?.credential_configuration_id;

  const generatedAccessToken = buildAccessToken(
    getServerUrl(),
    loadCryptographicKeys().privateKey,
    dpopCnf
  );
  const cNonceForSession = generateNonce();

  // Update session
  existingPreAuthSession.accessToken = generatedAccessToken;
  existingPreAuthSession.c_nonce = cNonceForSession;

  await storePreAuthSession(preAuthorizedCode, existingPreAuthSession);

  // Clear poll tracking for successful issuance
  await clearPollTime(preAuthorizedCode);

  // Prepare response
  const tokenResponse = {
    access_token: generatedAccessToken,
    refresh_token: generateRefreshToken(),
    token_type: dpopCnf ? "DPoP" : "bearer",
    expires_in: TOKEN_EXPIRES_IN,
  };

  if (parsedAuthDetails) {
    parsedAuthDetails.credential_identifiers = [chosenCredentialConfigurationId];
    tokenResponse.authorization_details = parsedAuthDetails;
  }

  return tokenResponse;
};

// Handle authorization code flow
const handleAuthorizationCodeFlow = async (
  code,
  code_verifier,
  authorizationDetails,
  dpopCnf = null
) => {
  const issuanceSessionId = await getSessionKeyAuthCode(code);
  
  if (!issuanceSessionId) {
    throw new Error(`${ERROR_MESSAGES.INVALID_GRANT_CODE}. Received: authorization code '${code}' not found or expired, expected: valid, unexpired authorization code`);
  }

  const existingCodeSession = await getCodeFlowSession(issuanceSessionId);
  
  if (!existingCodeSession) {
    throw new Error(`${ERROR_MESSAGES.INVALID_GRANT_CODE}. Received: session '${issuanceSessionId}' not found for authorization code '${code}', expected: valid session`);
  }

  // Verify PKCE
  const pkceVerified = await validatePKCE(
    existingCodeSession,
    code_verifier,
    existingCodeSession.requests?.challenge,
    sessionId
  );

  if (!pkceVerified) {
    // Mark session as failed when PKCE verification fails
    try {
      existingCodeSession.status = "failed";
      existingCodeSession.results.status = "failed";
      existingCodeSession.error = "invalid_grant";
      existingCodeSession.error_description = ERROR_MESSAGES.PKCE_FAILED;
      
      await storeCodeFlowSession(
        existingCodeSession.results.issuerState,
        existingCodeSession
      );
    } catch (storageError) {
      console.error("Failed to update session status after PKCE failure:", storageError);
    }
    
    throw new Error(ERROR_MESSAGES.PKCE_FAILED);
  }

  const parsedAuthDetails = parseAuthorizationDetails(authorizationDetails);
  const chosenCredentialConfigurationId = parsedAuthDetails?.[0]?.credential_configuration_id;
  const generatedAccessToken = buildAccessToken(
    getServerUrl(),
    loadCryptographicKeys().privateKey,
    dpopCnf
  );
  const cNonceForSession = generateNonce();

  // Update session
  existingCodeSession.requests.accessToken = generatedAccessToken;
  existingCodeSession.c_nonce = cNonceForSession;

  await storeCodeFlowSession(
    existingCodeSession.results.issuerState,
    existingCodeSession
  );

  // Prepare response
  const tokenResponse = {
    access_token: generatedAccessToken,
    refresh_token: generateRefreshToken(),
    token_type: dpopCnf ? "DPoP" : "Bearer",
    expires_in: TOKEN_EXPIRES_IN,
  };

  if (parsedAuthDetails) {
    parsedAuthDetails.credential_identifiers = [chosenCredentialConfigurationId];
    tokenResponse.authorization_details = parsedAuthDetails;
  }

  return tokenResponse;
};

// Handle immediate credential issuance
const handleImmediateCredentialIssuance = async (requestBody, sessionObject, effectiveConfigurationId, sessionId = null) => {
  const requestedCredentialType = [effectiveConfigurationId];
  requestBody.vct = requestedCredentialType[0];

  // Determine format from credential configuration (VCI v1.0 requirement)
  const issuerConfig = loadIssuerConfig();
  const credConfig = issuerConfig.credential_configurations_supported[effectiveConfigurationId];
  if (!credConfig) {
    const availableConfigs = Object.keys(issuerConfig.credential_configurations_supported || {}).join(', ') || 'none';
    throw new Error(`Credential configuration not found. Received: '${effectiveConfigurationId}', expected: one of [${availableConfigs}]`);
  }

  // Determine format - default to 'dc+sd-jwt' for backward compatibility
  let format = credConfig.format || 'dc+sd-jwt';

  // Map VCI v1.0 format identifiers to internal format identifiers
  if (format === 'mso_mdoc') {
    format = 'mDL'; // Use 'mDL' for internal processing
  }

  const credential = await handleCredentialGenerationBasedOnFormat(
    requestBody,
    sessionObject,
    getServerUrl(),
    format
  );

  if (sessionId) {
    logInfo(sessionId, "Credential generated successfully", {
      credentialFormat: format,
      credentialLength: credential.length,
      effectiveConfigurationId
    }).catch(() => {});
  }

  // Generate notification_id for this issuance flow
  const notification_id = uuidv4();

  return {
    credentials: [{ credential }],
    notification_id
  };
};

// Handle deferred credential issuance
const handleDeferredCredentialIssuance = async (requestBody, sessionObject, sessionKey, flowType) => {
  const transaction_id = generateNonce();
  const notification_id = uuidv4();

  sessionObject.transaction_id = transaction_id;
  sessionObject.notification_id = notification_id;
  sessionObject.requestBody = requestBody;
  sessionObject.isCredentialReady = false;
  sessionObject.attempt = 0;

  if (flowType === "code") {
    await storeCodeFlowSession(sessionKey, sessionObject);
  } else {
    await storePreAuthSession(sessionKey, sessionObject);
  }

  return {
    transaction_id,
    interval: 5 // V1.0 requirement: polling interval in seconds for deferred credential status checks
  };
};

// *****************************************************************
// ************* TOKEN ENDPOINTS ***********************************
// *****************************************************************

sharedRouter.post("/token_endpoint", async (req, res) => {
  let sessionId = null;

  try {
    const {
      grant_type,
      code,
      "pre-authorized_code": preAuthorizedCode,
      code_verifier,
      authorization_details,
    } = req.body;

    // Validate required parameters
    if (!(code || preAuthorizedCode)) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: ERROR_MESSAGES.INVALID_REQUEST,
      });
    }

    // Extract sessionId for logging
    // For pre-authorized code flow, the preAuthorizedCode IS the sessionId
    if (preAuthorizedCode) {
      sessionId = preAuthorizedCode;
    } else if (code) {
      // For authorization code flow, we need to look up the sessionId from the code
      sessionId = await getSessionKeyAuthCode(code);
    }

    // Set session context for console interception to capture all logs
    if (sessionId) {
      setSessionContext(sessionId);
      // Clear context when response finishes
      res.on("finish", () => {
        clearSessionContext();
      });
      res.on("close", () => {
        clearSessionContext();
      });
    }

    // Attempt to extract DPoP confirmation (cnf.jkt) from DPoP header if present
    let dpopCnf = null;
    const dpopHeader = req.headers["dpop"];
    if (typeof dpopHeader === "string") {
      try {
        // Per RFC 9449, the public key used for DPoP is carried in the JWS header as "jwk"
        const protectedHeader = jose.decodeProtectedHeader(dpopHeader);
        if (protectedHeader && protectedHeader.jwk) {
          const jkt = await jose.calculateJwkThumbprint(
            protectedHeader.jwk,
            "sha256"
          );
          dpopCnf = { jkt };
        } else if (sessionId) {
          // Header present but missing jwk -> will fall back to Bearer
          logWarn(sessionId, "DPoP header present but missing 'jwk'; issuing Bearer access token", {
            hasDpopHeader: true,
            hasJwkInHeader: !!(protectedHeader && protectedHeader.jwk),
          }).catch(() => {});
        }
      } catch (e) {
        // If DPoP proof is malformed, respond with an error specific to DPoP
        return res.status(400).json({
          error: "invalid_dpop_proof",
          error_description: `Invalid DPoP proof: ${e.message}`,
        });
      }
    } else if (sessionId) {
      // No DPoP header at all -> behavior falls back to Bearer-style token
      logWarn(sessionId, "DPoP header not present; issuing Bearer access token", {
        hasDpopHeader: false,
      }).catch(() => {});
    }

    let tokenResponse;

    if (
      grant_type ===
      "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    ) {
      tokenResponse = await handlePreAuthorizedCodeFlow(
        preAuthorizedCode,
        authorization_details,
        dpopCnf
      );
    } else if (grant_type === "authorization_code") {
      tokenResponse = await handleAuthorizationCodeFlow(
        code,
        code_verifier,
        authorization_details,
        dpopCnf
      );
    } else {
      return res.status(400).json({
        error: "unsupported_grant_type",
        error_description: `${ERROR_MESSAGES.UNSUPPORTED_GRANT}: '${grant_type}'`,
      });
    }

    res.json(tokenResponse);
  } catch (error) {
    if (sessionId) {
      logError(sessionId, "Token endpoint error", {
        error: error.message,
        stack: error.stack,
      }).catch(() => {});
    }

    // Handle authorization_pending and slow_down errors
    if (error.errorCode === "authorization_pending") {
      return res.status(400).json({
        error: "authorization_pending",
        error_description: error.message,
      });
    }

    if (error.errorCode === "slow_down") {
      return res.status(400).json({
        error: "slow_down",
        error_description: error.message,
      });
    }

    if (
      error.message.includes(ERROR_MESSAGES.INVALID_GRANT) ||
      error.message.includes(ERROR_MESSAGES.INVALID_GRANT_CODE) ||
      error.message.includes(ERROR_MESSAGES.PKCE_FAILED)
    ) {
      return res.status(400).json({
        error: "invalid_grant",
        error_description: error.message,
      });
    }

    res.status(500).json({
      error: "server_error",
      error_description: error.message,
    });
  }
});

// *****************************************************************
// ************* CREDENTIAL ENDPOINTS ******************************
// *****************************************************************

sharedRouter.post("/credential", async (req, res) => {
  let sessionObject;
  let sessionKey;
  let flowType;
  let sessionId = null;
  
  try {
    const requestBody = req.body;
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    // Validate credential request BEFORE we do any session lookup so that
    // malformed requests can return the appropriate 4xx without requiring
    // a stored session (useful for unit tests and spec compliance checks).
    const effectiveConfigurationId = validateCredentialRequest(requestBody, sessionId);

    // Get session after request validation
    const sessionData = await getSessionFromToken(token);
    sessionObject = sessionData.sessionObject;
    flowType = sessionData.flowType;
    sessionKey = sessionData.sessionKey;
    sessionId = extractSessionId(sessionKey);
    
    // Set session context for console interception to capture all logs
    if (sessionId) {
      setSessionContext(sessionId);
      // Clear context when response finishes
      res.on('finish', () => {
        clearSessionContext();
      });
      res.on('close', () => {
        clearSessionContext();
      });
    }
    
    if (!sessionObject) {
      if (sessionId) {
        await logError(sessionId, "Session not found for credential request", {
          error: ERROR_MESSAGES.SESSION_LOST
        }).catch(() => {});
      }
      return res.status(500).json({
        error: "server_error",
        error_description: ERROR_MESSAGES.SESSION_LOST,
      });
    }

    // Log credential request received
    if (sessionId) {
      await logInfo(sessionId, "Credential request received", {
        credential_configuration_id: requestBody.credential_configuration_id,
        credential_identifier: requestBody.credential_identifier,
        hasProof: !!requestBody.proof || !!requestBody.proofs
      }).catch(() => {});
    }

    // Validate proof if configuration ID is available
    if (effectiveConfigurationId) {
      try {
        // Ensure proofJwt is set (should be set by validateCredentialRequest)
        if (!requestBody.proofJwt) {
          throw new Error(`${ERROR_MESSAGES.INVALID_PROOF}. Received: proofJwt is ${typeof requestBody.proofJwt}, expected: proofJwt string or array`);
        }
        
        // First, check nonce validity BEFORE any other validation
        // This is critical for PoP failure recovery - we need to catch nonce errors
        // even if public key resolution or signature verification fails
        const decodedPayloadForNonce = jwt.decode(requestBody.proofJwt, { complete: false });
        
        // Check if nonce is missing
        if (!decodedPayloadForNonce || !decodedPayloadForNonce.nonce) {
          const received = !decodedPayloadForNonce ? 'unable to decode JWT payload' : 'payload without nonce claim';
          throw new Error(`${ERROR_MESSAGES.INVALID_PROOF_NONCE}. Received: ${received}, expected: JWT payload with nonce claim. See ${SPEC_REFS.VCI_PROOF}`);
        }
        
        // Check if nonce is valid/expired
        const nonceExists = await checkNonce(decodedPayloadForNonce.nonce);
        if (!nonceExists) {
          // Nonce exists but is invalid/expired - throw error for PoP failure recovery
          throw new Error(`${ERROR_MESSAGES.INVALID_PROOF_NONCE}. Received: nonce '${decodedPayloadForNonce.nonce}' (invalid, expired, or already used), expected: valid, unexpired, unused nonce. See ${SPEC_REFS.VCI_PROOF}`);
        }
        
        // Store nonce value for deletion after successful signature verification
        const nonceValue = decodedPayloadForNonce.nonce;
        
        const decodedProofHeader = validateProofJWT(requestBody.proofJwt, effectiveConfigurationId, sessionId);
        
        // Always verify proof JWT, even if algorithm validation was skipped
        // If header validation was skipped, decode the header to get public key info
        const headerForVerification = decodedProofHeader || jwt.decode(requestBody.proofJwt, { complete: true })?.header;
        
        if (!headerForVerification) {
          throw new Error(`${ERROR_MESSAGES.INVALID_PROOF_MALFORMED}. Received: unable to decode JWT header, expected: valid JWT with header`);
        }
        
        const publicKeyForProof = await resolvePublicKeyForProof(headerForVerification, sessionId);
        await verifyProofJWT(requestBody.proofJwt, publicKeyForProof, flowType, sessionId);
        
        // Delete the nonce after successful signature verification
        await deleteNonce(nonceValue);
        
        // Log successful proof validation
        if (sessionId) {
          await logInfo(sessionId, "Proof validation successful", {
            effectiveConfigurationId
          }).catch(() => {});
        }
      } catch (error) {
        console.error("Proof validation error:", error);
        if (sessionId) {
          await logError(sessionId, "Proof validation error", {
            error: error.message,
            stack: error.stack,
            proofValidationError: true
          }).catch(err => console.error("Failed to log proof validation error:", err));
        }
        
        if (error.message.includes(ERROR_MESSAGES.INVALID_PROOF)) {
          return res.status(400).json({
            error: "invalid_proof",
            error_description: error.message,
          });
        }
        
        if (error.message.includes(ERROR_MESSAGES.INVALID_CREDENTIAL_REQUEST)) {
          return res.status(400).json({
            error: "invalid_credential_request",
            error_description: error.message,
          });
        }

        error.proofValidationError = true;
        throw error;
      }
    }

    // Handle credential issuance
    if (sessionObject.isDeferred) {
      const response = await handleDeferredCredentialIssuance(requestBody, sessionObject, sessionKey, flowType);
      if (sessionId) {
        await logInfo(sessionId, "Deferred credential issuance initiated", {
          transaction_id: response.transaction_id
        }).catch(() => {});
      }
      return res.status(202).json(response);
    } else {
      try {
        const response = await handleImmediateCredentialIssuance(requestBody, sessionObject, effectiveConfigurationId, sessionId);
        if (sessionId) {
          await logInfo(sessionId, "Credential issued successfully", {
            effectiveConfigurationId,
            notification_id: response.notification_id
          }).catch(() => {});
        }

        // Mark session as successful after credential issuance and store notification_id
        if (sessionObject && sessionKey) {
          try {
            sessionObject.status = "success";
            sessionObject.notification_id = response.notification_id;

            if (flowType === "code") {
              await storeCodeFlowSession(sessionKey, sessionObject);
            } else {
              await storePreAuthSession(sessionKey, sessionObject);
            }
          } catch (storageError) {
            console.error("Failed to update session status after successful credential issuance:", storageError);
            if (sessionId) {
              await logError(sessionId, "Failed to update session status after successful credential issuance", {
                error: storageError.message
              }).catch(() => {});
            }
          }
        }

        return res.json(response);
      } catch (credError) {
        console.error("Credential generation error:", credError);
        if (sessionId) {
          await logError(sessionId, "Credential generation error", {
            error: credError.message,
            stack: credError.stack
          }).catch(err => console.error("Failed to log credential generation error:", err));
        }
        
        // Mark session as failed when credential generation fails
        if (sessionObject && sessionKey) {
          try {
            sessionObject.status = "failed";
            sessionObject.error = "server_error";
            sessionObject.error_description = credError.message || "Failed to generate credential";

            if (flowType === "code") {
              await storeCodeFlowSession(sessionKey, sessionObject);
            } else {
              await storePreAuthSession(sessionKey, sessionObject);
            }
          } catch (storageError) {
            console.error("Failed to update session status after credential generation failure:", storageError);
            if (sessionId) {
              await logError(sessionId, "Failed to update session status after credential generation failure", {
                error: storageError.message
              }).catch(() => {});
            }
          }
        }
        
        // If credential generation fails, it's a server error, not a client error
        return res.status(500).json({
          error: "server_error",
          error_description: credError.message || "Failed to generate credential",
        });
      }
    }
  } catch (error) {
    console.error("Credential endpoint error:", error);
    const sessionId = extractSessionId(sessionKey);
    if (sessionId) {
      await logError(sessionId, "Credential endpoint error", {
        error: error.message,
        stack: error.stack,
        errorCode: error.errorCode
      }).catch(err => console.error("Failed to log credential endpoint error:", err));
    }

    const proofRelatedErrors = [
      ERROR_MESSAGES.INVALID_PROOF,
      ERROR_MESSAGES.INVALID_PROOF_MALFORMED,
      ERROR_MESSAGES.INVALID_PROOF_ALGORITHM,
      ERROR_MESSAGES.INVALID_PROOF_PUBLIC_KEY,
      ERROR_MESSAGES.INVALID_PROOF_UNABLE,
      ERROR_MESSAGES.INVALID_PROOF_SIGNATURE,
      ERROR_MESSAGES.INVALID_PROOF_ISS,
      ERROR_MESSAGES.INVALID_PROOF_NONCE,
    ];

    if (
      error.proofValidationError ||
      proofRelatedErrors.some((msg) => error.message.includes(msg))
    ) {
      const errorResponse = {
        error: "invalid_proof",
        error_description: error.message,
      };

      if (error.message.includes(ERROR_MESSAGES.INVALID_PROOF_NONCE)) {
        try {
          const refreshedNonce = generateNonce();
          await storeNonce(refreshedNonce, NONCE_EXPIRES_IN);

          if (sessionObject && sessionKey) {
            sessionObject.c_nonce = refreshedNonce;

            if (flowType === "code") {
              await storeCodeFlowSession(sessionKey, sessionObject);
            } else {
              await storePreAuthSession(sessionKey, sessionObject);
            }
          }

          errorResponse.c_nonce = refreshedNonce;
          errorResponse.c_nonce_expires_in = NONCE_EXPIRES_IN;
        } catch (nonceError) {
          console.error("Failed to issue refreshed c_nonce after proof failure:", nonceError);
          if (sessionId) {
            await logError(sessionId, "Failed to issue refreshed c_nonce after proof failure", {
              error: nonceError.message
            }).catch(() => {});
          }
        }
      } else {
        // Mark session as failed for other proof validation errors (non-nonce errors)
        if (sessionObject && sessionKey) {
          try {
            sessionObject.status = "failed";
            sessionObject.error = "invalid_proof";
            sessionObject.error_description = error.message;

            if (flowType === "code") {
              await storeCodeFlowSession(sessionKey, sessionObject);
            } else {
              await storePreAuthSession(sessionKey, sessionObject);
            }
          } catch (storageError) {
            console.error("Failed to update session status after proof validation failure:", storageError);
            if (sessionId) {
              await logError(sessionId, "Failed to update session status after proof validation failure", {
                error: storageError.message
              }).catch(() => {});
            }
          }
        }
      }

      return res.status(400).json(errorResponse);
    }

    if (error.message.includes(ERROR_MESSAGES.INVALID_CREDENTIAL_REQUEST)) {
      // Mark session as failed when credential request validation fails
      if (sessionObject && sessionKey) {
        try {
          sessionObject.status = "failed";
          sessionObject.error = "invalid_credential_request";
          sessionObject.error_description = error.message;

          if (flowType === "code") {
            await storeCodeFlowSession(sessionKey, sessionObject);
          } else {
            await storePreAuthSession(sessionKey, sessionObject);
          }
        } catch (storageError) {
          console.error("Failed to update session status after validation failure:", storageError);
          if (sessionId) {
            await logError(sessionId, "Failed to update session status after validation failure", {
              error: storageError.message
            }).catch(() => {});
          }
        }
      }

      return res.status(400).json({
        error: "invalid_credential_request",
        error_description: error.message,
      });
    }

    // Mark session as failed for other credential request errors
    if (sessionObject && sessionKey && error.message.includes("credential")) {
      try {
        sessionObject.status = "failed";
        sessionObject.error = "credential_request_denied";
        sessionObject.error_description = error.message;

        if (flowType === "code") {
          await storeCodeFlowSession(sessionKey, sessionObject);
        } else {
          await storePreAuthSession(sessionKey, sessionObject);
        }
      } catch (storageError) {
        console.error("Failed to update session status after credential error:", storageError);
        if (sessionId) {
          await logError(sessionId, "Failed to update session status after credential error", {
            error: storageError.message
          }).catch(() => {});
        }
      }
    }

    return res.status(400).json({
      error: "credential_request_denied",
      error_description: error.message,
    });
  }
});

// *****************************************************************
// ************* DEFERRED ENDPOINTS ******************************
// *****************************************************************

sharedRouter.post("/credential_deferred", async (req, res) => {
  try {
    const { transaction_id } = req.body;
    
    if (!transaction_id) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Missing transaction_id",
      });
    }

    const sessionId = await getDeferredSessionTransactionId(transaction_id);
    
    // Set session context for console interception to capture all logs
    if (sessionId) {
      setSessionContext(sessionId);
      // Clear context when response finishes
      res.on('finish', () => {
        clearSessionContext();
      });
      res.on('close', () => {
        clearSessionContext();
      });
    }
    
    const sessionObject = await getCodeFlowSession(sessionId);
    
    if (!sessionObject) {
      return res.status(400).json({
        error: "invalid_transaction_id",
        error_description: ERROR_MESSAGES.INVALID_TRANSACTION,
      });
    }

    const credential = await handleCredentialGenerationBasedOnFormatDeferred(
      sessionObject,
      getServerUrl()
    );

    // OID4VCI v1.0 Section 9.2: Deferred Credential Response has the same structure
    // as immediate credential response - format is specified in metadata, not in response
    return res.status(200).json({
      credential,
      // notification_id: sessionObject.notification_id,
    });
  } catch (error) {
    if (sessionId) {
      logError(sessionId, "Deferred credential endpoint error", {
        error: error.message,
        stack: error.stack,
        transaction_id: req.body.transaction_id
      }).catch(() => {});
    }
    return res.status(500).json({
      error: "server_error",
      error_description: error.message,
    });
  }
});

// *****************************************************************
// ************* NONCE ENDPOINT ************************************
// *****************************************************************

sharedRouter.post("/nonce", async (req, res) => {
  try {
    const newCNonce = generateNonce();
    await storeNonce(newCNonce, NONCE_EXPIRES_IN);

    res.set("Cache-Control", "no-store");
    res.status(200).json({
      c_nonce: newCNonce,
      c_nonce_expires_in: NONCE_EXPIRES_IN,
    });
  } catch (error) {
    console.error("Nonce endpoint error:", error);
    res.set("Cache-Control", "no-store");
    res.status(500).json({
      error: "server_error",
      error_description: ERROR_MESSAGES.STORAGE_FAILED,
    });
  }
});

// *****************************************************************
// ************* Notification ENDPOINT ********************************
// *****************************************************************

sharedRouter.post("/notification", async (req, res) => {
  let sessionId = null;

  try {
    const { notification_id, event, event_description } = req.body;

    // Validate required parameters
    if (!notification_id) {
      return res.status(400).json({
        error: "invalid_notification_request",
        error_description: "Missing required parameter: notification_id",
      });
    }

    if (!event) {
      return res.status(400).json({
        error: "invalid_notification_request",
        error_description: "Missing required parameter: event",
      });
    }

  
    // Validate Authorization header with Bearer token
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Missing or invalid Authorization header. Expected: Bearer <access_token>",
      });
    }

    const accessToken = authHeader.substring(7); // Remove "Bearer " prefix

    // Find session associated with the access token
    const sessionData = await getSessionFromToken(accessToken);
    const sessionObject = sessionData.sessionObject;
    const sessionKey = sessionData.sessionKey;

    if (!sessionObject) {
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Invalid or expired access token",
      });
    }

    sessionId = extractSessionId(sessionKey);

    // Set session context for console interception to capture all logs
    if (sessionId) {
      setSessionContext(sessionId);
      // Clear context when response finishes
      res.on('finish', () => {
        clearSessionContext();
      });
      res.on('close', () => {
        clearSessionContext();
      });
    }

      // Log the notification event
    if (sessionId) {
      const logData = {
        notification_id,
        event,
        event_description: event_description || null
      };
      await logInfo(sessionId, `Notification received: ${event}`, logData).catch(() => {});
    }

    if(event === "credential_failure" || event === "credential_deleted") {
      const sessionObject = await getCodeFlowSession(sessionId);
      if (sessionObject) {

        sessionObject.status = "failed";
        console.error("Credential failure or deletion detected. Marking session as failed. Reason: " + event_description);
        
        if(sessionObject.flowType === "code") {
         
          await storeCodeFlowSession(sessionKey, sessionObject);
          return res.status(204).send();
        }else{
          await storePreAuthSession(sessionKey, sessionObject);
          return res.status(204).send();
        }

        
      }
    }
    if(event === "credential_accepted") {
      const sessionObject = await getCodeFlowSession(sessionId);
      if (sessionObject) {
        sessionObject.status = "success";
        console.error("credential accepted event received. Marking session as successful.");
         if(sessionObject.flowType === "code") {
        await storeCodeFlowSession(sessionKey, sessionObject);
        
        }else{
          await storePreAuthSession(sessionKey, sessionObject);
        }
      }
    }


    // Successfully processed notification - return 204 No Content
    res.status(204).send();

  } catch (error) {
    console.error("Notification endpoint error:", error);

    if (sessionId) {
      await logError(sessionId, "Notification endpoint error", {
        error: error.message,
        stack: error.stack
      }).catch(err => console.error("Failed to log notification error:", err));
    }

    // For unexpected server errors, return 500
    res.status(500).json({
      error: "server_error",
      error_description: error.message,
    });
  }
});

// *****************************************************************
// ************* STATUS ENDPOINT ***********************************
// *****************************************************************

sharedRouter.get("/issueStatus", async (req, res) => {
  try {
    const { sessionId } = req.query;
    
    if (!sessionId) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Missing sessionId parameter",
      });
    }

    const existingPreAuthSession = await getPreAuthSession(sessionId);
    const perAuthStatus = existingPreAuthSession ? existingPreAuthSession.status : null;

    const codeFlowSession = await getCodeFlowSession(sessionId);
    const codeFlowStatus = codeFlowSession ? codeFlowSession.status : null;

    const result = perAuthStatus || codeFlowStatus;
    
    if (result) {
      res.json({
        status: result,
        reason: "ok",
        sessionId: sessionId,
      });
    } else {
      res.json({
        status: "failed",
        reason: "not found",
        sessionId: sessionId,
      });
    }
  } catch (error) {
    console.error("Issue status endpoint error:", error);
    res.status(500).json({
      error: "server_error",
      error_description: error.message,
    });
  }
});

// *****************************************************************
// ************* HELPER FUNCTIONS **********************************
// *****************************************************************

async function validatePKCE(session, code_verifier, stored_code_challenge, sessionId = null) {
  if (!stored_code_challenge) {
    if (sessionId) {
      logError(sessionId, "PKCE validation failed: missing stored code challenge", {
        reason: "no_stored_code_challenge",
        hasCodeVerifier: !!code_verifier,
        hasStoredChallenge: false
      }).catch(() => {});
    }
    return false;
  }

  if (!code_verifier) {
    if (sessionId) {
      logError(sessionId, "PKCE validation failed: missing code verifier", {
        reason: "no_code_verifier",
        hasCodeVerifier: false,
        hasStoredChallenge: !!stored_code_challenge
      }).catch(() => {});
    }
    return false;
  }

  const tester = await base64UrlEncodeSha256(code_verifier);
  if (tester === stored_code_challenge) {
    if (sessionId) {
      logInfo(sessionId, "PKCE verification successful", {
        codeChallengeMatch: true
      }).catch(() => {});
    }
    return true;
  }

  if (sessionId) {
    logError(sessionId, "PKCE verification failed: code challenge mismatch", {
      reason: "challenge_mismatch",
      receivedChallenge: tester,
      expectedChallenge: stored_code_challenge,
      codeVerifierPresent: true,
      storedChallengePresent: true
    }).catch(() => {});
  }
  return false;
}

function getPersonaPart(inputString) {
  const personaKey = "persona=";
  const personaIndex = inputString.indexOf(personaKey);

  if (personaIndex === -1) {
    return null;
  }

  const parts = inputString.split(personaKey);
  return parts[1] || null;
}

export const publicKeyToPem = async (jwk) => {
  if (!jwk) {
    throw new Error("JWK is undefined or null.");
  }
  
  try {
    const publicKey = await jose.importJWK(jwk);
    const pem = await jose.exportSPKI(publicKey);
    return pem;
  } catch (err) {
    console.error("Error converting JWK to PEM:", err);
    console.error("Problematic JWK:", JSON.stringify(jwk));
    throw new Error(`Failed to convert JWK to PEM: ${err.message}`);
  }
};

// Initialize crypto components on module load
let cryptoComponents;
initializeCrypto()
  .then(components => {
    cryptoComponents = components;
    console.log("Cryptographic components initialized successfully");
  })
  .catch(error => {
    console.error("Failed to initialize cryptographic components:", error);
    process.exit(1);
  });

export default sharedRouter;
