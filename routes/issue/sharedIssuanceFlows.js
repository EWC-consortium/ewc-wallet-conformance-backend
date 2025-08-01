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
const SERVER_URL = process.env.SERVER_URL || "http://localhost:3000";
const TOKEN_EXPIRES_IN = 86400;
const NONCE_EXPIRES_IN = 86400;

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
  NONCE_GENERATION_FAILED: "Nonce generation failed"
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
const validateCredentialRequest = (requestBody) => {
  const { credential_identifier, credential_configuration_id } = requestBody;
  
  if ((credential_identifier && credential_configuration_id) || 
      (!credential_identifier && !credential_configuration_id)) {
    throw new Error(ERROR_MESSAGES.INVALID_CREDENTIAL_REQUEST);
  }

  if (!requestBody.proof || !requestBody.proof.jwt) {
    throw new Error(ERROR_MESSAGES.INVALID_PROOF);
  }

  return credential_configuration_id || credential_identifier;
};

// Validate proof JWT
const validateProofJWT = (proofJwt, effectiveConfigurationId) => {
  const issuerConfig = loadIssuerConfig();
  const credConfig = issuerConfig.credential_configurations_supported[effectiveConfigurationId];

  if (!credConfig) {
    throw new Error(`Credential configuration ID '${effectiveConfigurationId}' not found.`);
  }

  if (!credConfig.proof_types_supported?.jwt) {
    console.log(`No JWT proof type configuration found for ${effectiveConfigurationId}, skipping algorithm validation.`);
    return null;
  }

  const supportedAlgs = credConfig.proof_types_supported.jwt.proof_signing_alg_values_supported;
  if (!supportedAlgs || supportedAlgs.length === 0) {
    console.log(`No proof signing algorithms defined for ${effectiveConfigurationId}, skipping algorithm validation.`);
    return null;
  }

  const decodedProofHeader = jwt.decode(proofJwt, { complete: true })?.header;
  if (!decodedProofHeader || !decodedProofHeader.alg) {
    throw new Error(ERROR_MESSAGES.INVALID_PROOF_MALFORMED);
  }

  if (!supportedAlgs.includes(decodedProofHeader.alg)) {
    throw new Error(`${ERROR_MESSAGES.INVALID_PROOF_ALGORITHM} '${decodedProofHeader.alg}'. Supported algorithms are: ${supportedAlgs.join(", ")}.`);
  }

  return decodedProofHeader;
};

// Resolve public key for proof verification
const resolvePublicKeyForProof = async (decodedProofHeader) => {
  if (decodedProofHeader.jwk) {
    return decodedProofHeader.jwk;
  }

  if (decodedProofHeader.kid?.startsWith("did:key:")) {
    try {
      const jwks = await didKeyToJwks(decodedProofHeader.kid);
      if (jwks?.keys?.length > 0) {
        return jwks.keys[0];
      }
      throw new Error("Failed to resolve did:key to JWK or JWKS was empty.");
    } catch (error) {
      console.error("Error resolving did:key to JWK:", error);
      throw new Error("Failed to resolve public key from proof JWT kid (did:key).");
    }
  }

  if (decodedProofHeader.kid?.startsWith("did:jwk:")) {
    try {
      const didJwk = decodedProofHeader.kid;
      const jwkPart = didJwk.substring("did:jwk:".length);
      const jwkString = Buffer.from(jwkPart, "base64url").toString("utf8");
      return JSON.parse(jwkString);
    } catch (error) {
      console.error("Error resolving did:jwk to JWK:", error);
      throw new Error("Failed to resolve public key from proof JWT kid (did:jwk).");
    }
  }

  if (decodedProofHeader.kid?.startsWith("did:web:")) {
    return await resolveDidWebPublicKey(decodedProofHeader.kid);
  }

  throw new Error(ERROR_MESSAGES.INVALID_PROOF_PUBLIC_KEY);
};

// Resolve DID Web public key
const resolveDidWebPublicKey = async (didWeb) => {
  try {
    const [did, keyFragment] = didWeb.split("#");
    if (!keyFragment) {
      throw new Error("kid does not contain a key identifier fragment (e.g., #key-1)");
    }

    let didUrlPart = did.substring("did:web:".length);
    didUrlPart = decodeURIComponent(didUrlPart);

    const didParts = didUrlPart.split(":");
    const domain = didParts.shift();
    const path = didParts.join("/");

    const didDocUrl = path 
      ? `https://${domain}/${path}/did.json`
      : `https://${domain}/.well-known/did.json`;

    console.log(`Resolving did:web by fetching DID document from: ${didDocUrl}`);
    
    const response = await fetch(didDocUrl);
    if (!response.ok) {
      throw new Error(`Failed to fetch DID document, status: ${response.status}`);
    }
    
    const didDocument = await response.json();
    if (!didDocument) {
      throw new Error(`Failed to parse DID document or DID document is null for URL: ${didDocUrl}`);
    }

    const verificationMethod = didDocument.verificationMethod?.find(
      (vm) => vm.id === didWeb || (didDocument.id && didDocument.id + vm.id === didWeb)
    );

    if (!verificationMethod?.publicKeyJwk) {
      throw new Error(`Public key with id '${didWeb}' not found in DID document.`);
    }

    return verificationMethod.publicKeyJwk;
  } catch (error) {
    console.error("Error resolving did:web:", error);
    throw new Error(`Failed to resolve public key from proof JWT kid (did:web): ${error.message}`);
  }
};

// Verify proof JWT signature and claims
const verifyProofJWT = async (proofJwt, publicKeyForProof, flowType) => {
  try {
    const proofPayload = jwt.verify(
      proofJwt,
      await publicKeyToPem(publicKeyForProof),
      {
        algorithms: [jwt.decode(proofJwt, { complete: true })?.header?.alg],
        audience: SERVER_URL,
      }
    );

    // Verify claims
    if (!proofPayload.iss && flowType === "code") {
      throw new Error(ERROR_MESSAGES.INVALID_PROOF_ISS);
    }

    // Verify nonce
    const nonceExists = await checkNonce(proofPayload.nonce);
    if (!nonceExists) {
      throw new Error(ERROR_MESSAGES.INVALID_PROOF_NONCE);
    }

    // Delete the nonce to prevent replay attacks
    await deleteNonce(proofPayload.nonce);

    console.log(`Proof JWT validated. Issuer (Wallet): ${proofPayload.iss}, Nonce verified.`);
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
  const preAuthsessionKey = await getSessionKeyFromAccessToken(token);
  let sessionObject;
  let flowType = "pre-auth";

  if (preAuthsessionKey) {
    sessionObject = await getPreAuthSession(preAuthsessionKey);
    if (!sessionObject) {
      sessionObject = await getCodeFlowSession(preAuthsessionKey);
    }
  }

  if (!sessionObject) {
    const codeSessionKey = await getSessionAccessToken(token);
    if (codeSessionKey) {
      sessionObject = await getCodeFlowSession(codeSessionKey);
      flowType = "code";
    }
  }

  return { sessionObject, flowType };
};

// Handle pre-authorized code flow
const handlePreAuthorizedCodeFlow = async (preAuthorizedCode, authorizationDetails) => {
  const existingPreAuthSession = await getPreAuthSession(preAuthorizedCode);
  
  if (!existingPreAuthSession) {
    throw new Error(ERROR_MESSAGES.INVALID_GRANT);
  }

  const parsedAuthDetails = parseAuthorizationDetails(authorizationDetails);
  const chosenCredentialConfigurationId = parsedAuthDetails?.[0]?.credential_configuration_id;

  const generatedAccessToken = buildAccessToken(SERVER_URL, loadCryptographicKeys().privateKey);
  const cNonceForSession = generateNonce();

  // Update session
  existingPreAuthSession.status = "success";
  existingPreAuthSession.accessToken = generatedAccessToken;
  existingPreAuthSession.c_nonce = cNonceForSession;

  await storePreAuthSession(preAuthorizedCode, existingPreAuthSession);

  // Prepare response
  const tokenResponse = {
    access_token: generatedAccessToken,
    refresh_token: generateRefreshToken(),
    token_type: "bearer",
    expires_in: TOKEN_EXPIRES_IN,
  };

  if (parsedAuthDetails) {
    parsedAuthDetails.credential_identifiers = [chosenCredentialConfigurationId];
    tokenResponse.authorization_details = parsedAuthDetails;
  }

  return tokenResponse;
};

// Handle authorization code flow
const handleAuthorizationCodeFlow = async (code, code_verifier, authorizationDetails) => {
  const issuanceSessionId = await getSessionKeyAuthCode(code);
  
  if (!issuanceSessionId) {
    throw new Error(ERROR_MESSAGES.INVALID_GRANT_CODE);
  }

  const existingCodeSession = await getCodeFlowSession(issuanceSessionId);
  
  if (!existingCodeSession) {
    throw new Error(ERROR_MESSAGES.INVALID_GRANT_CODE);
  }

  // Verify PKCE
  const pkceVerified = await validatePKCE(
    existingCodeSession,
    code_verifier,
    existingCodeSession.requests?.challenge
  );

  if (!pkceVerified) {
    throw new Error(ERROR_MESSAGES.PKCE_FAILED);
  }

  const parsedAuthDetails = parseAuthorizationDetails(authorizationDetails);
  const chosenCredentialConfigurationId = parsedAuthDetails?.[0]?.credential_configuration_id;
  const generatedAccessToken = buildAccessToken(SERVER_URL, loadCryptographicKeys().privateKey);
  const cNonceForSession = generateNonce();

  // Update session
  existingCodeSession.results.status = "success";
  existingCodeSession.status = "success";
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
    token_type: "Bearer",
    expires_in: TOKEN_EXPIRES_IN,
  };

  if (parsedAuthDetails) {
    parsedAuthDetails.credential_identifiers = [chosenCredentialConfigurationId];
    tokenResponse.authorization_details = parsedAuthDetails;
  }

  return tokenResponse;
};

// Handle immediate credential issuance
const handleImmediateCredentialIssuance = async (requestBody, sessionObject, effectiveConfigurationId) => {
  const requestedCredentialType = [effectiveConfigurationId];
  requestBody.vct = requestedCredentialType[0];

  const credential = await handleCredentialGenerationBasedOnFormat(
    requestBody,
    sessionObject,
    SERVER_URL,
    'dc+sd-jwt'
  );

  return {
    credentials: [{ credential }]
  };
};

// Handle deferred credential issuance
const handleDeferredCredentialIssuance = async (requestBody, sessionObject) => {
  const transaction_id = generateNonce();
  sessionObject.transaction_id = transaction_id;
  sessionObject.requestBody = requestBody;
  sessionObject.isCredentialReady = false;
  sessionObject.attempt = 0;

  if (sessionObject.flowType === "code") {
    await storeCodeFlowSession('test-session-key', sessionObject);
  } else {
    await storePreAuthSession('test-pre-auth-key', sessionObject);
  }

  return {
    transaction_id,
    c_nonce: generateNonce(),
    c_nonce_expires_in: NONCE_EXPIRES_IN
  };
};

// *****************************************************************
// ************* TOKEN ENDPOINTS ***********************************
// *****************************************************************

sharedRouter.post("/token_endpoint", async (req, res) => {
  try {
    const { grant_type, code, 'pre-authorized_code': preAuthorizedCode, code_verifier, authorization_details } = req.body;

    // Validate required parameters
    if (!(code || preAuthorizedCode)) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: ERROR_MESSAGES.INVALID_REQUEST,
      });
    }

    let tokenResponse;

    if (grant_type === "urn:ietf:params:oauth:grant-type:pre-authorized_code") {
      tokenResponse = await handlePreAuthorizedCodeFlow(preAuthorizedCode, authorization_details);
    } else if (grant_type === "authorization_code") {
      tokenResponse = await handleAuthorizationCodeFlow(code, code_verifier, authorization_details);
    } else {
      return res.status(400).json({
        error: "unsupported_grant_type",
        error_description: `${ERROR_MESSAGES.UNSUPPORTED_GRANT}: '${grant_type}'`,
      });
    }

    res.json(tokenResponse);
  } catch (error) {
    console.error("Token endpoint error:", error);
    
    if (error.message.includes(ERROR_MESSAGES.INVALID_GRANT) || 
        error.message.includes(ERROR_MESSAGES.INVALID_GRANT_CODE) ||
        error.message.includes(ERROR_MESSAGES.PKCE_FAILED)) {
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
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    const requestBody = req.body;

    // Validate credential request
    const effectiveConfigurationId = validateCredentialRequest(requestBody);

    // Get session
    const { sessionObject, flowType } = await getSessionFromToken(token);
    
    if (!sessionObject) {
      return res.status(500).json({
        error: "server_error",
        error_description: ERROR_MESSAGES.SESSION_LOST,
      });
    }

    // Validate proof if configuration ID is available
    if (effectiveConfigurationId) {
      try {
        const decodedProofHeader = validateProofJWT(requestBody.proof.jwt, effectiveConfigurationId);
        
        if (decodedProofHeader) {
          const publicKeyForProof = await resolvePublicKeyForProof(decodedProofHeader);
          await verifyProofJWT(requestBody.proof.jwt, publicKeyForProof, flowType);
        }
      } catch (error) {
        console.error("Proof validation error:", error);
        
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

        return res.status(500).json({
          error: "server_error",
          error_description: ERROR_MESSAGES.SERVER_ERROR,
        });
      }
    }

    // Handle credential issuance
    if (sessionObject.isDeferred) {
      const response = await handleDeferredCredentialIssuance(requestBody, sessionObject);
      return res.status(202).json(response);
    } else {
      const response = await handleImmediateCredentialIssuance(requestBody, sessionObject, effectiveConfigurationId);
      return res.json(response);
    }
  } catch (error) {
    console.error("Credential endpoint error:", error);
    
    if (error.message.includes(ERROR_MESSAGES.INVALID_CREDENTIAL_REQUEST) ||
        error.message.includes(ERROR_MESSAGES.INVALID_PROOF)) {
      return res.status(400).json({
        error: "invalid_credential_request",
        error_description: error.message,
      });
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
    const sessionObject = await getCodeFlowSession(sessionId);
    
    if (!sessionObject) {
      return res.status(400).json({
        error: "invalid_transaction_id",
        error_description: ERROR_MESSAGES.INVALID_TRANSACTION,
      });
    }

    const credential = await handleCredentialGenerationBasedOnFormatDeferred(
      sessionObject,
      SERVER_URL
    );

    return res.status(200).json({
      format: "dc+sd-jwt",
      credential,
    });
  } catch (error) {
    console.error("Deferred credential endpoint error:", error);
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

    res.status(200).json({
      c_nonce: newCNonce,
      c_nonce_expires_in: NONCE_EXPIRES_IN,
    });
  } catch (error) {
    console.error("Nonce endpoint error:", error);
    res.status(500).json({
      error: "server_error",
      error_description: ERROR_MESSAGES.STORAGE_FAILED,
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

async function validatePKCE(session, code_verifier, stored_code_challenge) {
  if (!stored_code_challenge) {
    console.log("PKCE challenge not found in session.");
    return false;
  }
  
  if (!code_verifier) {
    console.log("Code verifier not provided in token request.");
    return false;
  }

  const tester = await base64UrlEncodeSha256(code_verifier);
  if (tester === stored_code_challenge) {
    console.log("PKCE verification success");
    return true;
  }

  console.log("PKCE verification FAILED!!!");
  console.log(`Expected challenge: ${stored_code_challenge}`);
  console.log(`Derived from verifier: ${tester}`);
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
