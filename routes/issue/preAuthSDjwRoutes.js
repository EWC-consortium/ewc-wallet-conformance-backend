import express from "express";
import {
  storePreAuthSession,
  getPreAuthSession,
  getSessionKeyFromAccessToken,
  getCodeFlowSession,
  storeCodeFlowSession,
  getSessionKeyAuthCode,
} from "../../services/cacheServiceRedis.js";

import {
  // Shared constants
  SERVER_URL,
  DEFAULT_CREDENTIAL_TYPE,
  QR_CONFIG,
  TX_CODE_CONFIG,
  URL_SCHEMES,
  ERROR_MESSAGES,
  
  // Cryptographic utilities
  loadCryptographicKeys,
  
  // Parameter extraction utilities
  getSessionId,
  getCredentialType,
  getSignatureType,
  
  // Session management utilities
  createBaseSession,
  createSessionWithPayload,
  
  // QR code and URL generation utilities
  generateQRCode,
  buildCredentialOfferUrl,
  createPreAuthCredentialOfferUri,
  createCredentialOfferResponse,
  createCredentialOfferConfig,
  
  // Error handling utilities
  handleRouteError,
  isValidSessionId,
  isValidCredentialPayload,
  sendErrorResponse,
} from "../../utils/routeUtils.js";

const router = express.Router();

// Initialize cryptographic keys
const { privateKey, publicKeyPem } = loadCryptographicKeys();

// Helper function to manage session creation
const manageSession = async (sessionId, sessionData) => {
  try {
    const existingSession = await getPreAuthSession(sessionId);
    if (!existingSession) {
      await storePreAuthSession(sessionId, sessionData);
      return sessionData; // Return the newly created session data
    }
    return existingSession;
  } catch (error) {
    console.error("Session management error:", error);
    throw new Error(ERROR_MESSAGES.SESSION_CREATION_FAILED);
  }
};

// ******************************************************************
// ************* CREDENTIAL OFFER ENDPOINTS *************************
// ******************************************************************

/**
 * Pre-auth flow with transaction code
 * Generates a VCI request with pre-authorized flow with a transaction code
 */
router.get("/offer-tx-code", async (req, res) => {
  try {
    const sessionId = getSessionId(req);
    const credentialType = getCredentialType(req);
    const signatureType = getSignatureType(req);

    const sessionData = createBaseSession("pre-auth", false, signatureType);
    await manageSession(sessionId, sessionData);

    const credentialOffer = createPreAuthCredentialOfferUri(
      sessionId,
      credentialType,
      "/credential-offer-tx-code"
    );

    const response = await createCredentialOfferResponse(credentialOffer, sessionId);
    res.json(response);
  } catch (error) {
    handleRouteError(error, "Offer tx-code", res);
  }
});

/**
 * Pre-authorized flow with transaction code - credential offer configuration
 */
router.get("/credential-offer-tx-code/:id", (req, res) => {
  try {
    const sessionId = req.params.id;
    const credentialType = getCredentialType(req);

    if (!isValidSessionId(sessionId)) {
      return sendErrorResponse(res, "invalid_request", ERROR_MESSAGES.INVALID_SESSION_ID, 400);
    }

    const config = createCredentialOfferConfig(credentialType, sessionId, true);
    res.json(config);
  } catch (error) {
    handleRouteError(error, "Credential offer tx-code config", res);
  }
});

/**
 * Pre-authorized flow without transaction code
 */
router.get("/offer-no-code", async (req, res) => {
  try {
    const sessionId = getSessionId(req);
    const credentialType = getCredentialType(req);
    const signatureType = getSignatureType(req);

    const sessionData = createBaseSession("pre-auth", false, signatureType);
    await manageSession(sessionId, sessionData);

    const credentialOffer = createPreAuthCredentialOfferUri(
      sessionId,
      credentialType,
      "/credential-offer-no-code"
    );

    const response = await createCredentialOfferResponse(credentialOffer, sessionId);
    res.json(response);
  } catch (error) {
    handleRouteError(error, "Offer no-code", res);
  }
});

/**
 * Pre-authorized flow without transaction code with request body
 */
router.post("/offer-no-code", async (req, res) => {
  try {
    const sessionId = getSessionId(req);
    const credentialType = getCredentialType(req);
    const credentialPayload = req.body;

    if (!isValidCredentialPayload(credentialPayload)) {
      return sendErrorResponse(res, "invalid_request", "Credential payload is required", 400);
    }

    const sessionData = createSessionWithPayload(credentialPayload, true);
    await manageSession(sessionId, sessionData);

    const credentialOffer = createPreAuthCredentialOfferUri(
      sessionId,
      credentialType,
      "/credential-offer-no-code"
    );

    const response = await createCredentialOfferResponse(credentialOffer, sessionId);
    res.json(response);
  } catch (error) {
    handleRouteError(error, "Offer no-code POST", res);
  }
});

/**
 * Pre-authorized flow without transaction code - credential offer configuration
 */
router.get("/credential-offer-no-code/:id", async (req, res) => {
  try {
    const sessionId = req.params.id;
    const credentialType = getCredentialType(req);

    if (!isValidSessionId(sessionId)) {
      return sendErrorResponse(res, "invalid_request", ERROR_MESSAGES.INVALID_SESSION_ID, 400);
    }

    // Check if session exists in Redis
    const sessionData = await getPreAuthSession(sessionId);
    if (!sessionData) {
      return sendErrorResponse(res, "invalid_request", "Session not found", 404);
    }

    const config = createCredentialOfferConfig(credentialType, sessionId, false);
    res.json(config);
  } catch (error) {
    handleRouteError(error, "Credential offer no-code config", res);
  }
});

// ******************************************************************
// ************* HAIP ENDPOINTS *************************************
// ******************************************************************

/**
 * HAIP pre-authorized flow with transaction code
 * 
 * The Grant Types authorization_code and urn:ietf:params:oauth:grant-type:pre-authorized_code 
 * MUST be supported as defined in Section 4.1.1 in [OIDF.OID4VCI]
 * 
 * For Grant Type urn:ietf:params:oauth:grant-type:pre-authorized_code, the pre-authorized 
 * code is used by the issuer to identify the credential type(s).
 * As a way to invoke the Wallet, at least a custom URL scheme haip:// MUST be supported. 
 * Implementations MAY support other ways to invoke the wallets as agreed by trust 
 * frameworks/ecosystems/jurisdictions, not limited to using other custom URL schemes.
 */
router.get("/haip-offer-tx-code", async (req, res) => {
  try {
    const sessionId = getSessionId(req);
    const credentialType = getCredentialType(req);

    const sessionData = createBaseSession("pre-auth", true);
    await manageSession(sessionId, sessionData);

    const credentialOffer = createPreAuthCredentialOfferUri(
      sessionId,
      credentialType,
      "/haip-credential-offer-tx-code",
      URL_SCHEMES.HAIP
    );

    const response = await createCredentialOfferResponse(credentialOffer, sessionId);
    res.json(response);
  } catch (error) {
    handleRouteError(error, "HAIP offer tx-code", res);
  }
});

/**
 * HAIP pre-authorized flow with transaction code - credential offer configuration
 */
router.get("/haip-credential-offer-tx-code/:id", (req, res) => {
  try {
    const sessionId = req.params.id;
    const credentialType = getCredentialType(req);

    if (!isValidSessionId(sessionId)) {
      return sendErrorResponse(res, "invalid_request", ERROR_MESSAGES.INVALID_SESSION_ID, 400);
    }

    const config = createCredentialOfferConfig(credentialType, sessionId, true);
    res.json(config);
  } catch (error) {
    handleRouteError(error, "HAIP credential offer config", res);
  }
});

export default router;
