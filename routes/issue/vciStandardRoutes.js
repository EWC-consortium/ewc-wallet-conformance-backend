import express from "express";
import { v4 as uuidv4 } from "uuid";
import {
  SERVER_URL,
  getSessionId,
  getCredentialType,
  getSignatureType,
  URL_SCHEMES,
  createCodeFlowSession,
  createBaseSession,
  generateQRCode,
  createCodeFlowCredentialOfferResponse,
  createPreAuthCredentialOfferUri,
  createCredentialOfferResponse,
  createCredentialOfferConfig,
  bindSessionLoggingContext,
  handleRouteError,
} from "../../utils/routeUtils.js";
import {
  getCodeFlowSession,
  storeCodeFlowSession,
  getPreAuthSession,
  storePreAuthSession,
  logInfo,
  logError,
} from "../../services/cacheServiceRedis.js";

const vciStandardRouter = express.Router();

/**
 * Standardized VCI Offer Endpoint
 * 
 * Maps standardized parameters to existing issuance logic:
 * - flow: authorization_code | pre_authorized_code
 * - tx_code_required: true | false
 * - credential_type: e.g., urn:eu.europa.ec.eudi:pid:1, org.iso.18013.5.1.mDL
 * - credential_format: sd-jwt | mso_mdoc
 * - signature_type: x509 | jwk | kid-jwk | did-web
 */
vciStandardRouter.get("/vci/offer", async (req, res) => {
  let sessionId;
  try {
    // Extract standardized parameters
    sessionId = req.query.session_id || getSessionId(req);
    bindSessionLoggingContext(req, res, sessionId);

    const flow = req.query.flow || "authorization_code";
    const txCodeRequired = req.query.tx_code_required === "true";
    const credentialType = req.query.credential_type || getCredentialType(req);
    const credentialFormat = req.query.credential_format || "sd-jwt";
    const signatureType = req.query.signature_type || getSignatureType(req);

    await logInfo(sessionId, "Processing standardized VCI offer request", {
      flow,
      txCodeRequired,
      credentialType,
      credentialFormat,
      signatureType,
    });

    // Map signature_type to internal format
    let internalSignatureType = signatureType;
    if (signatureType === "did-web") {
      internalSignatureType = "did:web";
    } else if (signatureType === "kid-jwk") {
      internalSignatureType = "kid-jwk";
    }

    // Handle authorization code flow
    if (flow === "authorization_code") {
      // For authorization code flow, we need to create a code flow session
      // The client_id_scheme is determined by signature_type
      let clientIdScheme = "redirect_uri"; // default
      if (signatureType === "x509") {
        clientIdScheme = "x509_san_dns";
      } else if (signatureType === "did-web") {
        clientIdScheme = "did:web";
      } else if (signatureType === "did:jwk") {
        clientIdScheme = "did:jwk";
      }

      const sessionData = createCodeFlowSession(
        clientIdScheme,
        "code",
        true, // isDynamic
        false, // isDeferred
        internalSignatureType
      );
      
      await storeCodeFlowSession(sessionId, sessionData);

      // Allow caller to control wallet invocation scheme for authorization_code offers.
      // Default: openid-credential-offer://
      // If url_scheme=haip, use haip:// as required by HAIP profile.
      const invocationScheme =
        req.query.url_scheme === "haip" ? URL_SCHEMES.HAIP : URL_SCHEMES.STANDARD;

      const credentialOffer = createCodeFlowCredentialOfferResponse(
        sessionId,
        credentialType,
        clientIdScheme,
        true, // includeCredentialType
        invocationScheme
      );
      
      const encodedQR = await generateQRCode(credentialOffer, sessionId);
      
      await logInfo(sessionId, "Authorization code flow offer generated", {
        hasQR: !!encodedQR,
        deepLinkLength: credentialOffer?.length,
      });

      return res.json({
        qr: encodedQR,
        deepLink: credentialOffer,
        sessionId,
      });
    }
    // Handle pre-authorized code flow
    else if (flow === "pre_authorized_code") {
      const sessionData = createBaseSession(
        "pre-auth",
        false, // isHaip
        internalSignatureType
      );
      
      await storePreAuthSession(sessionId, sessionData);

      // Determine endpoint path based on tx_code_required
      const endpointPath = txCodeRequired
        ? "/credential-offer-tx-code"
        : "/credential-offer-no-code";

      const credentialOffer = createPreAuthCredentialOfferUri(
        sessionId,
        credentialType,
        endpointPath
      );

      const response = await createCredentialOfferResponse(credentialOffer, sessionId);

      await logInfo(sessionId, "Pre-authorized code flow offer generated", {
        txCodeRequired,
        hasQR: !!response.qr,
        deepLinkLength: response.deepLink?.length,
      });

      return res.json(response);
    } else {
      throw new Error(
        `Invalid flow parameter. Received: '${flow}', expected: 'authorization_code' or 'pre_authorized_code'`
      );
    }
  } catch (error) {
    await logError(sessionId, "Error in standardized VCI offer endpoint", {
      error: error.message,
      stack: error.stack,
    });
    handleRouteError(error, "vci/offer", res, sessionId);
  }
});

/**
 * Credential offer configuration endpoint for authorization code flow
 * This endpoint is called by wallets to retrieve the credential offer configuration
 */
vciStandardRouter.get("/credential-offer-code-sd-jwt/:id", (req, res) => {
  const sessionId = req.params.id;
  try {
    bindSessionLoggingContext(req, res, sessionId);
    const credentialType = getCredentialType(req);
    const config = createCredentialOfferConfig(
      credentialType,
      sessionId,
      false, // includeTxCode
      "authorization_code"
    );
    res.json(config);
  } catch (error) {
    handleRouteError(error, "credential-offer-code-sd-jwt", res, sessionId);
  }
});

/**
 * Credential offer configuration endpoint for pre-authorized flow with tx-code
 */
vciStandardRouter.get("/credential-offer-tx-code/:id", (req, res) => {
  const sessionId = req.params.id;
  try {
    bindSessionLoggingContext(req, res, sessionId);
    const credentialType = getCredentialType(req);
    const config = createCredentialOfferConfig(
      credentialType,
      sessionId,
      true // includeTxCode
    );
    res.json(config);
  } catch (error) {
    handleRouteError(error, "credential-offer-tx-code", res, sessionId);
  }
});

/**
 * Credential offer configuration endpoint for pre-authorized flow without tx-code
 */
vciStandardRouter.get("/credential-offer-no-code/:id", async (req, res) => {
  const sessionId = req.params.id;
  try {
    bindSessionLoggingContext(req, res, sessionId);
    const credentialType = getCredentialType(req);

    // Check if session exists
    const sessionData = await getPreAuthSession(sessionId);
    if (!sessionData) {
      return res.status(404).json({
        error: "invalid_request",
        error_description: "Session not found",
      });
    }

    const config = createCredentialOfferConfig(
      credentialType,
      sessionId,
      false // includeTxCode
    );
    res.json(config);
  } catch (error) {
    handleRouteError(error, "credential-offer-no-code", res, sessionId);
  }
});

export default vciStandardRouter;


