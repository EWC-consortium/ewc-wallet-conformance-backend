import { v4 as uuidv4 } from "uuid";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { generateNonce, buildVpRequestJWT } from "./cryptoUtils.js";
import { storeVPSession, getVPSession } from "../services/cacheServiceRedis.js";
import { getSDsFromPresentationDef } from "./vpHeplers.js";
import fs from "fs";
import base64url from "base64url";
import { createPublicKey } from "crypto";

// Configuration constants
export const CONFIG = {
  SERVER_URL: process.env.SERVER_URL || "http://localhost:3000",
  CLIENT_ID: "x509_san_dns:dss.aegean.gr",
  DEFAULT_RESPONSE_MODE: "direct_post",
  DEFAULT_NONCE_LENGTH: 16,
  QR_CONFIG: {
    type: "png",
    ec_level: "M",
    size: 20,
    margin: 10,
  },
  MEDIA_TYPE: "PNG",
  CONTENT_TYPE: "application/oauth-authz-req+jwt",
  SESSION_STATUS: {
    PENDING: "pending",
  },
  ERROR_MESSAGES: {
    INVALID_SESSION: "Invalid session ID",
    FILE_READ_ERROR: "Failed to read configuration file",
    QR_GENERATION_ERROR: "Failed to generate QR code",
    SESSION_STORE_ERROR: "Failed to store session",
    JWT_BUILD_ERROR: "Failed to build JWT",
    JWK_GENERATION_ERROR: "Failed to generate JWK",
  },
};

// Default DCQL query configuration
export const DEFAULT_DCQL_QUERY = {
  credentials: [
    {
      id: "cmwallet",
      format: "dc+sd-jwt",
      meta: {
        vct_values: ["urn:eu.europa.ec.eudi:pid:1"],
      },
      claims: [
        {
          path: ["family_name"],
        },
      ],
    },
  ],
};

// Default transaction data configuration
export const DEFAULT_TRANSACTION_DATA = {
  type: "qes_authorization",
  transaction_data_hashes_alg: ["sha-256"],
  purpose: "Verification of identity",
  documentDigests: [
    {
      hash: "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
      label: "Example Contract",
      hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
      documentLocations: [
        {
          uri: "https://protected.rp.example/contract-01.pdf?token=HS9naJKWwp901hBcK348IUHiuH8374",
          method: {
            type: "public",
          },
        },
      ],
      dtbsr: "VYDl4oTeJ5TmIPCXKdTX1MSWRLI9CKYcyMRz6xlaGg",
    },
  ],
};

// Default mDL DCQL query configuration
export const DEFAULT_MDL_DCQL_QUERY = {
  credentials: [
    {
      claims: [
        {
          path: ["org.iso.18013.5.1", "family_name"],
        },
        {
          path: ["org.iso.18013.5.1", "given_name"],
        },
        {
          path: ["org.iso.18013.5.1", "age_over_21"],
        },
      ],
      format: "mso_mdoc",
      id: "cred1",
      meta: {
        doctype_value: "org.iso.18013.5.1.mDL",
      },
    },
  ],
};

/**
 * Load configuration files safely
 * @param {string} presentationDefPath - Path to presentation definition file
 * @param {string} clientMetadataPath - Path to client metadata file
 * @param {string} privateKeyPath - Path to private key file (optional)
 * @returns {Object} - Object containing loaded configurations
 */
export function loadConfigurationFiles(presentationDefPath, clientMetadataPath, privateKeyPath = null) {
  try {
    const presentationDefinition = JSON.parse(
      fs.readFileSync(presentationDefPath, "utf-8")
    );
    const clientMetadata = JSON.parse(
      fs.readFileSync(clientMetadataPath, "utf-8")
    );

    const result = {
      presentationDefinition,
      clientMetadata,
    };

    if (privateKeyPath) {
      result.privateKey = fs.readFileSync(privateKeyPath, "utf8");
    }

    return result;
  } catch (error) {
    console.error("Failed to load configuration files:", error.message);
    throw new Error(CONFIG.ERROR_MESSAGES.FILE_READ_ERROR);
  }
}

/**
 * Generate DID JWK identifier from private key
 * @param {string} privateKey - The private key in PEM format
 * @returns {string} - The DID JWK identifier
 */
export function generateDidJwkIdentifier(privateKey) {
  try {
    const publicKey = createPublicKey(privateKey);
    const jwk = publicKey.export({ format: 'jwk' });
    return `did:jwk:${base64url(JSON.stringify(jwk))}`;
  } catch (error) {
    console.error("Failed to generate DID JWK identifier:", error.message);
    throw new Error(CONFIG.ERROR_MESSAGES.JWK_GENERATION_ERROR);
  }
}

/**
 * Create DID controller from server URL
 * @param {string} serverURL - The server URL
 * @returns {string} - The DID controller
 */
export function createDidController(serverURL) {
  let controller = serverURL;
  if (process.env.PROXY_PATH) {
    controller = serverURL.replace("/" + process.env.PROXY_PATH, "") + ":" + process.env.PROXY_PATH;
  }
  controller = controller.replace("https://", "");
  return controller;
}

/**
 * Generate DID-based client ID and key ID
 * @param {string} serverURL - The server URL
 * @returns {Object} - Object containing client_id and kid
 */
export function generateDidIdentifiers(serverURL) {
  const controller = createDidController(serverURL);
  const client_id = `did:web:${controller}`;
  const kid = `did:web:${controller}#keys-1`;
  return { client_id, kid };
}

/**
 * Generate DID JWK identifiers
 * @param {string} didJwkIdentifier - The DID JWK identifier
 * @returns {Object} - Object containing client_id and kid
 */
export function generateDidJwkIdentifiers(didJwkIdentifier) {
  const client_id = didJwkIdentifier;
  const kid = `${didJwkIdentifier}#0`; // did:jwk uses #0 as default key ID
  return { client_id, kid };
}

/**
 * Generate a QR code from a string and return it as a data URI
 * @param {string} data - The data to encode in the QR code
 * @returns {Promise<string>} - The QR code as a data URI
 */
export async function generateQRCode(data) {
  try {
    const code = qr.image(data, CONFIG.QR_CONFIG);
    const encodedQR = imageDataURI.encode(await streamToBuffer(code), CONFIG.MEDIA_TYPE);
    return encodedQR;
  } catch (error) {
    console.error("QR code generation failed:", error.message);
    throw new Error(CONFIG.ERROR_MESSAGES.QR_GENERATION_ERROR);
  }
}

/**
 * Create an OpenID4VP request URL
 * @param {string} requestUri - The request URI
 * @param {string} clientId - The client ID
 * @param {boolean} usePostMethod - Whether to use POST method
 * @returns {string} - The OpenID4VP request URL
 */
export function createOpenID4VPRequestUrl(requestUri, clientId, usePostMethod = false) {
  const baseUrl = `openid4vp://?request_uri=${encodeURIComponent(requestUri)}&client_id=${encodeURIComponent(clientId)}`;
  return usePostMethod ? `${baseUrl}&request_uri_method=post` : baseUrl;
}

/**
 * Store VP session data
 * @param {string} sessionId - The session ID
 * @param {Object} sessionData - The session data to store
 * @returns {Promise<void>}
 */
export async function storeVPSessionData(sessionId, sessionData) {
  try {
    await storeVPSession(sessionId, {
      uuid: sessionId,
      status: CONFIG.SESSION_STATUS.PENDING,
      claims: null,
      ...sessionData,
    });
  } catch (error) {
    console.error("Failed to store VP session:", error.message);
    throw new Error(CONFIG.ERROR_MESSAGES.SESSION_STORE_ERROR);
  }
}

/**
 * Create a standard VP request response
 * @param {string} qrCode - The QR code data URI
 * @param {string} deepLink - The deep link URL
 * @param {string} sessionId - The session ID
 * @returns {Object} - The response object
 */
export function createVPRequestResponse(qrCode, deepLink, sessionId) {
  return {
    qr: qrCode,
    deepLink,
    sessionId,
  };
}

/**
 * Create transaction data object with credential IDs
 * @param {Object} presentationDefinition - The presentation definition
 * @returns {Object} - The transaction data object
 */
export function createTransactionData(presentationDefinition) {
  const credentialIds = presentationDefinition.input_descriptors.map(
    (descriptor) => descriptor.id
  );
  return {
    ...DEFAULT_TRANSACTION_DATA,
    credential_ids: credentialIds,
    timestamp: new Date().toISOString(),
    transaction_id: uuidv4(),
  };
}

/**
 * Generate VP request with common parameters
 * @param {Object} params - Parameters for VP request generation
 * @returns {Promise<Object>} - The VP request result
 */
export async function generateVPRequest(params) {
  const {
    sessionId,
    responseMode,
    presentationDefinition,
    clientId,
    privateKey,
    clientMetadata,
    kid,
    serverURL,
    dcqlQuery = null,
    transactionData = null,
    usePostMethod = false,
    routePath,
  } = params;

  const nonce = generateNonce(CONFIG.DEFAULT_NONCE_LENGTH);
  const responseUri = `${serverURL}/direct_post/${sessionId}`;

  // Prepare session data
  const sessionData = {
    nonce,
    response_mode: responseMode,
  };

  if (presentationDefinition) {
    sessionData.presentation_definition = presentationDefinition;
    sessionData.sdsRequested = getSDsFromPresentationDef(presentationDefinition);
  }

  if (dcqlQuery) {
    sessionData.dcql_query = dcqlQuery;
  }

  if (transactionData) {
    sessionData.transaction_data = [transactionData];
  }

  // Store session data
  await storeVPSessionData(sessionId, sessionData);

  // Build VP request JWT if private key is provided
  if (privateKey) {
    await buildVpRequestJWT(
      clientId,
      responseUri,
      presentationDefinition,
      privateKey,
      clientMetadata,
      kid,
      serverURL,
      "vp_token",
      nonce,
      dcqlQuery,
      transactionData ? [transactionData] : null,
      responseMode
    );
  }

  // Create OpenID4VP request URL
  const requestUri = `${serverURL}${routePath}/${sessionId}`;
  const vpRequest = createOpenID4VPRequestUrl(requestUri, clientId, usePostMethod);

  // Generate QR code
  const qrCode = await generateQRCode(vpRequest);

  return createVPRequestResponse(qrCode, vpRequest, sessionId);
}

/**
 * Helper function to process VP Request
 * @param {Object} params - Parameters for VP request processing
 * @returns {Promise<Object>} - The result object with JWT or error
 */
export async function processVPRequest(params) {
  const {
    sessionId,
    clientMetadata,
    serverURL,
    clientId,
    privateKey,
    kid,
    audience,
    walletNonce,
    walletMetadata,
  } = params;

  try {
    const vpSession = await getVPSession(sessionId);

    if (!vpSession) {
      return { error: CONFIG.ERROR_MESSAGES.INVALID_SESSION, status: 400 };
    }

    const responseUri = `${serverURL}/direct_post/${sessionId}`;

    const vpRequestJWT = await buildVpRequestJWT(
      clientId,
      responseUri,
      vpSession.presentation_definition,
      privateKey,
      clientMetadata,
      kid,
      serverURL,
      "vp_token",
      vpSession.nonce,
      vpSession.dcql_query || null,
      vpSession.transaction_data || null,
      vpSession.response_mode,
      audience,
      walletNonce,
      walletMetadata,
      vpSession.state
    );

    console.log("vpRequestJWT", vpRequestJWT);
    return { jwt: vpRequestJWT, status: 200 };
  } catch (error) {
    console.error("Error in processVPRequest:", error.message);
    throw new Error(CONFIG.ERROR_MESSAGES.JWT_BUILD_ERROR);
  }
}

/**
 * Handle session creation for GET requests when no session exists
 * @param {string} sessionId - The session ID
 * @param {Object} presentationDefinition - The presentation definition
 * @param {string} responseMode - The response mode
 * @returns {Promise<void>}
 */
export async function handleSessionCreation(sessionId, presentationDefinition, responseMode) {
  const nonce = generateNonce(CONFIG.DEFAULT_NONCE_LENGTH);

  await storeVPSessionData(sessionId, {
    presentation_definition: presentationDefinition,
    nonce,
    sdsRequested: getSDsFromPresentationDef(presentationDefinition),
    response_mode: responseMode,
  });
}

// Re-export functions for convenience
export { generateNonce } from "./cryptoUtils.js";
export { getSDsFromPresentationDef } from "./vpHeplers.js";

/**
 * Create error response handler
 * @param {Error} error - The error object
 * @param {string} context - The context where the error occurred
 * @returns {Object} - The error response object
 */
export function createErrorResponse(error, context) {
  console.error(`Error in ${context}:`, error.message);
  return { error: error.message };
} 