import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { generateNonce, buildVpRequestJWT } from "./cryptoUtils.js";
import { getSDsFromPresentationDef } from "./vpHeplers.js";
import { storeVPSession, getVPSession, logInfo, logWarn, logError, logDebug } from "../services/cacheServiceRedis.js";
import { createPublicKey } from "crypto";
import base64url from "base64url";

// ============================================================================
// SHARED CONSTANTS
// ============================================================================

export const SERVER_URL = process.env.SERVER_URL || "http://localhost:3000";
export const PROXY_PATH = process.env.PROXY_PATH || null;

export const DEFAULT_CREDENTIAL_TYPE = "VerifiablePortableDocumentA2SDJWT";
export const DEFAULT_SIGNATURE_TYPE = "jwt";
export const DEFAULT_CLIENT_ID_SCHEME = "redirect_uri";
export const DEFAULT_REDIRECT_URI = "openid4vp://";

export const QR_CONFIG = {
  type: "png",
  ec_level: "H",
  size: 10,
  margin: 10,
};

export const CLIENT_METADATA = {
  client_name: "UAegean EWC Verifier",
  logo_uri: "https://studyingreece.edu.gr/wp-content/uploads/2023/03/25.png",
  location: "Greece",
  cover_uri: "string",
  description: "EWC pilot case verification",
  vp_formats: {
    "vc+sd-jwt": {
      "sd-jwt_alg_values": ["ES256", "ES384"],
      "kb-jwt_alg_values": ["ES256", "ES384"],
    },
  },
};

export const TX_CODE_CONFIG = {
  length: 4,
  input_mode: "numeric",
  description: "Please provide the one-time code that was sent via e-mail or offline",
};

export const URL_SCHEMES = {
  STANDARD: "openid-credential-offer://",
  HAIP: "haip://",
  OPENID4VP: "openid4vp://",
};

export const ERROR_MESSAGES = {
  // Common errors
  SESSION_CREATION_FAILED: "Failed to create session",
  QR_GENERATION_FAILED: "Failed to generate QR code",
  INVALID_SESSION_ID: "Invalid session ID",
  INVALID_CREDENTIAL_TYPE: "Invalid credential type",
  STORAGE_ERROR: "Storage operation failed",
  QR_ENCODING_ERROR: "QR code encoding failed",
  CRYPTO_KEY_LOAD_ERROR: "Failed to load cryptographic keys",
  
  // Code flow specific errors
  ITB_SESSION_EXPIRED: "ITB session expired",
  INVALID_RESPONSE_TYPE: "Invalid response_type",
  NO_CREDENTIALS_REQUESTED: "no credentials requested",
  PARSE_AUTHORIZATION_DETAILS_ERROR: "error parsing authorization details",
  MISSING_RESPONSE_TYPE: "authorizationDetails missing response_type",
  MISSING_CODE_CHALLENGE: "authorizationDetails missing code_challenge",
  PAR_REQUEST_NOT_FOUND: "ERROR: request_uri present in authorization endpoint, but no par request cached for request_uri",
  ISSUANCE_SESSION_NOT_FOUND: "issuance session not found",
  NO_JWT_PRESENTED: "no jwt presented",
};

// Configuration constants for x509 routes
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

// ============================================================================
// CRYPTOGRAPHIC UTILITIES
// ============================================================================

/**
 * Load cryptographic keys from files
 * @returns {Object} Object containing privateKey and publicKeyPem
 */
export const loadCryptographicKeys = () => {
  try {
    const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
    const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");
    return { privateKey, publicKeyPem };
  } catch (error) {
    console.error("Error loading cryptographic keys:", error);
    throw new Error(ERROR_MESSAGES.CRYPTO_KEY_LOAD_ERROR);
  }
};

/**
 * Load presentation definition from file
 * @returns {Object} Presentation definition object
 */
export const loadPresentationDefinition = () => {
  return JSON.parse(fs.readFileSync("./data/presentation_definition_sdjwt.json", "utf-8"));
};

/**
 * Load private key from file
 * @returns {string} Private key content
 */
export const loadPrivateKey = () => {
  return fs.readFileSync("./didjwks/did_private_pkcs8.key", "utf8");
};

// ============================================================================
// PARAMETER EXTRACTION UTILITIES
// ============================================================================

/**
 * Extract session ID from request with fallback to UUID
 * @param {Object} req - Express request object
 * @returns {string} Session ID
 */
export const getSessionId = (req) => {
  return req.query.sessionId || uuidv4();
};

/**
 * Extract credential type from request with default fallback
 * @param {Object} req - Express request object
 * @returns {string} Credential type
 */
export const getCredentialType = (req) => {
  return req.query.credentialType || req.query.type || DEFAULT_CREDENTIAL_TYPE;
};

/**
 * Extract signature type from request with default fallback
 * @param {Object} req - Express request object
 * @returns {string} Signature type
 */
export const getSignatureType = (req) => {
  return req.query.signatureType || DEFAULT_SIGNATURE_TYPE;
};

/**
 * Extract client ID scheme from request with default fallback
 * @param {Object} req - Express request object
 * @returns {string} Client ID scheme
 */
export const getClientIdScheme = (req) => {
  return req.query.client_id_scheme || DEFAULT_CLIENT_ID_SCHEME;
};

// ============================================================================
// SESSION MANAGEMENT UTILITIES
// ============================================================================

/**
 * Create base session object with common properties
 * @param {string} flowType - Type of flow (pre-auth, code, etc.)
 * @param {boolean} isHaip - Whether this is a HAIP flow
 * @param {string} signatureType - Signature type
 * @param {Object} additionalProps - Additional properties to add
 * @returns {Object} Base session object
 */
export const createBaseSession = (flowType = "pre-auth", isHaip = false, signatureType = null, additionalProps = {}) => {
  const session = {
    status: "pending",
    flowType,
    isHaip,
    ...additionalProps
  };

  if (signatureType) {
    session.signatureType = signatureType;
  }

  return session;
};

/**
 * Create session with credential payload
 * @param {Object} credentialPayload - Credential payload data
 * @param {boolean} isHaip - Whether this is a HAIP flow
 * @returns {Object} Session object with credential payload
 */
export const createSessionWithPayload = (credentialPayload, isHaip = true) => {
  return {
    ...createBaseSession("pre-auth", isHaip),
    credentialPayload
  };
};

/**
 * Create code flow session object
 * @param {string} client_id_scheme - Client ID scheme
 * @param {string} flowType - Flow type
 * @param {boolean} isDynamic - Whether this is a dynamic flow
 * @param {boolean} isDeferred - Whether this is a deferred flow
 * @param {string} signatureType - Signature type
 * @returns {Object} Code flow session object
 */
export const createCodeFlowSession = (client_id_scheme, flowType, isDynamic = false, isDeferred = false, signatureType = null) => {
  const session = {
    walletSession: null,
    requests: null,
    results: null,
    status: "pending",
    client_id_scheme: client_id_scheme,
    flowType: flowType,
  };

  if (isDynamic) session.isDynamic = true;
  if (isDeferred) session.isDeferred = true;
  if (signatureType) session.signatureType = signatureType;

  return session;
};

// ============================================================================
// QR CODE AND URL GENERATION UTILITIES
// ============================================================================

/**
 * Generate QR code from credential offer
 * @param {string} credentialOffer - Credential offer string
 * @returns {Promise<string>} Base64 encoded QR code
 */
export const generateQRCode = async (credentialOffer, sessionId = null) => {
  try {
    if (sessionId) {
      await logDebug(sessionId, "Generating QR code", {
        offerLength: credentialOffer?.length
      });
    }
    
    const code = qr.image(credentialOffer, QR_CONFIG);
    const mediaType = "PNG";
    const encodedQR = imageDataURI.encode(await streamToBuffer(code), mediaType);
    
    if (sessionId) {
      await logInfo(sessionId, "QR code generated successfully", {
        encodedLength: encodedQR?.length
      });
    }
    
    return encodedQR;
  } catch (error) {
    if (sessionId) {
      await logError(sessionId, "QR code generation error", {
        error: error.message,
        stack: error.stack
      });
    } else {
      console.error("QR code generation error:", error);
    }
    throw new Error(ERROR_MESSAGES.QR_GENERATION_FAILED);
  }
};

/**
 * Build credential offer URL with parameters
 * @param {string} sessionId - Session ID
 * @param {string} credentialType - Credential type
 * @param {string} endpointPath - Endpoint path
 * @param {string} urlScheme - URL scheme to use
 * @param {Object} additionalParams - Additional query parameters
 * @returns {string} Encoded credential offer URL
 */
export const buildCredentialOfferUrl = (sessionId, credentialType, endpointPath, urlScheme = URL_SCHEMES.STANDARD, additionalParams = {}) => {
  const params = new URLSearchParams();
  params.append('type', credentialType);
  
  // Add additional parameters
  Object.entries(additionalParams).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      params.append(key, value);
    }
  });
  
  const queryString = params.toString();
  const fullUrl = `${SERVER_URL}${endpointPath}/${sessionId}${queryString ? `?${queryString}` : ''}`;
  
  return encodeURIComponent(fullUrl);
};

/**
 * Create pre-auth credential offer URI
 * @param {string} sessionId - Session ID
 * @param {string} credentialType - Credential type
 * @param {string} endpointPath - Endpoint path
 * @param {string} urlScheme - URL scheme to use
 * @param {Object} additionalParams - Additional query parameters
 * @returns {string} Proper OpenID4VCI credential offer URI
 */
export const createPreAuthCredentialOfferUri = (sessionId, credentialType, endpointPath, urlScheme = URL_SCHEMES.STANDARD, additionalParams = {}) => {
  const encodedCredentialOfferUri = buildCredentialOfferUrl(sessionId, credentialType, endpointPath, urlScheme, additionalParams);
  const credentialOffer = `${urlScheme}?credential_offer_uri=${encodedCredentialOfferUri}`;
  return credentialOffer;
};

/**
 * Create credential offer response with QR code
 * @param {string} credentialOffer - Credential offer string
 * @param {string} sessionId - Session ID
 * @returns {Promise<Object>} Response object with QR code and deep link
 */
export const createCredentialOfferResponse = async (credentialOffer, sessionId) => {
  try {
    const qr = await generateQRCode(credentialOffer);
    return {
      qr,
      deepLink: credentialOffer,
      sessionId,
    };
  } catch (error) {
    console.error("Credential offer response creation error:", error);
    throw error;
  }
};

/**
 * Create credential offer configuration object
 * @param {string} credentialType - Credential type
 * @param {string} sessionId - Session ID
 * @param {boolean} includeTxCode - Whether to include transaction code
 * @param {string} grantType - Grant type to use
 * @returns {Object} Credential offer configuration
 */
export const createCredentialOfferConfig = (credentialType, sessionId, includeTxCode = false, grantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code") => {
  const config = {
    credential_issuer: SERVER_URL,
    credential_configuration_ids: [credentialType],
    grants: {
      [grantType]: {},
    },
  };

  // For authorization code flow, use issuer_state
  if (grantType === "authorization_code") {
    config.grants[grantType].issuer_state = sessionId;
  } else {
    // For pre-authorized code flow, use pre-authorized_code
    config.grants[grantType]["pre-authorized_code"] = sessionId;
  }

  if (includeTxCode) {
    config.grants[grantType].tx_code = TX_CODE_CONFIG;
  }

  return config;
};

/**
 * Build code flow credential offer URL
 * @param {string} uuid - Session UUID
 * @param {string} credentialType - Credential type
 * @param {string} client_id_scheme - Client ID scheme
 * @param {boolean} includeCredentialType - Whether to include credential type in URL
 * @returns {string} Encoded credential offer URL
 */
export const buildCodeFlowCredentialOfferUrl = (uuid, credentialType, client_id_scheme, includeCredentialType = true) => {
  const baseUrl = `${SERVER_URL}/credential-offer-code-sd-jwt/${uuid}`;
  const params = new URLSearchParams();
  
  if (includeCredentialType) {
    params.append('credentialType', credentialType);
  }
  params.append('scheme', client_id_scheme);
  
  const queryString = params.toString();
  const fullUrl = queryString ? `${baseUrl}?${queryString}` : baseUrl;
  
  return encodeURIComponent(fullUrl);
};

/**
 * Create code flow credential offer response
 * @param {string} uuid - Session UUID
 * @param {string} credentialType - Credential type
 * @param {string} client_id_scheme - Client ID scheme
 * @param {boolean} includeCredentialType - Whether to include credential type in URL
 * @returns {string} Credential offer string
 */
export const createCodeFlowCredentialOfferResponse = (uuid, credentialType, client_id_scheme, includeCredentialType = true) => {
  const encodedCredentialOfferUri = buildCodeFlowCredentialOfferUrl(uuid, credentialType, client_id_scheme, includeCredentialType);
  const credentialOffer = `openid-credential-offer://?credential_offer_uri=${encodedCredentialOfferUri}`;
  return credentialOffer;
};

// ============================================================================
// DID UTILITIES
// ============================================================================

/**
 * Build DID controller string
 * @returns {string} DID controller string
 */
export const buildDidController = () => {
  let controller = SERVER_URL;
  if (PROXY_PATH) {
    controller = SERVER_URL.replace("/" + PROXY_PATH, "") + ":" + PROXY_PATH;
  }
  return controller.replace("https://", "");
};

// ============================================================================
// ERROR HANDLING UTILITIES
// ============================================================================

/**
 * Create standardized error response
 * @param {string} error - Error code
 * @param {string} description - Error description
 * @param {number} status - HTTP status code
 * @returns {Object} Standardized error response
 */
export const createErrorResponse = (error, description, status = 500, sessionId = null) => {
  if (sessionId) {
    logError(sessionId, "Creating error response", {
      error: error || "server_error",
      description: description || "An unexpected error occurred",
      status
    }).catch(err => console.error("Failed to log error response:", err));
  }
  
  return {
    status,
    body: {
      error: error || "server_error",
      error_description: description || "An unexpected error occurred"
    }
  };
};

/**
 * Handle route errors consistently
 * @param {Error} error - Error object
 * @param {string} context - Error context for logging
 * @param {Object} res - Express response object
 */
export const handleRouteError = (error, context, res, sessionId = null) => {
  if (sessionId) {
    logError(sessionId, `${context} error`, {
      error: error.message,
      stack: error.stack,
      context
    }).catch(err => console.error("Failed to log route error:", err));
  } else {
    console.error(`${context} error:`, error);
  }
  
  const errorResponse = createErrorResponse("server_error", error.message, 500, sessionId);
  res.status(errorResponse.status).json(errorResponse.body);
};

// ============================================================================
// VALIDATION UTILITIES
// ============================================================================

/**
 * Validate session ID
 * @param {string} sessionId - Session ID to validate
 * @returns {boolean} Whether session ID is valid
 */
export const isValidSessionId = (sessionId) => {
  return sessionId && typeof sessionId === 'string' && sessionId.trim().length > 0;
};

/**
 * Validate credential payload
 * @param {Object} payload - Credential payload to validate
 * @returns {boolean} Whether payload is valid
 */
export const isValidCredentialPayload = (payload) => {
  return payload && typeof payload === 'object' && Object.keys(payload).length > 0;
};

// ============================================================================
// RESPONSE UTILITIES
// ============================================================================

/**
 * Send standardized success response
 * @param {Object} res - Express response object
 * @param {Object} data - Response data
 * @param {number} status - HTTP status code
 */
export const sendSuccessResponse = (res, data, status = 200) => {
  res.status(status).json(data);
};

/**
 * Send standardized error response
 * @param {Object} res - Express response object
 * @param {string} error - Error code
 * @param {string} description - Error description
 * @param {number} status - HTTP status code
 */
export const sendErrorResponse = (res, error, description, status = 500) => {
  const errorResponse = createErrorResponse(error, description, status);
  res.status(errorResponse.status).json(errorResponse.body);
};

// ============================================================================
// X509 ROUTES UTILITIES
// ============================================================================

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

  await logInfo(sessionId, "Starting VP request generation in routeUtils", {
    responseMode,
    clientId,
    hasPrivateKey: !!privateKey,
    hasDcqlQuery: !!dcqlQuery,
    hasTransactionData: !!transactionData,
    usePostMethod,
    routePath
  });

  const nonce = generateNonce(CONFIG.DEFAULT_NONCE_LENGTH);
  const responseUri = `${serverURL}/direct_post/${sessionId}`;
  
  await logDebug(sessionId, "Generated nonce and response URI", {
    nonce,
    responseUri
  });

  // Prepare session data
  const sessionData = {
    nonce,
    response_mode: responseMode,
  };

  if (presentationDefinition) {
    sessionData.presentation_definition = presentationDefinition;
    sessionData.sdsRequested = getSDsFromPresentationDef(presentationDefinition);
    await logDebug(sessionId, "Added presentation definition to session", {
      inputDescriptors: presentationDefinition.input_descriptors?.length || 0
    });
  }

  if (dcqlQuery) {
    sessionData.dcql_query = dcqlQuery;
    await logDebug(sessionId, "Added DCQL query to session", {
      credentialsCount: dcqlQuery.credentials?.length || 0
    });
  }

  if (transactionData) {
    sessionData.transaction_data = [transactionData];
    await logDebug(sessionId, "Added transaction data to session", {
      transactionType: transactionData.type
    });
  }

  // Store session data
  await logDebug(sessionId, "Storing VP session data");
  await storeVPSessionData(sessionId, sessionData);
  await logInfo(sessionId, "VP session data stored successfully");

  // Build VP request JWT if private key is provided
  if (privateKey) {
    await logDebug(sessionId, "Building VP request JWT with private key");
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
    await logInfo(sessionId, "VP request JWT built successfully");
  } else {
    await logDebug(sessionId, "No private key provided, skipping JWT build");
  }

  // Create OpenID4VP request URL
  const requestUri = `${serverURL}${routePath}/${sessionId}`;
  const vpRequest = createOpenID4VPRequestUrl(requestUri, clientId, usePostMethod);
  
  await logDebug(sessionId, "Created OpenID4VP request URL", {
    requestUri,
    vpRequest: vpRequest.substring(0, 100) + "..."
  });

  // Generate QR code
  const qrCode = await generateQRCode(vpRequest, sessionId);

  const response = createVPRequestResponse(qrCode, vpRequest, sessionId);
  await logInfo(sessionId, "VP request generation completed successfully", {
    hasQrCode: !!response.qr,
    deepLinkLength: response.deepLink?.length
  });
  
  return response;
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

  await logInfo(sessionId, "Starting VP request processing in routeUtils", {
    clientId,
    hasPrivateKey: !!privateKey,
    hasAudience: !!audience,
    hasWalletNonce: !!walletNonce,
    hasWalletMetadata: !!walletMetadata
  });

  try {
    await logDebug(sessionId, "Retrieving VP session data");
    const vpSession = await getVPSession(sessionId);

    if (!vpSession) {
      await logError(sessionId, "VP session not found", {
        sessionId,
        error: CONFIG.ERROR_MESSAGES.INVALID_SESSION
      });
      return { error: CONFIG.ERROR_MESSAGES.INVALID_SESSION, status: 400 };
    }
    
    await logInfo(sessionId, "VP session retrieved successfully", {
      hasNonce: !!vpSession.nonce,
      hasPresentationDefinition: !!vpSession.presentation_definition,
      hasDcqlQuery: !!vpSession.dcql_query,
      hasTransactionData: !!vpSession.transaction_data,
      responseMode: vpSession.response_mode
    });

    const responseUri = `${serverURL}/direct_post/${sessionId}`;
    
    await logDebug(sessionId, "Building VP request JWT", {
      responseUri,
      responseMode: vpSession.response_mode
    });

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
    
    await logInfo(sessionId, "VP request JWT built successfully", {
      jwtLength: vpRequestJWT?.length
    });

    console.log("vpRequestJWT", vpRequestJWT);
    await logDebug(sessionId, "VP request JWT details", {
      jwt: vpRequestJWT
    });
    
    await logInfo(sessionId, "VP request processing completed successfully");
    return { jwt: vpRequestJWT, status: 200 };
  } catch (error) {
    console.error("Error in processVPRequest:", error.message);
    await logError(sessionId, "Error in processVPRequest", {
      error: error.message,
      stack: error.stack
    });
    throw new Error(CONFIG.ERROR_MESSAGES.JWT_BUILD_ERROR);
  }
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
    await logDebug(sessionId, "Storing VP session data", {
      hasNonce: !!sessionData.nonce,
      hasPresentationDefinition: !!sessionData.presentation_definition,
      hasDcqlQuery: !!sessionData.dcql_query,
      hasTransactionData: !!sessionData.transaction_data,
      responseMode: sessionData.response_mode
    });
    
    await storeVPSession(sessionId, {
      uuid: sessionId,
      status: CONFIG.SESSION_STATUS.PENDING,
      claims: null,
      ...sessionData,
    });
    
    await logInfo(sessionId, "VP session data stored successfully");
  } catch (error) {
    console.error("Failed to store VP session:", error.message);
    await logError(sessionId, "Failed to store VP session", {
      error: error.message,
      stack: error.stack
    });
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
 * Handle session creation for GET requests when no session exists
 * @param {string} sessionId - The session ID
 * @param {Object} presentationDefinition - The presentation definition
 * @param {string} responseMode - The response mode
 * @returns {Promise<void>}
 */
export async function handleSessionCreation(sessionId, presentationDefinition, responseMode) {
  await logInfo(sessionId, "Creating new VP session", {
    responseMode,
    hasPresentation: !!presentationDefinition
  });
  
  const nonce = generateNonce(CONFIG.DEFAULT_NONCE_LENGTH);
  
  await logDebug(sessionId, "Generated nonce for new session", {
    nonce
  });

  await storeVPSessionData(sessionId, {
    presentation_definition: presentationDefinition,
    nonce,
    sdsRequested: getSDsFromPresentationDef(presentationDefinition),
    response_mode: responseMode,
  });
  
  await logInfo(sessionId, "VP session created successfully");
}

// ============================================================================
// DID UTILITIES
// ============================================================================

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