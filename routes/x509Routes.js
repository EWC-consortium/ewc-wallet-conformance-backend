import express from "express";
import { v4 as uuidv4 } from "uuid";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { generateNonce } from "../utils/cryptoUtils.js";
import { buildVpRequestJWT } from "../utils/cryptoUtils.js";
import { storeVPSession, getVPSession } from "../services/cacheServiceRedis.js";
import { getSDsFromPresentationDef } from "../utils/vpHeplers.js";
import fs from "fs";

const x509Router = express.Router();

// Configuration constants
const CONFIG = {
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
  },
};

// Default DCQL query configuration
const DEFAULT_DCQL_QUERY = {
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
const DEFAULT_TRANSACTION_DATA = {
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

// Load configuration files
let presentationDefinitionSdJwt;
let clientMetadata;

try {
  presentationDefinitionSdJwt = JSON.parse(
    fs.readFileSync("./data/presentation_definition_pid.json", "utf-8")
  );
  clientMetadata = JSON.parse(
    fs.readFileSync("./data/verifier-config.json", "utf-8")
  );
} catch (error) {
  console.error("Failed to load configuration files:", error.message);
  throw new Error(CONFIG.ERROR_MESSAGES.FILE_READ_ERROR);
}

/**
 * Generate a QR code from a string and return it as a data URI
 * @param {string} data - The data to encode in the QR code
 * @returns {Promise<string>} - The QR code as a data URI
 */
async function generateQRCode(data) {
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
function createOpenID4VPRequestUrl(requestUri, clientId, usePostMethod = false) {
  const baseUrl = `openid4vp://?request_uri=${encodeURIComponent(requestUri)}&client_id=${encodeURIComponent(clientId)}`;
  return usePostMethod ? `${baseUrl}&request_uri_method=post` : baseUrl;
}

/**
 * Store VP session data
 * @param {string} sessionId - The session ID
 * @param {Object} sessionData - The session data to store
 * @returns {Promise<void>}
 */
async function storeVPSessionData(sessionId, sessionData) {
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
function createVPRequestResponse(qrCode, deepLink, sessionId) {
  return {
    qr: qrCode,
    deepLink,
    sessionId,
  };
}

/**
 * Generate VP request with presentation definition
 */
x509Router.get("/generateVPRequest", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const nonce = generateNonce(CONFIG.DEFAULT_NONCE_LENGTH);
    const responseUri = `${CONFIG.SERVER_URL}/direct_post/${sessionId}`;

    // Store session data
    await storeVPSessionData(sessionId, {
      presentation_definition: presentationDefinitionSdJwt,
      nonce,
      sdsRequested: getSDsFromPresentationDef(presentationDefinitionSdJwt),
      response_mode: responseMode,
    });

    // Build VP request JWT
    await buildVpRequestJWT(
      CONFIG.CLIENT_ID,
      responseUri,
      presentationDefinitionSdJwt,
      null,
      clientMetadata,
      null,
      CONFIG.SERVER_URL,
      "vp_token",
      nonce,
      null,
      null,
      responseMode
    );

    // Create OpenID4VP request URL
    const requestUri = `${CONFIG.SERVER_URL}/x509/x509VPrequest/${sessionId}`;
    const vpRequest = createOpenID4VPRequestUrl(requestUri, CONFIG.CLIENT_ID, true);

    // Generate QR code
    const qrCode = await generateQRCode(vpRequest);

    res.json(createVPRequestResponse(qrCode, vpRequest, sessionId));
  } catch (error) {
    console.error("Error in generateVPRequest:", error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Generate VP request for GET method
 */
x509Router.get("/generateVPRequestGet", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const nonce = generateNonce(CONFIG.DEFAULT_NONCE_LENGTH);

    // Store session data
    await storeVPSessionData(sessionId, {
      presentation_definition: presentationDefinitionSdJwt,
      nonce,
      sdsRequested: getSDsFromPresentationDef(presentationDefinitionSdJwt),
      response_mode: responseMode,
    });

    // Create OpenID4VP request URL (GET method)
    const requestUri = `${CONFIG.SERVER_URL}/x509/x509VPrequest/${sessionId}`;
    const vpRequest = createOpenID4VPRequestUrl(requestUri, CONFIG.CLIENT_ID, false);

    // Generate QR code
    const qrCode = await generateQRCode(vpRequest);

    res.json(createVPRequestResponse(qrCode, vpRequest, sessionId));
  } catch (error) {
    console.error("Error in generateVPRequestGet:", error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Generate VP request with DCQL query
 */
x509Router.get("/generateVPRequestDCQL", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const nonce = generateNonce(CONFIG.DEFAULT_NONCE_LENGTH);
    const responseUri = `${CONFIG.SERVER_URL}/direct_post/${sessionId}`;

    // Store session data with DCQL query
    await storeVPSessionData(sessionId, {
      dcql_query: DEFAULT_DCQL_QUERY,
      nonce,
      response_mode: responseMode,
    });

    // Build VP request JWT with DCQL query
    await buildVpRequestJWT(
      CONFIG.CLIENT_ID,
      responseUri,
      null,
      null,
      clientMetadata,
      null,
      CONFIG.SERVER_URL,
      "vp_token",
      nonce,
      DEFAULT_DCQL_QUERY,
      null,
      responseMode
    );

    // Create OpenID4VP request URL
    const requestUri = `${CONFIG.SERVER_URL}/x509/x509VPrequest/${sessionId}`;
    const vpRequest = createOpenID4VPRequestUrl(requestUri, CONFIG.CLIENT_ID, true);

    // Generate QR code
    const qrCode = await generateQRCode(vpRequest);

    res.json(createVPRequestResponse(qrCode, vpRequest, sessionId));
  } catch (error) {
    console.error("Error in generateVPRequestDCQL:", error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Generate VP request with DCQL query for GET method
 */
x509Router.get("/generateVPRequestDCQLGET", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const nonce = generateNonce(CONFIG.DEFAULT_NONCE_LENGTH);

    // Store session data with DCQL query
    await storeVPSessionData(sessionId, {
      dcql_query: DEFAULT_DCQL_QUERY,
      nonce,
      response_mode: responseMode,
    });

    // Create OpenID4VP request URL (GET method)
    const requestUri = `${CONFIG.SERVER_URL}/x509/x509VPrequest/${sessionId}`;
    const vpRequest = createOpenID4VPRequestUrl(requestUri, CONFIG.CLIENT_ID, false);

    // Generate QR code
    const qrCode = await generateQRCode(vpRequest);

    res.json(createVPRequestResponse(qrCode, vpRequest, sessionId));
  } catch (error) {
    console.error("Error in generateVPRequestDCQLGET:", error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Generate VP request with transaction data
 */
x509Router.get("/generateVPRequestTransaction", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const nonce = generateNonce(CONFIG.DEFAULT_NONCE_LENGTH);
    const responseUri = `${CONFIG.SERVER_URL}/direct_post/${sessionId}`;

    // Create transaction data with credential IDs
    const credentialIds = presentationDefinitionSdJwt.input_descriptors.map(
      (descriptor) => descriptor.id
    );
    const transactionDataObj = {
      ...DEFAULT_TRANSACTION_DATA,
      credential_ids: credentialIds,
      timestamp: new Date().toISOString(),
      transaction_id: uuidv4(),
    };

    const base64UrlEncodedTxData = Buffer.from(JSON.stringify(transactionDataObj))
      .toString("base64url");

    // Store session data with transaction data
    await storeVPSessionData(sessionId, {
      presentation_definition: presentationDefinitionSdJwt,
      nonce,
      transaction_data: [base64UrlEncodedTxData],
      response_mode: responseMode,
      sdsRequested: getSDsFromPresentationDef(presentationDefinitionSdJwt),
    });

    // Build VP request JWT with transaction data
    await buildVpRequestJWT(
      CONFIG.CLIENT_ID,
      responseUri,
      presentationDefinitionSdJwt,
      null,
      clientMetadata,
      null,
      CONFIG.SERVER_URL,
      "vp_token",
      nonce,
      null,
      [base64UrlEncodedTxData],
      responseMode
    );

    // Create OpenID4VP request URL
    const requestUri = `${CONFIG.SERVER_URL}/x509/x509VPrequest/${sessionId}`;
    const vpRequest = createOpenID4VPRequestUrl(requestUri, CONFIG.CLIENT_ID, true);

    // Generate QR code
    const qrCode = await generateQRCode(vpRequest);

    res.json(createVPRequestResponse(qrCode, vpRequest, sessionId));
  } catch (error) {
    console.error("Error in generateVPRequestTransaction:", error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Helper function to process VP Request
 * @param {string} sessionId - The session ID
 * @param {Object} clientMetadata - The client metadata
 * @param {string} serverURL - The server URL
 * @param {string} walletNonce - The wallet nonce (optional)
 * @param {string} walletMetadata - The wallet metadata (optional)
 * @returns {Promise<Object>} - The result object with JWT or error
 */
async function generateX509VPRequest(sessionId, clientMetadata, serverURL, walletNonce, walletMetadata) {
  try {
    const vpSession = await getVPSession(sessionId);

    if (!vpSession) {
      return { error: CONFIG.ERROR_MESSAGES.INVALID_SESSION, status: 400 };
    }

    const responseUri = `${serverURL}/direct_post/${sessionId}`;

    const vpRequestJWT = await buildVpRequestJWT(
      CONFIG.CLIENT_ID,
      responseUri,
      vpSession.presentation_definition,
      null,
      clientMetadata,
      null,
      serverURL,
      "vp_token",
      vpSession.nonce,
      vpSession.dcql_query || null,
      vpSession.transaction_data || null,
      vpSession.response_mode,
      undefined,
      walletNonce,
      walletMetadata
    );

    return { jwt: vpRequestJWT, status: 200 };
  } catch (error) {
    console.error("Error in generateX509VPRequest:", error.message);
    throw new Error(CONFIG.ERROR_MESSAGES.JWT_BUILD_ERROR);
  }
}

/**
 * Request URI endpoint (handles both POST and GET)
 */
x509Router
  .route("/x509VPrequest/:id")
  .post(express.urlencoded({ extended: true }), async (req, res) => {
    try {
      console.log("POST request received");
      const sessionId = req.params.id;

      // Extract wallet parameters
      const { wallet_nonce: walletNonce, wallet_metadata: walletMetadata } = req.body;
      if (walletNonce || walletMetadata) {
        console.log(`Received from wallet: wallet_nonce=${walletNonce}, wallet_metadata=${walletMetadata}`);
      }

      const result = await generateX509VPRequest(
        sessionId,
        clientMetadata,
        CONFIG.SERVER_URL,
        walletNonce,
        walletMetadata
      );

      if (result.error) {
        return res.status(result.status).json({ error: result.error });
      }

      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      console.error("Error in POST /x509VPrequest/:id:", error.message);
      res.status(500).json({ error: error.message });
    }
  })
  .get(async (req, res) => {
    try {
      console.log("GET request received");
      const sessionId = req.params.id;
      const result = await generateX509VPRequest(sessionId, clientMetadata, CONFIG.SERVER_URL);

      if (result.error) {
        return res.status(result.status).json({ error: result.error });
      }

      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      console.error("Error in GET /x509VPrequest/:id:", error.message);
      res.status(500).json({ error: error.message });
    }
  });

export default x509Router; 