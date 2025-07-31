import express from "express";
import { v4 as uuidv4 } from "uuid";
import {
  CONFIG,
  DEFAULT_DCQL_QUERY,
  DEFAULT_TRANSACTION_DATA,
  loadConfigurationFiles,
  generateDidJwkIdentifier,
  generateDidJwkIdentifiers,
  generateVPRequest,
  processVPRequest,
  createTransactionData,
  createErrorResponse,
} from "../utils/routeUtils.js";

const didJwkRouter = express.Router();

// Load configuration files and generate DID JWK identifier
const { presentationDefinition, clientMetadata, privateKey } = loadConfigurationFiles(
  "./data/presentation_definition_pid.json",
  "./data/verifier-config.json",
  "./didjwks/did_private_pkcs8.key"
);

const didJwkIdentifier = generateDidJwkIdentifier(privateKey);

/**
 * Generate VP request with presentation definition
 */
didJwkRouter.get("/generateVPRequest", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const { client_id, kid } = generateDidJwkIdentifiers(didJwkIdentifier);

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
      routePath: "/did-jwk/didJwkVPrequest",
    });

    res.json(result);
  } catch (error) {
    const errorResponse = createErrorResponse(error, "generateVPRequest");
    res.status(500).json(errorResponse);
  }
});

/**
 * Generate VP request for GET method
 */
didJwkRouter.get("/generateVPRequestGET", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const { client_id, kid } = generateDidJwkIdentifiers(didJwkIdentifier);

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      presentationDefinition,
      clientId: client_id,
      privateKey,
      clientMetadata,
      kid,
      serverURL: CONFIG.SERVER_URL,
      usePostMethod: false,
      routePath: "/did-jwk/didJwkVPrequest",
    });

    res.json(result);
  } catch (error) {
    const errorResponse = createErrorResponse(error, "generateVPRequestGET");
    res.status(500).json(errorResponse);
  }
});

/**
 * Generate VP request with DCQL query
 */
didJwkRouter.get("/generateVPRequestDCQL", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const { client_id, kid } = generateDidJwkIdentifiers(didJwkIdentifier);

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      presentationDefinition: null,
      clientId: client_id,
    privateKey,
    clientMetadata,
    kid,
      serverURL: CONFIG.SERVER_URL,
      dcqlQuery: DEFAULT_DCQL_QUERY,
      usePostMethod: true,
      routePath: "/did-jwk/didJwkVPrequest",
    });

    res.json(result);
  } catch (error) {
    const errorResponse = createErrorResponse(error, "generateVPRequestDCQL");
    res.status(500).json(errorResponse);
  }
});

/**
 * Generate VP request with DCQL query for GET method
 */
didJwkRouter.get("/generateVPRequestDCQLGET", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const { client_id, kid } = generateDidJwkIdentifiers(didJwkIdentifier);

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      presentationDefinition: null,
      clientId: client_id,
      privateKey,
      clientMetadata,
      kid,
      serverURL: CONFIG.SERVER_URL,
      dcqlQuery: DEFAULT_DCQL_QUERY,
      usePostMethod: false,
      routePath: "/did-jwk/didJwkVPrequest",
    });

    res.json(result);
  } catch (error) {
    const errorResponse = createErrorResponse(error, "generateVPRequestDCQLGET");
    res.status(500).json(errorResponse);
  }
});

/**
 * Generate VP request with transaction data
 */
didJwkRouter.get("/generateVPRequestTransaction", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const { client_id, kid } = generateDidJwkIdentifiers(didJwkIdentifier);

    const transactionDataObj = createTransactionData(presentationDefinition);
  const base64UrlEncodedTxData = Buffer.from(JSON.stringify(transactionDataObj))
      .toString("base64url");

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      presentationDefinition,
      clientId: client_id,
    privateKey,
    clientMetadata,
    kid,
      serverURL: CONFIG.SERVER_URL,
      transactionData: base64UrlEncodedTxData,
      usePostMethod: true,
      routePath: "/did-jwk/didJwkVPrequest",
    });

    res.json(result);
  } catch (error) {
    const errorResponse = createErrorResponse(error, "generateVPRequestTransaction");
    res.status(500).json(errorResponse);
  }
});

/**
 * Request URI endpoint (handles both POST and GET)
 */
didJwkRouter
  .route("/didJwkVPrequest/:id")
  .post(async (req, res) => {
    try {
      const sessionId = req.params.id;
      const { client_id, kid } = generateDidJwkIdentifiers(didJwkIdentifier);
      const { wallet_nonce: walletNonce, wallet_metadata: walletMetadata } = req.body;

      if (walletNonce || walletMetadata) {
        console.log(`Received from wallet: wallet_nonce=${walletNonce}, wallet_metadata=${walletMetadata}`);
      }

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

    if (result.error) {
      return res.status(result.status).json({ error: result.error });
    }

      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      const errorResponse = createErrorResponse(error, "POST /didJwkVPrequest/:id");
      res.status(500).json(errorResponse);
    }
  })
  .get(async (req, res) => {
    try {
      const sessionId = req.params.id;
      const { client_id, kid } = generateDidJwkIdentifiers(didJwkIdentifier);

      const result = await processVPRequest({
        sessionId,
        clientMetadata,
        serverURL: CONFIG.SERVER_URL,
        clientId: client_id,
        privateKey,
        kid,
      });

    if (result.error) {
      return res.status(result.status).json({ error: result.error });
    }

      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      const errorResponse = createErrorResponse(error, "GET /didJwkVPrequest/:id");
      res.status(500).json(errorResponse);
    }
  });

export default didJwkRouter;