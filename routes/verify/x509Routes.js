import express from "express";
import { v4 as uuidv4 } from "uuid";
import {
  CONFIG,
  DEFAULT_DCQL_QUERY,
  DEFAULT_TRANSACTION_DATA,
  loadConfigurationFiles,
  generateVPRequest,
  processVPRequest,
  createTransactionData,
  createErrorResponse,
} from "../../utils/routeUtils.js";

const x509Router = express.Router();

// Load configuration files
const { presentationDefinition, clientMetadata } = loadConfigurationFiles(
  "./data/presentation_definition_pid.json",
  "./data/verifier-config.json"
);

/**
 * Generate VP request with presentation definition
 */
x509Router.get("/generateVPRequest", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      presentationDefinition,
      clientId: CONFIG.CLIENT_ID,
      privateKey: null,
      clientMetadata,
      kid: null,
      serverURL: CONFIG.SERVER_URL,
      usePostMethod: true,
      routePath: "/x509/x509VPrequest",
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
x509Router.get("/generateVPRequestGet", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      presentationDefinition,
      clientId: CONFIG.CLIENT_ID,
      privateKey: null,
      clientMetadata,
      kid: null,
      serverURL: CONFIG.SERVER_URL,
      usePostMethod: false,
      routePath: "/x509/x509VPrequest",
    });

    res.json(result);
  } catch (error) {
    const errorResponse = createErrorResponse(error, "generateVPRequestGet");
    res.status(500).json(errorResponse);
  }
});

/**
 * Generate VP request with DCQL query
 */
x509Router.get("/generateVPRequestDCQL", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      presentationDefinition: null,
      clientId: CONFIG.CLIENT_ID,
      privateKey: null,
      clientMetadata,
      kid: null,
      serverURL: CONFIG.SERVER_URL,
      dcqlQuery: DEFAULT_DCQL_QUERY,
      usePostMethod: true,
      routePath: "/x509/x509VPrequest",
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
x509Router.get("/generateVPRequestDCQLGET", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      presentationDefinition: null,
      clientId: CONFIG.CLIENT_ID,
      privateKey: null,
      clientMetadata,
      kid: null,
      serverURL: CONFIG.SERVER_URL,
      dcqlQuery: DEFAULT_DCQL_QUERY,
      usePostMethod: false,
      routePath: "/x509/x509VPrequest",
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
x509Router.get("/generateVPRequestTransaction", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;

    const transactionDataObj = createTransactionData(presentationDefinition);
    const base64UrlEncodedTxData = Buffer.from(JSON.stringify(transactionDataObj))
      .toString("base64url");

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      presentationDefinition,
      clientId: CONFIG.CLIENT_ID,
      privateKey: null,
      clientMetadata,
      kid: null,
      serverURL: CONFIG.SERVER_URL,
      transactionData: base64UrlEncodedTxData,
      usePostMethod: true,
      routePath: "/x509/x509VPrequest",
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
x509Router
  .route("/x509VPrequest/:id")
  .post(express.urlencoded({ extended: true }), async (req, res) => {
    try {
      const sessionId = req.params.id;
      const { wallet_nonce: walletNonce, wallet_metadata: walletMetadata } = req.body;

      if (walletNonce || walletMetadata) {
        console.log(`Received from wallet: wallet_nonce=${walletNonce}, wallet_metadata=${walletMetadata}`);
      }

      const result = await processVPRequest({
        sessionId,
        clientMetadata,
        serverURL: CONFIG.SERVER_URL,
        clientId: CONFIG.CLIENT_ID,
        privateKey: null,
        kid: null,
        walletNonce,
        walletMetadata,
      });

      if (result.error) {
        return res.status(result.status).json({ error: result.error });
      }

      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      const errorResponse = createErrorResponse(error, "POST /x509VPrequest/:id");
      res.status(500).json(errorResponse);
    }
  })
  .get(async (req, res) => {
    try {
      const sessionId = req.params.id;
      const result = await processVPRequest({
        sessionId,
        clientMetadata,
        serverURL: CONFIG.SERVER_URL,
        clientId: CONFIG.CLIENT_ID,
        privateKey: null,
        kid: null,
      });

      if (result.error) {
        return res.status(result.status).json({ error: result.error });
      }

      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      const errorResponse = createErrorResponse(error, "GET /x509VPrequest/:id");
      res.status(500).json(errorResponse);
    }
  });

export default x509Router; 