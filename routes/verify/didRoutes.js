import express from "express";
import { v4 as uuidv4 } from "uuid";
import {
  CONFIG,
  DEFAULT_DCQL_QUERY,
  DEFAULT_TRANSACTION_DATA,
  loadConfigurationFiles,
  generateDidIdentifiers,
  generateVPRequest,
  processVPRequest,
  createTransactionData,
  createErrorResponse,
} from "../../utils/routeUtils.js";
import {
  logInfo,
  logWarn,
  logError,
  logDebug,
  setSessionContext,
  clearSessionContext,
} from "../../services/cacheServiceRedis.js";

const didRouter = express.Router();

// Middleware to set session context for console interception
didRouter.use((req, res, next) => {
  const sessionId = req.query.sessionId || req.params.sessionId || req.params.id;
  if (sessionId) {
    setSessionContext(sessionId);
    // Clear context when response finishes
    res.on('finish', () => {
      clearSessionContext();
    });
  }
  next();
});

// Load configuration files
const { presentationDefinition, clientMetadata, privateKey } = loadConfigurationFiles(
  "./data/presentation_definition_pid.json",
  "./data/verifier-config.json",
  "./didjwks/did_private_pkcs8.key"
);

/**
 * Generate VP request with presentation definition
 */
didRouter.get("/generateVPRequest", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const { client_id, kid } = generateDidIdentifiers(CONFIG.SERVER_URL);
    
    await logInfo(sessionId, "Starting DID VP request generation", {
      endpoint: "/generateVPRequest",
      responseMode,
      clientId: client_id,
      kid
    });

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

    await logInfo(sessionId, "DID VP request generated successfully", {
      hasQR: !!result.qr,
      deepLinkLength: result.deepLink?.length
    });
    
    res.json(result);
  } catch (error) {
    await logError(sessionId, "Error generating DID VP request", {
      error: error.message,
      stack: error.stack
    });
    const errorResponse = createErrorResponse(error.message, "generateVPRequest", 500, sessionId);
    res.status(500).json(errorResponse);
  }
});

/**
 * Generate VP request for GET method
 */
didRouter.get("/generateVPRequestGET", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const { client_id, kid } = generateDidIdentifiers(CONFIG.SERVER_URL);
    
    await logInfo(sessionId, "Starting DID VP request generation (GET method)", {
      endpoint: "/generateVPRequestGET",
      responseMode,
      clientId: client_id,
      kid
    });

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
      routePath: "/did/VPrequest",
    });

    await logInfo(sessionId, "DID VP request generated successfully (GET method)", {
      hasQR: !!result.qr,
      deepLinkLength: result.deepLink?.length
    });
    
    res.json(result);
  } catch (error) {
    await logError(sessionId, "Error generating DID VP request (GET method)", {
      error: error.message,
      stack: error.stack
    });
    const errorResponse = createErrorResponse(error.message, "generateVPRequestGET", 500, sessionId);
    res.status(500).json(errorResponse);
  }
});

/**
 * Generate VP request with DCQL query
 */
didRouter.get("/generateVPRequestDCQL", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const { client_id, kid } = generateDidIdentifiers(CONFIG.SERVER_URL);
    
    await logInfo(sessionId, "Starting DID VP request generation with DCQL", {
      endpoint: "/generateVPRequestDCQL",
      responseMode,
      clientId: client_id,
      kid
    });

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
      routePath: "/did/VPrequest",
    });

    await logInfo(sessionId, "DID VP request with DCQL generated successfully", {
      hasQR: !!result.qr,
      deepLinkLength: result.deepLink?.length
    });
    
    res.json(result);
  } catch (error) {
    await logError(sessionId, "Error generating DID VP request with DCQL", {
      error: error.message,
      stack: error.stack
    });
    const errorResponse = createErrorResponse(error.message, "generateVPRequestDCQL", 500, sessionId);
    res.status(500).json(errorResponse);
  }
});

/**
 * Generate VP request with transaction data
 */
didRouter.get("/generateVPRequestTransaction", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const { client_id, kid } = generateDidIdentifiers(CONFIG.SERVER_URL);
    
    await logInfo(sessionId, "Starting DID VP request generation with transaction data", {
      endpoint: "/generateVPRequestTransaction",
      responseMode,
      clientId: client_id,
      kid
    });

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
      routePath: "/did/VPrequest",
    });

    await logInfo(sessionId, "DID VP request with transaction data generated successfully", {
      hasQR: !!result.qr,
      deepLinkLength: result.deepLink?.length
    });
    
    res.json(result);
  } catch (error) {
    await logError(sessionId, "Error generating DID VP request with transaction data", {
      error: error.message,
      stack: error.stack
    });
    const errorResponse = createErrorResponse(error.message, "generateVPRequestTransaction", 500, sessionId);
    res.status(500).json(errorResponse);
  }
});

/**
 * Request URI endpoint (handles both POST and GET)
 */
didRouter
  .route("/VPrequest/:id")
  .post(async (req, res) => {
    try {
      const sessionId = req.params.id;
      const { client_id, kid } = generateDidIdentifiers(CONFIG.SERVER_URL);
      const { wallet_nonce: walletNonce, wallet_metadata: walletMetadata } = req.body;

      await logInfo(sessionId, "Processing POST DID VP request", {
        endpoint: "POST /VPrequest/:id",
        clientId: client_id,
        kid,
        hasWalletNonce: !!walletNonce,
        hasWalletMetadata: !!walletMetadata
      });

      if (walletNonce || walletMetadata) {
        console.log(`Received from wallet: wallet_nonce=${walletNonce}, wallet_metadata=${walletMetadata}`);
        await logInfo(sessionId, "Received wallet data", {
          walletNonce,
          walletMetadata
        });
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
        await logError(sessionId, "DID VP request processing failed", {
          error: result.error,
          status: result.status
        });
        return res.status(result.status).json({ error: result.error });
      }

      await logInfo(sessionId, "DID VP request processed successfully (POST)", {
        jwtLength: result.jwt?.length
      });
      
      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      await logError(sessionId, "Error processing POST DID VP request", {
        error: error.message,
        stack: error.stack
      });
      const errorResponse = createErrorResponse(error.message, "POST /VPrequest/:id", 500, sessionId);
      res.status(500).json(errorResponse);
    }
  })
  .get(async (req, res) => {
    try {
      const sessionId = req.params.id;
      const { client_id, kid } = generateDidIdentifiers(CONFIG.SERVER_URL);
      
      await logInfo(sessionId, "Processing GET DID VP request", {
        endpoint: "GET /VPrequest/:id",
        clientId: client_id,
        kid
      });

      const result = await processVPRequest({
        sessionId,
        clientMetadata,
        serverURL: CONFIG.SERVER_URL,
        clientId: client_id,
        privateKey,
        kid,
      });

      if (result.error) {
        await logError(sessionId, "DID VP request processing failed (GET)", {
          error: result.error,
          status: result.status
        });
        return res.status(result.status).json({ error: result.error });
      }

      await logInfo(sessionId, "DID VP request processed successfully (GET)", {
        jwtLength: result.jwt?.length
      });
      
      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      await logError(sessionId, "Error processing GET DID VP request", {
        error: error.message,
        stack: error.stack
      });
      const errorResponse = createErrorResponse(error.message, "GET /VPrequest/:id", 500, sessionId);
      res.status(500).json(errorResponse);
    }
  });

export default didRouter; 