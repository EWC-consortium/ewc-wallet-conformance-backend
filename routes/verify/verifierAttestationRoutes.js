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
import {
  logInfo,
  logWarn,
  logError,
  logDebug,
  setSessionContext,
  clearSessionContext,
} from "../../services/cacheServiceRedis.js";

const vAttestationRouter = express.Router();


// Middleware to set session context for console interception
vAttestationRouter.use((req, res, next) => {
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
const { presentationDefinition, clientMetadata } = loadConfigurationFiles(
  "./data/presentation_definition_pid.json",
  "./data/verifier-config.json"
);

/**
 * Generate VP request with presentation definition
 */
vAttestationRouter.get("/va/generateVPRequest", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    
    await logInfo(sessionId, "Starting VP request generation", { 
      endpoint: "/generateVPRequest", 
      responseMode 
    });

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      presentationDefinition,
      clientId: CONFIG.VERIFIER_ATTESTATION_CLIENT_ID,
      clientMetadata,
      kid: null,
      serverURL: CONFIG.SERVER_URL,
      usePostMethod: true,
      routePath: "/verifierAttestationVPrequest",
    });

    await logInfo(sessionId, "VP request generated successfully", { result });
    res.json(result);
  } catch (error) {
    await logError(sessionId, "Error generating VP request", { error: error.message, stack: error.stack });
    const errorResponse = createErrorResponse(error.message, "generateVPRequest", 500, sessionId);
    res.status(500).json(errorResponse);
  }
});

/**
 * Generate VP request for GET method
 */
vAttestationRouter.get("/va/generateVPRequestGet", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    
    await logInfo(sessionId, "Starting VP request generation (GET method)", { 
      endpoint: "/generateVPRequestGet", 
      responseMode 
    });

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      presentationDefinition,
      clientId: CONFIG.VERIFIER_ATTESTATION_CLIENT_ID,
      clientMetadata,
      kid: null,
      serverURL: CONFIG.SERVER_URL,
      usePostMethod: false,
      routePath: "/verifierAttestationVPrequest",
    });

    await logInfo(sessionId, "VP request generated successfully (GET method)", { result });
    res.json(result);
  } catch (error) {
    await logError(sessionId, "Error generating VP request (GET method)", { error: error.message, stack: error.stack });
    const errorResponse = createErrorResponse(error.message, "generateVPRequestGet", 500, sessionId);
    res.status(500).json(errorResponse);
  }
});

/**
 * Generate VP request with DCQL query
 */
vAttestationRouter.get("/va/generateVPRequestDCQL", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    
    await logInfo(sessionId, "Starting VP request generation with DCQL", { 
      endpoint: "/generateVPRequestDCQL", 
      responseMode 
    });

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      presentationDefinition: null,
      clientId: CONFIG.VERIFIER_ATTESTATION_CLIENT_ID,
      clientMetadata,
      kid: null,
      serverURL: CONFIG.SERVER_URL,
      dcqlQuery: DEFAULT_DCQL_QUERY,
      usePostMethod: true,
      routePath: "/verifierAttestationVPrequest",
    });

    await logInfo(sessionId, "VP request with DCQL generated successfully", { result });
    res.json(result);
  } catch (error) {
    await logError(sessionId, "Error generating VP request with DCQL", { error: error.message, stack: error.stack });
    const errorResponse = createErrorResponse(error.message, "generateVPRequestDCQL", 500, sessionId);
    res.status(500).json(errorResponse);
  }
});

/**
 * Generate VP request with DCQL query for GET method
 */
vAttestationRouter.get("/va/generateVPRequestDCQLGET", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    
    await logInfo(sessionId, "Starting VP request generation with DCQL (GET method)", { 
      endpoint: "/generateVPRequestDCQLGET", 
      responseMode 
    });

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      presentationDefinition: null,
      clientId: CONFIG.VERIFIER_ATTESTATION_CLIENT_ID,
      clientMetadata,
      kid: null,
      serverURL: CONFIG.SERVER_URL,
      dcqlQuery: DEFAULT_DCQL_QUERY,
      usePostMethod: false,
      routePath: "/verifierAttestationVPrequest",
    });

    await logInfo(sessionId, "VP request with DCQL generated successfully (GET method)", { result });
    res.json(result);
  } catch (error) {
    await logError(sessionId, "Error generating VP request with DCQL (GET method)", { error: error.message, stack: error.stack });
    const errorResponse = createErrorResponse(error.message, "generateVPRequestDCQLGET", 500, sessionId);
    res.status(500).json(errorResponse);
  }
});

/**
 * Generate VP request with transaction data
 */
vAttestationRouter.get("/va/generateVPRequestTransaction", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    
    await logInfo(sessionId, "Starting VP request generation with transaction data", { 
      endpoint: "/generateVPRequestTransaction", 
      responseMode 
    });

    const transactionDataObj = createTransactionData(presentationDefinition);
    const base64UrlEncodedTxData = Buffer.from(JSON.stringify(transactionDataObj))
      .toString("base64url");

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      presentationDefinition: null,
      clientId: CONFIG.VERIFIER_ATTESTATION_CLIENT_ID,
      clientMetadata,
      kid: null,
      serverURL: CONFIG.SERVER_URL,
      dcqlQuery: DEFAULT_DCQL_QUERY,
      transactionData: base64UrlEncodedTxData,
      usePostMethod: true,
      routePath: "/verifierAttestationVPrequest",
    });

    await logInfo(sessionId, "VP request with transaction data generated successfully", { result });
    res.json(result);
  } catch (error) {
    await logError(sessionId, "Error generating VP request with transaction data", { error: error.message, stack: error.stack });
    const errorResponse = createErrorResponse(error.message, "generateVPRequestTransaction", 500, sessionId);
    res.status(500).json(errorResponse);
  }
});

/**
 * Request URI endpoint (handles both POST and GET)
 */
vAttestationRouter
  .route("/verifierAttestationVPrequest/:id")
  .post(express.urlencoded({ extended: true }), async (req, res) => {
    const sessionId = req.params.id;
    try {
      const { wallet_nonce: walletNonce, wallet_metadata: walletMetadata } = req.body;

      await logInfo(sessionId, "Processing POST VP request", {
        endpoint: "POST /verifierAttestationVPrequest/:id",
        hasWalletNonce: !!walletNonce,
        hasWalletMetadata: !!walletMetadata
      });

      if (walletNonce || walletMetadata) {
        await logInfo(sessionId, "Received wallet data", { 
          walletNonce, 
          walletMetadata 
        });
      }

      const result = await processVPRequest({
        sessionId,
        clientMetadata,
        serverURL: CONFIG.SERVER_URL,
        clientId: CONFIG.VERIFIER_ATTESTATION_CLIENT_ID,
        kid: null,
        walletNonce,
        walletMetadata,
      });

      if (result.error) {
        await logError(sessionId, "VP request processing failed", { 
          error: result.error, 
          status: result.status 
        });
        // Mark session as failed
        try {
          const { getVPSession, storeVPSession } = await import("../../services/cacheServiceRedis.js");
          const vpSession = await getVPSession(sessionId);
          if (vpSession) {
            vpSession.status = "failed";
            vpSession.error = "processing_error";
            vpSession.error_description = result.error;
            await storeVPSession(sessionId, vpSession);
          }
        } catch (storageError) {
          await logError(sessionId, "Failed to update session status after x509 VP request processing failure", {
            error: storageError.message,
            stack: storageError.stack
          }).catch(() => {});
        }
        return res.status(result.status).json({ error: result.error });
      }

      await logInfo(sessionId, "VP request processed successfully (POST)", { 
        jwtLength: result.jwt?.length 
      });
      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      await logError(sessionId, "Error processing POST VP request", { 
        error: error.message, 
        stack: error.stack 
      });
      const errorResponse = createErrorResponse(error.message, "POST /x509VPrequest/:id", 500, sessionId);
      res.status(500).json(errorResponse);
    }
  })
  .get(async (req, res) => {
    try {
      const sessionId = req.params.id;

      await logInfo(sessionId, "Processing GET VP request", {
        endpoint: "GET /verifierAttestationVPrequest/:id"
      });
      const result = await processVPRequest({
        sessionId,
        clientMetadata,
        serverURL: CONFIG.SERVER_URL,
        clientId: CONFIG.VERIFIER_ATTESTATION_CLIENT_ID,
        kid: null,
      });

      if (result.error) {
        await logError(sessionId, "VP request processing failed", { 
          error: result.error, 
          status: result.status 
        });
        // Mark session as failed
        try {
          const { getVPSession, storeVPSession } = await import("../../services/cacheServiceRedis.js");
          const vpSession = await getVPSession(sessionId);
          if (vpSession) {
            vpSession.status = "failed";
            vpSession.error = "processing_error";
            vpSession.error_description = result.error;
            await storeVPSession(sessionId, vpSession);
          }
        } catch (storageError) {
          await logError(sessionId, "Failed to update session status after x509 VP request processing failure", {
            error: storageError.message,
            stack: storageError.stack
          }).catch(() => {});
        }
        return res.status(result.status).json({ error: result.error });
      }

      await logInfo(sessionId, "VP request processed successfully (GET)", { 
        jwtLength: result.jwt?.length 
      });
      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      await logError(sessionId, "Error processing GET VP request", { 
        error: error.message, 
        stack: error.stack 
      });
      const errorResponse = createErrorResponse(error.message, "GET /x509VPrequest/:id", 500, sessionId);
      res.status(500).json(errorResponse);
    }
  });

export default vAttestationRouter; 