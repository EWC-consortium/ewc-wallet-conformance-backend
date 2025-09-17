import express from "express";
import { v4 as uuidv4 } from "uuid";
import {
  CONFIG,
  DEFAULT_MDL_DCQL_QUERY,
  loadConfigurationFiles,
  generateVPRequest,
  processVPRequest,
  handleSessionCreation,
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

const mdlRouter = express.Router();

// Middleware to set session context for console interception
mdlRouter.use((req, res, next) => {
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
const { presentationDefinition: presentationDefinitionMdl, clientMetadata } = loadConfigurationFiles(
  "./data/presentation_definition_mdl.json",
  "./data/verifier-config.json"
);

const { clientMetadata: clientMetadataMDL } = loadConfigurationFiles(
  "./data/presentation_definition_mdl.json",
  "./data/verifier-config-mdl.json"
);

/**
 * Generate VP request with presentation definition
 */
mdlRouter.get("/generateVPRequest", async (req, res) => {
  try {
    const sessionId = req.query.sessionId || uuidv4();
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    
    await logInfo(sessionId, "Starting mDL VP request generation", {
      endpoint: "/generateVPRequest",
      responseMode,
      sessionId
    });

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      presentationDefinition: presentationDefinitionMdl,
      clientId: CONFIG.CLIENT_ID,
      privateKey: null,
      clientMetadata,
      kid: null,
      serverURL: CONFIG.SERVER_URL,
      usePostMethod: false, // GET method, no request_uri_method
      routePath: "/mdl/VPrequest",
    });

    await logInfo(sessionId, "mDL VP request generated successfully", {
      hasQR: !!result.qr,
      deepLinkLength: result.deepLink?.length
    });
    
    res.json(result);
  } catch (error) {
    await logError(sessionId, "Error generating mDL VP request", {
      error: error.message,
      stack: error.stack
    });
    const errorResponse = createErrorResponse(error.message, "generateVPRequest", 500, sessionId);
    res.status(500).json(errorResponse);
  }
});

/**
 * Request URI endpoint (handles both POST and GET)
 */
mdlRouter
  .route("/VPrequest/:id?")
  .post(express.urlencoded({ extended: true }), async (req, res) => {
    try {
      const sessionId = req.params.id;
      const { wallet_nonce: walletNonce, wallet_metadata: walletMetadata } = req.body;

      await logInfo(sessionId, "Processing POST mDL VP request", {
        endpoint: "POST /VPrequest/:id",
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
        clientId: CONFIG.CLIENT_ID,
        privateKey: null,
        kid: null,
        walletNonce,
        walletMetadata,
      });

      if (result.error) {
        await logError(sessionId, "mDL VP request processing failed", {
          error: result.error,
          status: result.status
        });
        return res.status(result.status).json({ error: result.error });
      }

      await logInfo(sessionId, "mDL VP request processed successfully (POST)", {
        jwtLength: result.jwt?.length
      });
      
      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      await logError(sessionId, "Error processing POST mDL VP request", {
        error: error.message,
        stack: error.stack
      });
      const errorResponse = createErrorResponse(error.message, "POST /VPrequest/:id", 500, sessionId);
      res.status(500).json(errorResponse);
    }
  })
  .get(async (req, res) => {
    try {
      let sessionId = req.params.id;
      
      await logInfo(sessionId, "Processing GET mDL VP request", {
        endpoint: "GET /VPrequest/:id",
        hasSessionId: !!sessionId
      });
      
      // Handle case where no session ID is provided
      if (!sessionId) {
        sessionId = req.query.sessionId || uuidv4();
        const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
        await logInfo(sessionId, "Creating new session for mDL request", {
          sessionId,
          responseMode
        });
        await handleSessionCreation(sessionId, presentationDefinitionMdl, responseMode);
      }

      // Check if session exists, create new one if not
      const { getVPSession } = await import("../../services/cacheServiceRedis.js");
      let storedSession = await getVPSession(sessionId);
      if (!storedSession) {
        console.log(`No session found for UUID: ${sessionId}`);
        await logInfo(sessionId, "No existing session found, creating new one", {
          sessionId
        });
        const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
        await handleSessionCreation(sessionId, presentationDefinitionMdl, responseMode);
        console.log(`New session created for UUID: ${sessionId}`);
        await logInfo(sessionId, "New mDL session created", {
          sessionId
        });
      }

      const result = await processVPRequest({
        sessionId,
        clientMetadata,
        serverURL: CONFIG.SERVER_URL,
        clientId: CONFIG.CLIENT_ID,
        privateKey: null,
        kid: null,
      });

      if (result.error) {
        await logError(sessionId, "mDL VP request processing failed (GET)", {
          error: result.error,
          status: result.status
        });
        return res.status(result.status).json({ error: result.error });
      }

      console.log("result.jwt", result.jwt);
      await logInfo(sessionId, "mDL VP request processed successfully (GET)", {
        jwtLength: result.jwt?.length
      });
      
      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      await logError(sessionId, "Error processing GET mDL VP request", {
        error: error.message,
        stack: error.stack
      });
      const errorResponse = createErrorResponse(error.message, "GET /VPrequest/:id", 500, sessionId);
      res.status(500).json(errorResponse);
    }
  });

/**
 * DC API endpoint for mDL requests
 */
mdlRouter.get("/VPrequest/dcapi/:id", async (req, res) => {
  try {
    const sessionId = req.params.id;
    const responseMode = "dc_api.jwt";
    
    await logInfo(sessionId, "Processing mDL DC API request", {
      endpoint: "/VPrequest/dcapi/:id",
      responseMode,
      sessionId
    });
    
    const { generateNonce, storeVPSessionData, getSDsFromPresentationDef } = await import("../../utils/routeUtils.js");
    const nonce = generateNonce(CONFIG.DEFAULT_NONCE_LENGTH);
    const state = generateNonce(CONFIG.DEFAULT_NONCE_LENGTH);
    
    await logDebug(sessionId, "Generated nonce and state for DC API", {
      nonce,
      state
    });

    // Store session data with DCQL query and state
    await storeVPSessionData(sessionId, {
      nonce,
      state,
      dcql_query: DEFAULT_MDL_DCQL_QUERY,
      sdsRequested: getSDsFromPresentationDef(presentationDefinitionMdl),
      response_mode: responseMode,
    });

    console.log(`New session created for UUID: ${sessionId}`);
    await logInfo(sessionId, "mDL DC API session created", {
      sessionId,
      hasNonce: !!nonce,
      hasState: !!state
    });

    const result = await processVPRequest({
      sessionId,
      clientMetadata: clientMetadataMDL,
      serverURL: CONFIG.SERVER_URL,
      clientId: CONFIG.CLIENT_ID,
      privateKey: null,
      kid: null,
      audience: "https://self-issued.me/v2", // DC API audience
    });

    if (result.error) {
      await logError(sessionId, "mDL DC API request processing failed", {
        error: result.error,
        status: result.status
      });
      return res.status(result.status).json({ error: result.error });
    }

    console.log("result.jwt", result.jwt);
    await logInfo(sessionId, "mDL DC API request processed successfully", {
      jwtLength: result.jwt?.length
    });
    
    res.json({
      request: result.jwt,
    });
  } catch (error) {
    await logError(sessionId, "Error processing mDL DC API request", {
      error: error.message,
      stack: error.stack
    });
    const errorResponse = createErrorResponse(error.message, "GET /VPrequest/dcapi/:id", 500, sessionId);
    res.status(500).json(errorResponse);
  }
});

export default mdlRouter;
