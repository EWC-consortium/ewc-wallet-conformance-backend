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
} from "../utils/routeUtils.js";

const mdlRouter = express.Router();

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

    res.json(result);
  } catch (error) {
    const errorResponse = createErrorResponse(error, "generateVPRequest");
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
      const errorResponse = createErrorResponse(error, "POST /VPrequest/:id");
      res.status(500).json(errorResponse);
    }
  })
  .get(async (req, res) => {
    try {
      let sessionId = req.params.id;
      
      // Handle case where no session ID is provided
      if (!sessionId) {
        sessionId = req.query.sessionId || uuidv4();
        const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
        await handleSessionCreation(sessionId, presentationDefinitionMdl, responseMode);
      }

      // Check if session exists, create new one if not
      const { getVPSession } = await import("../services/cacheServiceRedis.js");
      let storedSession = await getVPSession(sessionId);
      if (!storedSession) {
        console.log(`No session found for UUID: ${sessionId}`);
        const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
        await handleSessionCreation(sessionId, presentationDefinitionMdl, responseMode);
        console.log(`New session created for UUID: ${sessionId}`);
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
        return res.status(result.status).json({ error: result.error });
      }

      console.log("result.jwt", result.jwt);
      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      const errorResponse = createErrorResponse(error, "GET /VPrequest/:id");
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
    const { generateNonce, storeVPSessionData, getSDsFromPresentationDef } = await import("../utils/routeUtils.js");
    const nonce = generateNonce(CONFIG.DEFAULT_NONCE_LENGTH);
    const state = generateNonce(CONFIG.DEFAULT_NONCE_LENGTH);

    // Store session data with DCQL query and state
    await storeVPSessionData(sessionId, {
      nonce,
      state,
      dcql_query: DEFAULT_MDL_DCQL_QUERY,
      sdsRequested: getSDsFromPresentationDef(presentationDefinitionMdl),
      response_mode: responseMode,
    });

    console.log(`New session created for UUID: ${sessionId}`);

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
      return res.status(result.status).json({ error: result.error });
    }

    console.log("result.jwt", result.jwt);
    res.json({
      request: result.jwt,
    });
  } catch (error) {
    const errorResponse = createErrorResponse(error, "GET /VPrequest/dcapi/:id");
    res.status(500).json(errorResponse);
  }
});

export default mdlRouter;
