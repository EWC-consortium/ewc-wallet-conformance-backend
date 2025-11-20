import express, { urlencoded } from "express";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { v4 as uuidv4 } from "uuid";
import {
  getPushedAuthorizationRequests,
  getSessionsAuthorizationDetail,
  getAuthCodeAuthorizationDetail,
} from "../../services/cacheService.js";
import { buildVPbyValue } from "../../utils/tokenUtils.js";

import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { generateNonce, buildVpRequestJWT } from "../../utils/cryptoUtils.js";
import {
  updateIssuerStateWithAuthCode,
  updateIssuerStateWithAuthCodeAfterVP,
} from "../codeFlowJwtRoutes.js";

import {
  getCodeFlowSession,
  storeCodeFlowSession,
  setSessionContext,
  clearSessionContext,
} from "../../services/cacheServiceRedis.js";

import {
  // Shared constants
  SERVER_URL,
  PROXY_PATH,
  DEFAULT_CREDENTIAL_TYPE,
  DEFAULT_SIGNATURE_TYPE,
  DEFAULT_CLIENT_ID_SCHEME,
  DEFAULT_REDIRECT_URI,
  QR_CONFIG,
  CLIENT_METADATA,
  ERROR_MESSAGES,
  
  // Cryptographic utilities
  loadPresentationDefinition,
  loadPrivateKey,
  
  // Parameter extraction utilities
  getSessionId,
  getCredentialType,
  getSignatureType,
  getClientIdScheme,
  
  // Session management utilities
  createCodeFlowSession,
  
  // QR code and URL generation utilities
  generateQRCode,
  createCodeFlowCredentialOfferResponse,
  createCredentialOfferConfig,
  
  // DID utilities
  buildDidController,
  
  // Error handling utilities
  handleRouteError,
  sendErrorResponse,
} from "../../utils/routeUtils.js";

const codeFlowRouterSDJWT = express.Router();

// Load private key
const PRIVATE_KEY = fs.readFileSync("./private-key.pem", "utf-8");

// Helper Functions
async function manageSession(uuid, sessionData) {
  const existingSession = await getCodeFlowSession(uuid);
  if (!existingSession) {
    await storeCodeFlowSession(uuid, sessionData);
  }
  return existingSession;
}

function createPARRequest(requestData) {
  const requestURI = "urn:aegean.gr:" + uuidv4();
  const parRequests = getPushedAuthorizationRequests();
  
  parRequests.set(requestURI, {
    client_id: requestData.client_id,
    scope: requestData.scope,
    response_type: requestData.response_type,
    redirect_uri: requestData.redirect_uri,
    code_challenge: requestData.code_challenge,
    code_challenge_method: requestData.code_challenge_method,
    claims: requestData.claims,
    state: requestData.state,
    authorizationHeader: requestData.authorizationHeader,
    responseType: requestData.response_type,
    issuerState: requestData.issuerState,
    authorizationDetails: requestData.authorizationDetails,
    clientMetadata: requestData.clientMetadata,
    wallet_issuer_id: requestData.wallet_issuer_id,
    user_hint: requestData.user_hint,
  });

  return {
    request_uri: requestURI,
    expires_in: 90,
  };
}

function parseAuthorizationDetails(authorizationDetails) {
  if (!authorizationDetails) return null;
  
  try {
    return JSON.parse(decodeURIComponent(authorizationDetails));
  } catch (error) {
    console.log("error parsing authorization details", authorizationDetails);
    throw new Error(ERROR_MESSAGES.PARSE_AUTHORIZATION_DETAILS_ERROR);
  }
}

function extractCredentialsFromAuthorizationDetails(authorizationDetails) {
  const credentials = [];
  let isPIDIssuanceFlow = false;

  if (authorizationDetails && authorizationDetails.length > 0) {
    authorizationDetails.forEach((item) => {
      const cred = fetchVCTorCredentialConfigId(item);
      credentials.push(cred);
      
      if (cred === "urn:eu.europa.ec.eudi:pid:1" || cred.indexOf("urn:eu.europa.ec.eudi:pid:1") >= 0) {
        isPIDIssuanceFlow = true;
      }
      
      console.log("requested credentials: " + cred);
    });
  }

  return { credentials, isPIDIssuanceFlow };
}

function extractCredentialsFromScope(scope) {
  const credentials = [];
  let isPIDIssuanceFlow = false;

  if (scope) {
    console.log("requested credentials: " + scope);
    credentials.push(scope);
    if (scope.indexOf("urn:eu.europa.ec.eudi:pid:1") >= 0) {
      isPIDIssuanceFlow = true;
    }
  }

  return { credentials, isPIDIssuanceFlow };
}

function validateAuthorizationRequest(response_type, code_challenge, authorizationDetails) {
  const errors = [];

  if (authorizationDetails) {
    if (!response_type) {
      errors.push(ERROR_MESSAGES.MISSING_RESPONSE_TYPE);
    }
    if (!code_challenge) {
      errors.push(ERROR_MESSAGES.MISSING_CODE_CHALLENGE);
    }
  }

  if (response_type !== "code") {
    errors.push(ERROR_MESSAGES.INVALID_RESPONSE_TYPE);
  }

  return errors;
}

function handlePARRequest(request_uri) {
  if (!request_uri) return null;

  const parRequest = getPushedAuthorizationRequests()?.get(request_uri);
  if (!parRequest) {
    console.log(ERROR_MESSAGES.PAR_REQUEST_NOT_FOUND + request_uri);
    return null;
  }

  return parRequest;
}

function updateSessionForAuthorization(existingCodeSession, requestData) {
  existingCodeSession.walletSession = requestData.state;
  existingCodeSession.authorizationDetails = requestData.authorizationDetails;
  existingCodeSession.scope = requestData.scope;
  existingCodeSession.requests = {
    redirectUri: requestData.redirectUri,
    challenge: requestData.code_challenge,
    method: requestData.code_challenge_method,
    sessionId: null,
    issuerState: requestData.issuerState,
    state: requestData.state,
  };
  existingCodeSession.results = {
    sessionId: null,
    issuerState: requestData.issuerState,
    state: requestData.state,
    status: "pending",
  };
  existingCodeSession.status = "pending";
  existingCodeSession.isPIDIssuanceFlow = requestData.isPIDIssuanceFlow;
  existingCodeSession.flowType = "code";

  return existingCodeSession;
}

function handleDynamicAuthorizationRedirect(existingCodeSession, requestData) {
  const { client_id_scheme, credentialsRequested, nonce, state, redirectUri } = requestData;

  if (client_id_scheme === "redirect_uri") {
    return handleRedirectUriScheme(existingCodeSession, requestData);
  } else if (client_id_scheme === "x509_san_dns") {
    return handleX509Scheme(existingCodeSession, requestData);
  } else if (client_id_scheme.indexOf("did") >= 0) {
    return handleDidScheme(existingCodeSession, requestData);
  } else if (client_id_scheme === "payment") {
    return handlePaymentScheme(existingCodeSession, requestData);
  }

  throw new Error(`Unsupported client_id_scheme: ${client_id_scheme}`);
}

function handleRedirectUriScheme(existingCodeSession, requestData) {
  const { credentialsRequested, nonce, issuerState } = requestData;
  
  console.log("client_id_scheme redirect_uri");
  const response_uri = `${SERVER_URL}/direct_post_vci/${issuerState}`;
  const presentation_definition_uri = `${SERVER_URL}/presentation-definition/itbsdjwt`;
  const client_metadata_uri = `${SERVER_URL}/client-metadata`;

  let redirectUrl = buildVPbyValue(
    response_uri,
    presentation_definition_uri,
    "redirect_uri",
    client_metadata_uri,
    response_uri,
    "vp_token",
    nonce
  );

  if (credentialsRequested.indexOf("urn:eu.europa.ec.eudi:pid:1") >= 0) {
    console.log("passing id_token!!");
    redirectUrl = buildVPbyValue(
      response_uri,
      null,
      "redirect_uri",
      client_metadata_uri,
      response_uri,
      existingCodeSession.state,
      "id_token",
      nonce
    );
  }

  return redirectUrl;
}

function handleX509Scheme(existingCodeSession, requestData) {
  const { credentialsRequested, redirectUri, issuerState } = requestData;
  
  console.log("client_id_scheme x509_san_dns");
  
  if (credentialsRequested.indexOf("urn:eu.europa.ec.eudi:pid:1") >= 0) {
    return handleX509PIDFlow(existingCodeSession, requestData);
  }

  const request_uri = `${SERVER_URL}/x509VPrequest_dynamic/${issuerState}`;
  const clientId = "dss.aegean.gr";
  const vpRequest = `openid4vp://?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(request_uri)}&request_uri_method=get`;

  return vpRequest;
}

async function handleX509PIDFlow(existingCodeSession, requestData) {
  const { authorizationDetails, redirectUri, issuerState } = requestData;
  
  const authorizationCode = generateNonce(16);
  getAuthCodeAuthorizationDetail().set(authorizationCode, authorizationDetails);
  
  existingCodeSession.results.sessionId = authorizationCode;
  existingCodeSession.requests.sessionId = authorizationCode;
  await storeCodeFlowSession(issuerState, existingCodeSession);

  return `${redirectUri}?code=${authorizationCode}&state=${existingCodeSession.requests.state}`;
}

function handleDidScheme(existingCodeSession, requestData) {
  const { credentialsRequested, issuerState } = requestData;
  
  console.log("client_id_scheme did");
  
  let request_uri = `${SERVER_URL}/didJwksVPrequest_dynamic/${issuerState}`;
  if (credentialsRequested.indexOf("urn:eu.europa.ec.eudi:pid:1") >= 0) {
    request_uri = `${SERVER_URL}/id_token_did_request_dynamic/${issuerState}`;
  }

  const controller = buildDidController();
  const clientId = `did:web:${controller}`;
  const vpRequest = `openid4vp://?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(request_uri)}&request_uri_method=get`;

  return vpRequest;
}

function handlePaymentScheme(existingCodeSession, requestData) {
  const { issuerState } = requestData;
  
  console.log("client_id_scheme payment");
  const request_uri = `${SERVER_URL}/payment-request/${issuerState}`;
  const clientId = "dss.aegean.gr";
  const vpRequest = `openid4vp://?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(request_uri)}&request_uri_method=get`;

  return vpRequest;
}

async function handleNonDynamicAuthorization(existingCodeSession, requestData) {
  const { state, authorizationDetails, issuerState } = requestData;
  
  const authorizationCode = generateNonce(16);
  const issuanceState = issuerState;
  
  existingCodeSession.results.sessionId = authorizationCode;
  existingCodeSession.requests.sessionId = authorizationCode;
  existingCodeSession.results.state = state;
  existingCodeSession.authorizationCode = authorizationCode;
  existingCodeSession.authorizationDetails = authorizationDetails;
  
  await storeCodeFlowSession(issuanceState, existingCodeSession);

  const encodedIssuer = encodeURIComponent(SERVER_URL);
  return `${existingCodeSession.requests.redirectUri}?code=${authorizationCode}&state=${state}&iss=${encodedIssuer}`;
}

async function buildVPRequestJWTForX509(uuid) {
  const response_uri = `${SERVER_URL}/direct_post_vci/${uuid}`;
  const presentation_definition_sdJwt = loadPresentationDefinition();
  const clientId = "dss.aegean.gr";
  
  return await buildVpRequestJWT(
    clientId,
    response_uri,
    presentation_definition_sdJwt,
    "",
    "x509_san_dns",
    CLIENT_METADATA,
    null,
    SERVER_URL
  );
}

async function buildVPRequestJWTForDid(uuid) {
  const response_uri = `${SERVER_URL}/direct_post_vci/${uuid}`;
  const privateKeyPem = loadPrivateKey();
  const controller = buildDidController();
  const clientId = `did:web:${controller}`;
  const presentation_definition_sdJwt = loadPresentationDefinition();

  return await buildVpRequestJWT(
    clientId,
    response_uri,
    presentation_definition_sdJwt,
    privateKeyPem,
    "did",
    CLIENT_METADATA,
    `did:web:${controller}#keys-1`,
    SERVER_URL
  );
}

async function buildIdTokenRequestJWTForX509(uuid, existingCodeSession) {
  const response_uri = `${SERVER_URL}/direct_post_vci/${existingCodeSession.requests.state}`;
  const clientId = "dss.aegean.gr";
  
  return await buildVpRequestJWT(
    clientId,
    response_uri,
    null,
    "",
    "x509_san_dns",
    CLIENT_METADATA,
    null,
    SERVER_URL,
    "id_token"
  );
}

async function buildIdTokenRequestJWTForDid(uuid, existingCodeSession) {
  const response_uri = `${SERVER_URL}/direct_post_vci/${existingCodeSession.requests.state}`;
  const privateKeyPem = loadPrivateKey();
  const controller = buildDidController();
  const clientId = `did:web:${controller}`;
  const presentation_definition_sdJwt = loadPresentationDefinition();

  return await buildVpRequestJWT(
    clientId,
    response_uri,
    null,
    privateKeyPem,
    "did",
    CLIENT_METADATA,
    `did:web:${controller}#keys-1`,
    SERVER_URL,
    "vp_token id_token"
  );
}

// ******************************************************************
// ************* CREDENTIAL OFFER ENDPOINTS *************************
// ******************************************************************
codeFlowRouterSDJWT.get(["/offer-code-sd-jwt"], async (req, res) => {
  try {
    const uuid = getSessionId(req);
    const signatureType = getSignatureType(req);
    const credentialType = getCredentialType(req);
    const client_id_scheme = getClientIdScheme(req);

    const sessionData = createCodeFlowSession(client_id_scheme, "code", false, false, signatureType);
    await manageSession(uuid, sessionData);

    const credentialOffer = createCodeFlowCredentialOfferResponse(uuid, credentialType, client_id_scheme, true);
    const encodedQR = await generateQRCode(credentialOffer);
    
    res.json({
      qr: encodedQR,
      deepLink: credentialOffer,
      sessionId: uuid,
    });
  } catch (error) {
    handleRouteError(error, "offer-code-sd-jwt", res);
  }
});

codeFlowRouterSDJWT.get(["/offer-code-sd-jwt-dynamic"], async (req, res) => {
  try {
    const uuid = getSessionId(req);
    const credentialType = getCredentialType(req);
    const client_id_scheme = getClientIdScheme(req);

    const sessionData = createCodeFlowSession(client_id_scheme, "code", true);
    await manageSession(uuid, sessionData);

    const credentialOffer = createCodeFlowCredentialOfferResponse(uuid, credentialType, client_id_scheme, false);
    const encodedQR = await generateQRCode(credentialOffer);
    
    res.json({
      qr: encodedQR,
      deepLink: credentialOffer,
      sessionId: uuid,
    });
  } catch (error) {
    handleRouteError(error, "offer-code-sd-jwt-dynamic", res);
  }
});

codeFlowRouterSDJWT.get(["/offer-code-defered"], async (req, res) => {
  try {
    const uuid = getSessionId(req);
    const credentialType = getCredentialType(req);
    const client_id_scheme = getClientIdScheme(req);

    const sessionData = createCodeFlowSession(client_id_scheme, "code", false, true);
    await manageSession(uuid, sessionData);

    const credentialOffer = createCodeFlowCredentialOfferResponse(uuid, credentialType, client_id_scheme, false);
    const encodedQR = await generateQRCode(credentialOffer);
    
    res.json({
      qr: encodedQR,
      deepLink: credentialOffer,
      sessionId: uuid,
    });
  } catch (error) {
    handleRouteError(error, "offer-code-defered", res);
  }
});

// auth code-flow request
// with dynamic cred request and client_id_scheme == redirect_uri
codeFlowRouterSDJWT.get(["/credential-offer-code-sd-jwt/:id"], (req, res) => {
  try {
    const credentialType = getCredentialType(req);
    const config = createCredentialOfferConfig(credentialType, req.params.id, false, "authorization_code");
    res.json(config);
  } catch (error) {
    handleRouteError(error, "credential-offer-code-sd-jwt", res);
  }
});

/***************************************************************
 *               Push Authorization Request Endpoints
 * https://datatracker.ietf.org/doc/html/rfc9126
 ***************************************************************/
codeFlowRouterSDJWT.post(["/par", "/authorize/par"], async (req, res) => {
  try {
    const requestData = {
      client_id: req.body.client_id,
      scope: req.body.scope,
      response_type: req.body.response_type,
      redirect_uri: req.body.redirect_uri,
      code_challenge: req.body.code_challenge,
      code_challenge_method: req.body.code_challenge_method,
      claims: req.body.claims,
      state: req.body.state,
      authorizationHeader: req.get("Authorization"),
      responseType: req.body.response_type,
      issuerState: decodeURIComponent(req.body.issuer_state),
      authorizationDetails: req.body.authorization_details,
      clientMetadata: req.body.client_metadata,
      wallet_issuer_id: req.body.wallet_issuer_id,
      user_hint: req.body.user_hint,
    };

    const result = createPARRequest(requestData);

    console.log("par state " + requestData.state);
    console.log("issuer state " + requestData.issuerState);

    // res.status(201).json(result);
    res.statusCode = 201;
    return res.json(result);
  } catch (error) {
    handleRouteError(error, "PAR endpoint", res);
  }
});

/*********************************************************************************
 *               Authorization request
 *
 * Two ways to request authorization
 * One way is to use the authorization_details request parameter with one or more authorization details objects of type openid_credential
 * Second way is through the use of scope
 ****************************************************************/
codeFlowRouterSDJWT.get("/authorize", async (req, res) => {
  try {
    // Extract and process request parameters
    let requestData = {
      response_type: req.query.response_type,
      issuerState: decodeURIComponent(req.query.issuer_state),
      state: req.query.state,
      client_id: decodeURIComponent(req.query.client_id),
      authorizationDetails: req.query.authorization_details,
      scope: req.query.scope,
      redirect_uri: req.query.redirect_uri,
      code_challenge: decodeURIComponent(req.query.code_challenge),
      code_challenge_method: req.query.code_challenge_method,
      client_metadata: req.query.client_metadata,
      nonce: req.query.nonce,
      wallet_issuer_id: req.query.wallet_issuer_id,
      user_hint: req.query.user_hint,
      request_uri: req.query.request_uri,
    };

    // Set session context for console interception to capture all logs
    // issuerState is the sessionId for code flow
    if (requestData.issuerState) {
      setSessionContext(requestData.issuerState);
      // Clear context when response finishes
      res.on('finish', () => {
        clearSessionContext();
      });
      res.on('close', () => {
        clearSessionContext();
      });
    }

    // Handle PAR request if present
    const parRequest = handlePARRequest(requestData.request_uri);
    if (parRequest) {
      requestData = { ...requestData, ...parRequest };
    }

    console.log("wallet_issuer_id: " + requestData.wallet_issuer_id);
    console.log("user_hint: " + requestData.user_hint);

    const redirectUri = requestData.redirect_uri ? decodeURIComponent(requestData.redirect_uri) : DEFAULT_REDIRECT_URI;

    // Parse client metadata
    try {
      if (requestData.client_metadata) {
        JSON.parse(decodeURIComponent(requestData.client_metadata));
      } else {
        console.log("client_metadata was missing");
      }
    } catch (error) {
      console.log("client_metadata was missing");
      console.log(error);
    }

    // Extract credentials and determine flow type
    let credentialsRequested = [];
    let isPIDIssuanceFlow = false;

    if (requestData.authorizationDetails) {
      const parsedAuthDetails = parseAuthorizationDetails(requestData.authorizationDetails);
      const result = extractCredentialsFromAuthorizationDetails(parsedAuthDetails);
      credentialsRequested = result.credentials;
      isPIDIssuanceFlow = result.isPIDIssuanceFlow;
    } else {
      console.log("authorization_details not found trying scope");
      const result = extractCredentialsFromScope(requestData.scope);
      credentialsRequested = result.credentials;
      isPIDIssuanceFlow = result.isPIDIssuanceFlow;
      
      if (credentialsRequested.length === 0) {
        throw new Error(ERROR_MESSAGES.NO_CREDENTIALS_REQUESTED);
      }
    }

    // Get and update session
    let existingCodeSession = await getCodeFlowSession(requestData.issuerState);
    if (!existingCodeSession) {
      // Note: Can't mark session as failed since session doesn't exist
      throw new Error(ERROR_MESSAGES.ITB_SESSION_EXPIRED);
    }

    const updatedRequestData = {
      ...requestData,
      redirectUri,
      credentialsRequested,
      isPIDIssuanceFlow,
    };

    existingCodeSession = updateSessionForAuthorization(existingCodeSession, updatedRequestData);
    await storeCodeFlowSession(requestData.issuerState, existingCodeSession);

    // Validate request
    const errors = validateAuthorizationRequest(
      requestData.response_type,
      requestData.code_challenge,
      requestData.authorizationDetails
    );

    if (errors.length > 0) {
      console.error("Validation errors:", errors);
      const error_description = errors.join(" ");
      const encodedErrorDescription = encodeURIComponent(error_description.trim());
      const errorRedirectUrl = `${redirectUri}?error=invalid_request&error_description=${encodedErrorDescription}`;
      
      existingCodeSession.status = "failed";
      if (existingCodeSession.results) {
        existingCodeSession.results.status = "failed";
      } else {
        existingCodeSession.results = { status: "failed" };
      }
      await storeCodeFlowSession(requestData.issuerState, existingCodeSession);

      return res.redirect(302, errorRedirectUrl);
    }

    // Handle authorization based on flow type
    if (existingCodeSession.isDynamic) {
      const redirectUrl = handleDynamicAuthorizationRedirect(existingCodeSession, updatedRequestData);
      return res.redirect(302, redirectUrl);
    } else {
      const redirectUrl = await handleNonDynamicAuthorization(existingCodeSession, updatedRequestData);
      return res.redirect(302, redirectUrl);
    }
  } catch (error) {
    console.error("Error in authorize endpoint:", error);
    
    // Try to mark session as failed if we have issuerState
    try {
      const issuerState = req.query?.issuer_state ? decodeURIComponent(req.query.issuer_state) : null;
      if (issuerState) {
        const existingCodeSession = await getCodeFlowSession(issuerState);
        if (existingCodeSession) {
          existingCodeSession.status = "failed";
          if (existingCodeSession.results) {
            existingCodeSession.results.status = "failed";
          } else {
            existingCodeSession.results = { status: "failed" };
          }
          existingCodeSession.error = "invalid_request";
          existingCodeSession.error_description = error.message;
          await storeCodeFlowSession(issuerState, existingCodeSession);
        }
      }
    } catch (sessionError) {
      console.error("Failed to update session status after authorize error:", sessionError);
    }
    
    const errorRedirectUrl = `${DEFAULT_REDIRECT_URI}?error=invalid_request&error_description=${encodeURIComponent(error.message)}`;
    return res.redirect(302, errorRedirectUrl);
  }
});

// **************************************************
// ************ DYNAMIC VP REQUESTS ************
// **************************************************
// Dynamic VP request by reference endpoint
codeFlowRouterSDJWT.get("/x509VPrequest_dynamic/:id", async (req, res) => {
  try {
    const uuid = req.params.id || uuidv4();
    const signedVPJWT = await buildVPRequestJWTForX509(uuid);
    console.log(signedVPJWT);
    res.type("text/plain").send(signedVPJWT);
  } catch (error) {
    handleRouteError(error, "x509VPrequest_dynamic", res);
  }
});

codeFlowRouterSDJWT.get("/didJwksVPrequest_dynamic/:id", async (req, res) => {
  try {
    const uuid = req.params.id || uuidv4();
    const signedVPJWT = await buildVPRequestJWTForDid(uuid);
    res.type("text/plain").send(signedVPJWT);
  } catch (error) {
    handleRouteError(error, "didJwksVPrequest_dynamic", res);
  }
});

// Dynamic VP request with only id_token
codeFlowRouterSDJWT.get("/id_token_x509_request_dynamic/:id", async (req, res) => {
  try {
    const uuid = req.params.id || uuidv4();
    const existingCodeSession = await getCodeFlowSession(uuid);
    const signedVPJWT = await buildIdTokenRequestJWTForX509(uuid, existingCodeSession);
    console.log(signedVPJWT);
    res.type("text/plain").send(signedVPJWT);
  } catch (error) {
    handleRouteError(error, "id_token_x509_request_dynamic", res);
  }
});

codeFlowRouterSDJWT.get("/id_token_did_request_dynamic/:id", async (req, res) => {
  try {
    const uuid = req.params.id || uuidv4();
    const existingCodeSession = await getCodeFlowSession(uuid);
    const signedVPJWT = await buildIdTokenRequestJWTForDid(uuid, existingCodeSession);
    res.type("text/plain").send(signedVPJWT);
  } catch (error) {
    handleRouteError(error, "id_token_did_request_dynamic", res);
  }
});

/*
  presentation by the wallet during an Issuance part of the Dynamic Credential Request 
*/
codeFlowRouterSDJWT.post("/direct_post_vci/:id", async (req, res) => {
  try {
    console.log("direct_post VP for VCI is below!");
    const state = req.body.state;
    const jwt = req.body.vp_token;
    const issuerState = req.params.id;
    console.log("direct_post_vci state" + issuerState);

    if (!jwt) {
      console.log(ERROR_MESSAGES.NO_JWT_PRESENTED);
      
      // Try to mark session as failed if we have issuerState
      try {
        const existingCodeSession = await getCodeFlowSession(issuerState);
        if (existingCodeSession) {
          existingCodeSession.status = "failed";
          if (existingCodeSession.results) {
            existingCodeSession.results.status = "failed";
          } else {
            existingCodeSession.results = { status: "failed" };
          }
          existingCodeSession.error = "invalid_request";
          existingCodeSession.error_description = ERROR_MESSAGES.NO_JWT_PRESENTED;
          await storeCodeFlowSession(issuerState, existingCodeSession);
        }
      } catch (sessionError) {
        console.error("Failed to update session status after JWT missing error:", sessionError);
      }
      
      return res.sendStatus(500);
    }

    const authorizationDetails = getSessionsAuthorizationDetail().get(state);
    const authorizationCode = generateNonce(16);
    getAuthCodeAuthorizationDetail().set(authorizationCode, authorizationDetails);

    console.log("wallet state " + state);

    const existingCodeSession = await getCodeFlowSession(issuerState);
    if (!existingCodeSession) {
      console.log(ERROR_MESSAGES.ISSUANCE_SESSION_NOT_FOUND + " " + issuerState);
      // Note: Can't mark session as failed since session doesn't exist
      return res.sendStatus(500);
    }

    const issuanceState = existingCodeSession.results.state;
    existingCodeSession.results.sessionId = authorizationCode;
    existingCodeSession.requests.sessionId = authorizationCode;
    await storeCodeFlowSession(issuanceState, existingCodeSession);

    const redirectUrl = `${existingCodeSession.requests.redirectUri}?code=${authorizationCode}&state=${existingCodeSession.requests.state}`;
    return res.send({ redirect_uri: redirectUrl });
  } catch (error) {
    // Try to mark session as failed if we have issuerState
    try {
      const issuerState = req.params?.id;
      if (issuerState) {
        const existingCodeSession = await getCodeFlowSession(issuerState);
        if (existingCodeSession) {
          existingCodeSession.status = "failed";
          if (existingCodeSession.results) {
            existingCodeSession.results.status = "failed";
          } else {
            existingCodeSession.results = { status: "failed" };
          }
          existingCodeSession.error = "server_error";
          existingCodeSession.error_description = error.message;
          await storeCodeFlowSession(issuerState, existingCodeSession);
        }
      }
    } catch (sessionError) {
      console.error("Failed to update session status after direct_post_vci error:", sessionError);
    }
    
    handleRouteError(error, "direct_post_vci", res);
  }
});

// Function to fetch either vct or credential_configuration_id
function fetchVCTorCredentialConfigId(data) {
  // 1. Handle the structure from the user's first modification (most specific)
  if (
    data.credential_definition &&
    data.credential_definition.type &&
    Array.isArray(data.credential_definition.type) &&
    data.credential_definition.type.length > 0
  ) {
    return data.credential_definition.type[0];
  }

  // 2. Handle 'credential_configuration_id'
  // (Covers A, C, D part 1, E part 1 from examples)
  if (data.credential_configuration_id) {
    return data.credential_configuration_id;
  }

  // 3. Handle 'format' and its associated fields
  if (data.format) {
    // For 'vc+sd-jwt' format, use 'vct' (Covers B from examples)
    if (data.format === "vc+sd-jwt" && data.vct) {
      return data.vct;
    }
    // For 'mso_mdoc' format, use 'doctype' (Covers D part 2 from examples)
    if (data.format === "mso_mdoc" && data.doctype) {
      return data.doctype;
    }
  }

  // 4. Fallback for the original `data.vct` if it wasn't caught by format-specific logic
  // This respects the original function's high priority for `vct`.
  if (data.vct) {
    return data.vct;
  }

  // 5. Fallback to 'types' (from original function structure)
  if (data.types) {
    return data.types;
  }

  return null; // If none of the above, return null
}

export default codeFlowRouterSDJWT;
