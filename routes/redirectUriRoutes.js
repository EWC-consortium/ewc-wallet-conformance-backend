import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { generateNonce } from "../utils/cryptoUtils.js";
import { buildVPbyValue } from "../utils/tokenUtils.js";
import { getSDsFromPresentationDef } from "../utils/vpHeplers.js";
import { getVPSession, storeVPSession } from "../services/cacheServiceRedis.js";

const redirectUriRouter = express.Router();

// Configuration
const serverURL = process.env.SERVER_URL || "http://localhost:3000";
const proxyPath = process.env.PROXY_PATH || null;

// Load Verifier Configuration / Client Metadata
const clientMetadata = JSON.parse(
  fs.readFileSync("./data/verifier-config.json", "utf-8")
);

// Load presentation definitions
const presentation_definition_sdJwt = JSON.parse(
  fs.readFileSync("./data/presentation_definition_sdjwt.json", "utf-8")
);

/**
 * Standard VP Request endpoint using redirect_uri client_id_scheme
 */
redirectUriRouter.get("/generateVPRequest", async (req, res) => {
  const stateParam = req.query.sessionId ? req.query.sessionId : uuidv4();
  const nonce = generateNonce(16);
  const state = generateNonce(16);
  const responseMode = req.query.response_mode || "direct_post";

  const response_uri = serverURL + "/direct_post" + "/" + stateParam;
  const presentation_definition_uri = serverURL + "/presentation-definition/itbsdjwt";
  const clientId = serverURL + "/direct_post" + "/" + stateParam;

  // Find the field object that has path $.vct
  const vctField = presentation_definition_sdJwt.input_descriptors[0].constraints.fields.find(
    (field) => field.path && field.path.includes("$.vct")
  );
  const paths = getSDsFromPresentationDef(presentation_definition_sdJwt);

  storeVPSession(stateParam, {
    uuid: stateParam,
    status: "pending",
    claims: null,
    presentation_definition: presentation_definition_sdJwt,
    credentialRequested: vctField?.filter,
    nonce: nonce,
    sdsRequested: paths,
  });

  const vpRequest = buildVPbyValue(
    clientId,
    presentation_definition_uri,
    "redirect_uri",
    clientMetadata,
    response_uri,
    state,
    "vp_token",
    nonce,
    responseMode
  );

  let code = qr.image(vpRequest, {
    type: "png",
    ec_level: "H",
    size: 10,
    margin: 10,
  });
  let mediaType = "PNG";
  let encodedQR = imageDataURI.encode(await streamToBuffer(code), mediaType);
  res.json({
    qr: encodedQR,
    deepLink: vpRequest,
    sessionId: stateParam,
  });
});

/**
 * DCQL Query endpoint using redirect_uri client_id_scheme
 */
redirectUriRouter.get("/generateVPRequestDCQL", async (req, res) => {
  const stateParam = req.query.sessionId ? req.query.sessionId : uuidv4();
  const nonce = generateNonce(16);
  const state = generateNonce(16);

  const response_uri = serverURL + "/direct_post" + "/" + stateParam;
  const clientId = serverURL + "/direct_post" + "/" + stateParam;

  // Example DCQL query - this should be configurable based on requirements
  const dcql_query =   {
    "credentials": [
      {
        "id": "cmwallet",
        "format": "dc+sd-jwt",
        "meta": {
          "vct_values": [
            "urn:eu.europa.ec.eudi:pid:1"
          ]
        },
        "claims": [
          { "path": ["family_name"] },
          { "path": ["given_name"] },
          { "path": ["birth_date"] },
          { "path": ["age_over_18"] },
          { "path": ["issuance_date"] },
          { "path": ["expiry_date"] },
          { "path": ["issuing_authority"] },
          { "path": ["issuing_country"] }
        ]
      }
    ]
  }

  storeVPSession(stateParam, {
    uuid: stateParam,
    status: "pending",
    claims: null,
    dcql_query: dcql_query,
    nonce: nonce
  });

  const vpRequest = buildVPbyValue(
    clientId,
    null, // No presentation_definition_uri for DCQL
    "redirect_uri",
    clientMetadata,
    response_uri,
    state,
    "vp_token",
    nonce,
    "direct_post",
    dcql_query
  );

  let code = qr.image(vpRequest, {
    type: "png",
    ec_level: "H",
    size: 10,
    margin: 10,
  });
  let mediaType = "PNG";
  let encodedQR = imageDataURI.encode(await streamToBuffer(code), mediaType);
  res.json({
    qr: encodedQR,
    deepLink: vpRequest,
    sessionId: stateParam,
  });
});

/**
 * Transaction Data endpoint using redirect_uri client_id_scheme
 */
redirectUriRouter.get("/generateVPRequestTransaction", async (req, res) => {
  const stateParam = req.query.sessionId ? req.query.sessionId : uuidv4();
  const nonce = generateNonce(16);
  const state = generateNonce(16);

  const response_uri = serverURL + "/direct_post" + "/" + stateParam;
  const presentation_definition_uri = serverURL + "/presentation-definition/itbsdjwt";
  const clientId = serverURL + "/direct_post" + "/" + stateParam;

  // Find the presentation definition for the credential type
  const presentation_definition = presentation_definition_sdJwt;
  
  // Get credential IDs from the presentation definition
  const credentialIds = presentation_definition.input_descriptors.map(descriptor => descriptor.id);

  // Create transaction data as per OpenID4VP spec
  const transactionDataObj = {
    type: "identity_verification",
    credential_ids: credentialIds,
    transaction_data_hashes_alg: ["sha-256"],
    // Transaction-specific data
    purpose: "Verification of identity",
    timestamp: new Date().toISOString(),
    transaction_id: uuidv4()
  };

  // Base64url encode the transaction data
  const base64UrlEncodedTxData = Buffer.from(
    JSON.stringify(transactionDataObj)
  ).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  storeVPSession(stateParam, {
    uuid: stateParam,
    status: "pending",
    claims: null,
    presentation_definition: presentation_definition,
    nonce: nonce,
    transaction_data: [base64UrlEncodedTxData] // Store as array of encoded strings
  });

  const vpRequest = buildVPbyValue(
    clientId,
    presentation_definition_uri,
    "redirect_uri",
    clientMetadata,
    response_uri,
    state,
    "vp_token",
    nonce,
    "direct_post",
    null,
  );

  let code = qr.image(vpRequest, {
    type: "png",
    ec_level: "H",
    size: 10,
    margin: 10,
  });
  let mediaType = "PNG";
  let encodedQR = imageDataURI.encode(await streamToBuffer(code), mediaType);
  res.json({
    qr: encodedQR,
    deepLink: vpRequest,
    sessionId: stateParam,
  });
});

export default redirectUriRouter; 