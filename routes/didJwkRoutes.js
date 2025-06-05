import express from "express";
import { v4 as uuidv4 } from "uuid";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { generateNonce, buildVpRequestJWT } from "../utils/cryptoUtils.js";
import { getVPSession, storeVPSession } from "../services/cacheServiceRedis.js";
import { getSDsFromPresentationDef } from "../utils/vpHeplers.js";
import fs from "fs";
import base64url from "base64url";
import { createPublicKey } from "crypto";

const didJwkRouter = express.Router();
const serverURL = process.env.SERVER_URL || "http://localhost:3000";

// Load presentation definitions
const presentation_definition_sdJwt = JSON.parse(
  fs.readFileSync("./data/presentation_definition_pid.json", "utf-8")
);

// Load client metadata
const clientMetadata = JSON.parse(
  fs.readFileSync("./data/verifier-config.json", "utf-8")
);

// Load private key and generate did:jwk identifier
const privateKey = fs.readFileSync("./didjwks/did_private_pkcs8.key", "utf8");
const publicKey = createPublicKey(privateKey);
const jwk = publicKey.export({ format: 'jwk' });

// Create did:jwk identifier by base64url encoding the public key
const didJwkIdentifier = `did:jwk:${base64url(JSON.stringify(jwk))}`;

// Standard VP Request with presentation_definition
didJwkRouter.get("/generateVPRequest", async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const responseMode = req.query.response_mode || "direct_post";
  const nonce = generateNonce(16);

  const response_uri = `${serverURL}/direct_post/${uuid}`;
  const client_id = didJwkIdentifier;
  const kid = `${didJwkIdentifier}#0`; // did:jwk uses #0 as default key ID

  storeVPSession(uuid, {
    uuid: uuid,
    status: "pending",
    claims: null,
    presentation_definition: presentation_definition_sdJwt,
    nonce: nonce,
    sdsRequested: getSDsFromPresentationDef(presentation_definition_sdJwt),
    response_mode: responseMode // Store response mode in session
  });

  const vpRequestJWT = await buildVpRequestJWT(
    client_id,
    response_uri,
    presentation_definition_sdJwt,
    privateKey,
    "did",
    clientMetadata,
    kid,
    serverURL,
    "vp_token",
    nonce,
    null, // dcql_query
    null, // transaction_data
    responseMode // Pass response_mode parameter
  );

  const requestUri = `${serverURL}/did-jwk/didJwkVPrequest/${uuid}`;
  const vpRequest = `openid4vp://?request_uri=${encodeURIComponent(requestUri)}&request_uri_method=post&client_id=${client_id}`;

  let code = qr.image(vpRequest, {
    type: "png",
    ec_level: "M",
    size: 20,
    margin: 10,
  });
  let mediaType = "PNG";
  let encodedQR = imageDataURI.encode(await streamToBuffer(code), mediaType);
  
  res.json({
    qr: encodedQR,
    deepLink: vpRequest,
    sessionId: uuid,
  });
});

// Standard VP Request with presentation_definition
didJwkRouter.get("/generateVPRequestGET", async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const responseMode = req.query.response_mode || "direct_post";
  const nonce = generateNonce(16);

  const response_uri = `${serverURL}/direct_post/${uuid}`;
  const client_id = didJwkIdentifier;
  const kid = `${didJwkIdentifier}#0`; // did:jwk uses #0 as default key ID

  storeVPSession(uuid, {
    uuid: uuid,
    status: "pending",
    claims: null,
    presentation_definition: presentation_definition_sdJwt,
    nonce: nonce,
    sdsRequested: getSDsFromPresentationDef(presentation_definition_sdJwt),
    response_mode: responseMode // Store response mode in session
  });

  
  const requestUri = `${serverURL}/did-jwk/didJwkVPrequest/${uuid}`;
  const vpRequest = `openid4vp://?request_uri=${encodeURIComponent(requestUri)}&client_id=${client_id}`;

  let code = qr.image(vpRequest, {
    type: "png",
    ec_level: "M",
    size: 20,
    margin: 10,
  });
  let mediaType = "PNG";
  let encodedQR = imageDataURI.encode(await streamToBuffer(code), mediaType);
  
  res.json({
    qr: encodedQR,
    deepLink: vpRequest,
    sessionId: uuid,
  });
});


// DCQL Query endpoint
didJwkRouter.get("/generateVPRequestDCQL", async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const nonce = generateNonce(16);
  const responseMode = req.query.response_mode || "direct_post";

  const response_uri = `${serverURL}/direct_post/${uuid}`;
  const client_id = didJwkIdentifier;
  const kid = `${didJwkIdentifier}#0`;

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
          {
            "path": [
              "family_name"
            ]
          }
        ]
      }
    ]
  }

  storeVPSession(uuid, {
    uuid: uuid,
    status: "pending",
    claims: null,
    dcql_query: dcql_query,
    nonce: nonce,
    response_mode: responseMode
  });

  const vpRequestJWT = await buildVpRequestJWT(
    client_id,
    response_uri,
    null,
    privateKey,
    "did",
    clientMetadata,
    kid,
    serverURL,
    "vp_token",
    nonce,
    dcql_query,
    null,
    responseMode
  );

  const requestUri = `${serverURL}/did-jwk/didJwkVPrequest/${uuid}`;
  const vpRequest = `openid4vp://?request_uri=${encodeURIComponent(requestUri)}&request_uri_method=post&client_id=${client_id}`;

  let code = qr.image(vpRequest, {
    type: "png",
    ec_level: "M",
    size: 20,
    margin: 10,
  });
  let mediaType = "PNG";
  let encodedQR = imageDataURI.encode(await streamToBuffer(code), mediaType);
  
  res.json({
    qr: encodedQR,
    deepLink: vpRequest,
    sessionId: uuid,
  });
});


// DCQL Query endpoint with GET method
didJwkRouter.get("/generateVPRequestDCQLGET", async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const nonce = generateNonce(16);
  const responseMode = req.query.response_mode || "direct_post";

  const response_uri = `${serverURL}/direct_post/${uuid}`;
  const client_id = didJwkIdentifier;
  const kid = `${didJwkIdentifier}#0`;

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
          {
            "path": [
              "family_name"
            ]
          }
        ]
      }
    ]
  }

  storeVPSession(uuid, {
    uuid: uuid,
    status: "pending",
    claims: null,
    dcql_query: dcql_query,
    nonce: nonce,
    response_mode: responseMode
  });

  const requestUri = `${serverURL}/did-jwk/didJwkVPrequest/${uuid}`;
  const vpRequest = `openid4vp://?request_uri=${encodeURIComponent(requestUri)}&client_id=${client_id}`;

  let code = qr.image(vpRequest, {
    type: "png",
    ec_level: "M",
    size: 20,
    margin: 10,
  });
  let mediaType = "PNG";
  let encodedQR = imageDataURI.encode(await streamToBuffer(code), mediaType);
  
  res.json({
    qr: encodedQR,
    deepLink: vpRequest,
    sessionId: uuid,
  });
});

// Transaction Data endpoint
didJwkRouter.get("/generateVPRequestTransaction", async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const nonce = generateNonce(16);
  const responseMode = req.query.response_mode || "direct_post";

  const response_uri = `${serverURL}/direct_post/${uuid}`;
  const client_id = didJwkIdentifier;
  const kid = `${didJwkIdentifier}#0`;

  const presentation_definition = presentation_definition_sdJwt;
  const credentialIds = presentation_definition.input_descriptors.map(descriptor => descriptor.id);
  const transactionDataObj = {
    type: "identity_verification",
    credential_ids: credentialIds,
    transaction_data_hashes_alg: ["sha-256"],
    // Transaction-specific data
    purpose: "Verification of identity",
    timestamp: new Date().toISOString(),
    transaction_id: uuidv4()
  };
  const base64UrlEncodedTxData = Buffer.from(JSON.stringify(transactionDataObj))
    .toString('base64url');

  storeVPSession(uuid, {
    uuid: uuid,
    status: "pending",
    claims: null,
    presentation_definition: presentation_definition,
    nonce: nonce,
    transaction_data: [base64UrlEncodedTxData],
    response_mode: responseMode
  });

  const vpRequestJWT = await buildVpRequestJWT(
    client_id,
    response_uri,
    presentation_definition,
    privateKey,
    "did",
    clientMetadata,
    kid,
    serverURL,
    "vp_token",
    nonce,
    null,
    [base64UrlEncodedTxData],
    responseMode
  );

  const requestUri = `${serverURL}/did-jwk/didJwkVPrequest/${uuid}`;
  const vpRequest = `openid4vp://?request_uri=${encodeURIComponent(requestUri)}&request_uri_method=post&client_id=${client_id}`;

  let code = qr.image(vpRequest, {
    type: "png",
    ec_level: "M",
    size: 20,
    margin: 10,
  });
  let mediaType = "PNG";
  let encodedQR = imageDataURI.encode(await streamToBuffer(code), mediaType);
  
  res.json({
    qr: encodedQR,
    deepLink: vpRequest,
    sessionId: uuid,
  });
});

// Request URI endpoint (POST method)
didJwkRouter.route("/didJwkVPrequest/:id")
  .post(async (req, res) => {
    const uuid = req.params.id;
    const vpSession = await getVPSession(uuid);
    
    if (!vpSession) {
      return res.status(400).json({ error: "Invalid session ID" });
    }

    const response_uri = `${serverURL}/direct_post/${uuid}`;
    const client_id = didJwkIdentifier;
    const kid = `${didJwkIdentifier}#0`;

    const vpRequestJWT = await buildVpRequestJWT(
      client_id,
      response_uri,
      vpSession.presentation_definition,
      privateKey,
      "did",
      clientMetadata,
      kid,
      serverURL,
      "vp_token",
      vpSession.nonce,
      vpSession.dcql_query || null,
      vpSession.transaction_data || null,
      vpSession.response_mode
    );

    res.type("text/plain").send(vpRequestJWT);
  })
  .get(async (req, res) => {
    const uuid = req.params.id;
    const vpSession = await getVPSession(uuid);
    
    if (!vpSession) {
      return res.status(400).json({ error: "Invalid session ID" });
    }

    const response_uri = `${serverURL}/direct_post/${uuid}`;
    const client_id = didJwkIdentifier;
    const kid = `${didJwkIdentifier}#0`;

    const vpRequestJWT = await buildVpRequestJWT(
      client_id,
      response_uri,
      vpSession.presentation_definition,
      privateKey,
      "did",
      clientMetadata,
      kid,
      serverURL,
      "vp_token",
      vpSession.nonce,
      vpSession.dcql_query || null,
      vpSession.transaction_data || null,
      vpSession.response_mode
    );

    res.type("text/plain").send(vpRequestJWT);
  });

export default didJwkRouter; 