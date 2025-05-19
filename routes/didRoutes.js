import express from "express";
import { v4 as uuidv4 } from "uuid";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { generateNonce, buildVpRequestJWT, didKeyToJwks } from "../utils/cryptoUtils.js";
import { storeVPSession } from "../services/cacheServiceRedis.js";
import { getSDsFromPresentationDef } from "../utils/vpHeplers.js";
import fs from "fs";

const didRouter = express.Router();
const serverURL = process.env.SERVER_URL || "http://localhost:3000";

// Load presentation definitions
const presentation_definition_sdJwt = JSON.parse(
  fs.readFileSync("./data/presentation_definition_sdjwt.json", "utf-8")
);

// Load client metadata
const clientMetadata = JSON.parse(
  fs.readFileSync("./data/verifier-config.json", "utf-8")
);

// Load DID private key
const privateKey = fs.readFileSync("./didjwks/did_private_pkcs8.key", "utf8");

// Standard VP Request with presentation_definition
didRouter.get("/generateVPRequest", async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const responseMode = req.query.response_mode || "direct_post";
  const nonce = generateNonce(16);

  const response_uri = `${serverURL}/direct_post/${uuid}`;
  let controller = serverURL;
  if (process.env.PROXY_PATH) {
    controller = serverURL.replace("/" + process.env.PROXY_PATH, "") + ":" + process.env.PROXY_PATH;
  }
  controller = controller.replace("https://", "");
  const client_id = `did:web:${controller}`;
  const kid = `did:web:${controller}#keys-1`;

  storeVPSession(uuid, {
    uuid: uuid,
    status: "pending",
    claims: null,
    presentation_definition: presentation_definition_sdJwt,
    nonce: nonce,
    sdsRequested: getSDsFromPresentationDef(presentation_definition_sdJwt),
    response_mode: responseMode
  });

  const vpRequestJWT = await buildVpRequestJWT(
    client_id,
    response_uri,
    presentation_definition_sdJwt,
    privateKey,
    "did", // this references the key format not the DID method
    clientMetadata,
    kid,
    serverURL,
    "vp_token",
    nonce,
    null,
    null,
    responseMode
  );

  const vpRequest = `openid4vp://?request_uri=${encodeURIComponent(`${serverURL}/didVPrequest/${uuid}`)}`;

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
didRouter.get("/generateVPRequestDCQL", async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const nonce = generateNonce(16);

  const response_uri = `${serverURL}/direct_post/${uuid}`;
  let controller = serverURL;
  if (process.env.PROXY_PATH) {
    controller = serverURL.replace("/" + process.env.PROXY_PATH, "") + ":" + process.env.PROXY_PATH;
  }
  controller = controller.replace("https://", "");
  const client_id = `did:web:${controller}`;
  const kid = `did:web:${controller}#keys-1`;

  // Example DCQL query - this should be configurable
  const dcql_query = {
    type: "CredentialQuery",
    credentialTypes: ["VerifiableCredential"],
    claims: ["name", "birthDate", "nationality"]
  };

  storeVPSession(uuid, {
    uuid: uuid,
    status: "pending",
    claims: null,
    dcql_query: dcql_query,
    nonce: nonce
  });

  const vpRequestJWT = await buildVpRequestJWT(
    client_id,
    response_uri,
    null, // No presentation_definition for DCQL
    privateKey,
    "did:jwks",
    clientMetadata,
    kid,
    serverURL,
    "vp_token",
    nonce,
    dcql_query, // dcql_query parameter
    null // transaction_data parameter (null for DCQL query)
  );

  const vpRequest = `openid4vp://?request_uri=${encodeURIComponent(`${serverURL}/didVPrequest/${uuid}`)}`;

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
didRouter.get("/generateVPRequestTransaction", async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const nonce = generateNonce(16);

  const response_uri = `${serverURL}/direct_post/${uuid}`;
  let controller = serverURL;
  if (process.env.PROXY_PATH) {
    controller = serverURL.replace("/" + process.env.PROXY_PATH, "") + ":" + process.env.PROXY_PATH;
  }
  controller = controller.replace("https://", "");
  const client_id = `did:web:${controller}`;
  const kid = `did:web:${controller}#keys-1`;

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

  storeVPSession(uuid, {
    uuid: uuid,
    status: "pending",
    claims: null,
    presentation_definition: presentation_definition,
    nonce: nonce,
    transaction_data: [base64UrlEncodedTxData] // Store as array of encoded strings
  });

  const vpRequestJWT = await buildVpRequestJWT(
    client_id,
    response_uri,
    presentation_definition,
    privateKey,
    "did:jwks",
    clientMetadata,
    kid,
    serverURL,
    "vp_token",
    nonce,
    null, // dcql_query parameter (null for transaction data)
    [base64UrlEncodedTxData] // transaction_data parameter
  );

  const vpRequest = `openid4vp://?request_uri=${encodeURIComponent(`${serverURL}/didVPrequest/${uuid}`)}`;

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
didRouter.post("/didVPrequest/:id", async (req, res) => {
  const uuid = req.params.id;
  const vpSession = await getVPSession(uuid);
  
  if (!vpSession) {
    return res.status(400).json({ error: "Invalid session ID" });
  }

  const response_uri = `${serverURL}/direct_post/${uuid}`;
  let controller = serverURL;
  if (process.env.PROXY_PATH) {
    controller = serverURL.replace("/" + process.env.PROXY_PATH, "") + ":" + process.env.PROXY_PATH;
  }
  controller = controller.replace("https://", "");
  const client_id = `did:web:${controller}`;
  const kid = `did:web:${controller}#keys-1`;

  const vpRequestJWT = await buildVpRequestJWT(
    client_id,
    response_uri,
    vpSession.presentation_definition,
    privateKey,
    "did:jwks",
    clientMetadata,
    kid,
    serverURL,
    "vp_token",
    vpSession.nonce,
    vpSession.dcql_query || null,
    vpSession.transaction_data || null
  );

  res.type("text/plain").send(vpRequestJWT);
});

export default didRouter; 