import express from "express";
import { v4 as uuidv4 } from "uuid";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { generateNonce } from "../utils/cryptoUtils.js";
import { buildVpRequestJWT } from "../utils/cryptoUtils.js";
import { storeVPSession } from "../services/cacheServiceRedis.js";
import { getSDsFromPresentationDef } from "../utils/vpHeplers.js";

const x509Router = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

// Load presentation definitions
const presentation_definition_sdJwt = JSON.parse(
  fs.readFileSync("./data/presentation_definition_sdjwt.json", "utf-8")
);

// Load client metadata
const clientMetadata = JSON.parse(
  fs.readFileSync("./data/verifier-config.json", "utf-8")
);

// Standard VP Request with presentation_definition
x509Router.get("/generateVPRequest", async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const responseMode = req.query.response_mode || "direct_post";
  const nonce = generateNonce(16);

  const response_uri = `${serverURL}/direct_post/${uuid}`;
  const client_id = "dss.aegean.gr"; // This should match the DNS SAN in the certificate

  // Store session data
  storeVPSession(uuid, {
    uuid: uuid,
    status: "pending",
    claims: null,
    presentation_definition: presentation_definition_sdJwt,
    nonce: nonce,
    sdsRequested: getSDsFromPresentationDef(presentation_definition_sdJwt),
    response_mode: responseMode // Store response mode in session
  });

  // Build and sign the VP request JWT (which will be served at the request_uri)
  // Note: buildVpRequestJWT itself doesn't need request_uri_method. 
  // This parameter is for the initial openid4vp:// URI.
  const vpRequestJWT = await buildVpRequestJWT(
    client_id,
    response_uri,
    presentation_definition_sdJwt,
    null, // privateKey will be loaded in buildVpRequestJWT
    "x509_san_dns",
    clientMetadata,
    null,
    serverURL,
    "vp_token",
    nonce,
    null, // dcql_query
    null, // transaction_data
    responseMode
  );

  // Create the openid4vp:// URL
  // Since the /x509VPrequest/:id endpoint is a POST endpoint (as per its definition later in this file),
  // we add request_uri_method=post.
  const requestUri = `${serverURL}/x509VPrequest/${uuid}`;
  const vpRequest = `openid4vp://?request_uri=${encodeURIComponent(requestUri)}&request_uri_method=post`;

  // Generate QR code
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
x509Router.get("/generateVPRequestDCQL", async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const nonce = generateNonce(16);
  const responseMode = req.query.response_mode || "direct_post"; // Added for consistency if needed for JWT

  const response_uri = `${serverURL}/direct_post/${uuid}`;
  const client_id = "dss.aegean.gr";

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
    nonce: nonce,
    response_mode: responseMode // Store response mode
  });

  // JWT for request_uri
  const vpRequestJWT = await buildVpRequestJWT(
    client_id,
    response_uri,
    null, // No presentation_definition for DCQL
    null, // privateKey
    "x509_san_dns",
    clientMetadata,
    null, // kid
    serverURL,
    "vp_token",
    nonce,
    dcql_query, // dcql_query parameter
    null, // transaction_data parameter (null for DCQL query)
    responseMode
  );

  const requestUri = `${serverURL}/x509VPrequest/${uuid}`;
  const vpRequest = `openid4vp://?request_uri=${encodeURIComponent(requestUri)}&request_uri_method=post`;

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
x509Router.get("/generateVPRequestTransaction", async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const nonce = generateNonce(16);
  const responseMode = req.query.response_mode || "direct_post"; // Added for consistency

  const response_uri = `${serverURL}/direct_post/${uuid}`;
  const client_id = "dss.aegean.gr";

  // For transaction data, we still need a presentation definition
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
    response_mode: responseMode // Store response mode
  });

  // JWT for request_uri
  const vpRequestJWT = await buildVpRequestJWT(
    client_id,
    response_uri,
    presentation_definition, 
    null, 
    "x509_san_dns",
    clientMetadata,
    null, 
    serverURL,
    "vp_token",
    nonce,
    null, // No DCQL query when using transaction data with PD
    [base64UrlEncodedTxData],
    responseMode
  );

  const requestUri = `${serverURL}/x509VPrequest/${uuid}`;
  const vpRequest = `openid4vp://?request_uri=${encodeURIComponent(requestUri)}&request_uri_method=post`;

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
x509Router.post("/x509VPrequest/:id", async (req, res) => {
  const uuid = req.params.id;
  const vpSession = await getVPSession(uuid);
  
  if (!vpSession) {
    return res.status(400).json({ error: "Invalid session ID" });
  }

  const response_uri = `${serverURL}/direct_post/${uuid}`;
  const client_id = "dss.aegean.gr";

  const vpRequestJWT = await buildVpRequestJWT(
    client_id,
    response_uri,
    vpSession.presentation_definition,
    null, // privateKey
    "x509_san_dns",
    clientMetadata,
    null, // kid
    serverURL,
    "vp_token",
    vpSession.nonce,
    vpSession.dcql_query || null,
    vpSession.transaction_data || null
  );

  res.type("text/plain").send(vpRequestJWT);
});

export default x509Router; 