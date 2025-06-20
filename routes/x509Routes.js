import express from "express";
import { v4 as uuidv4 } from "uuid";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { generateNonce } from "../utils/cryptoUtils.js";
import { buildVpRequestJWT } from "../utils/cryptoUtils.js";
import { storeVPSession, getVPSession } from "../services/cacheServiceRedis.js";
import { getSDsFromPresentationDef } from "../utils/vpHeplers.js";
import fs from "fs";

const x509Router = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

// Load presentation definitions
const presentation_definition_sdJwt = JSON.parse(
  fs.readFileSync("./data/presentation_definition_pid.json", "utf-8")
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
  const client_id = "x509_san_dns:dss.aegean.gr"; // This should match the DNS SAN in the certificate

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
  const requestUri = `${serverURL}/x509/x509VPrequest/${uuid}`;
  const vpRequest = `openid4vp://?request_uri=${encodeURIComponent(
    requestUri
  )}&request_uri_method=post&client_id=${encodeURIComponent(client_id)}`;

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

// New endpoint for GET request_uri
x509Router.get("/generateVPRequestGet", async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const responseMode = req.query.response_mode || "direct_post";
  const nonce = generateNonce(16);

  const response_uri = `${serverURL}/direct_post/${uuid}`;
  const client_id = "x509_san_dns:dss.aegean.gr";

  storeVPSession(uuid, {
    uuid: uuid,
    status: "pending",
    claims: null,
    presentation_definition: presentation_definition_sdJwt,
    nonce: nonce,
    sdsRequested: getSDsFromPresentationDef(presentation_definition_sdJwt),
    response_mode: responseMode
  });

  // Note: buildVpRequestJWT is called by the /x509/x509VPrequest/:id endpoint
  // So we don't need to call it here directly for the QR code generation step.

  const requestUri = `${serverURL}/x509/x509VPrequest/${uuid}`;  
  // openid4vp:// URL without request_uri_method, defaulting to GET for request_uri
  const vpRequest = `openid4vp://?request_uri=${encodeURIComponent(
    requestUri
  )}&client_id=${encodeURIComponent(client_id)}`;

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
  const client_id = "x509_san_dns:dss.aegean.gr";

  // Example DCQL query - this should be configurable
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
    response_mode: responseMode // Store response mode
  });

  // JWT for request_uri
  const vpRequestJWT = await buildVpRequestJWT(
    client_id,
    response_uri,
    null, // No presentation_definition for DCQL
    null, // privateKey
    clientMetadata,
    null, // kid
    serverURL,
    "vp_token",
    nonce,
    dcql_query, // dcql_query parameter
    null, // transaction_data parameter (null for DCQL query)
    responseMode
  );

  const requestUri = `${serverURL}/x509/x509VPrequest/${uuid}`;
  const vpRequest = `openid4vp://?request_uri=${encodeURIComponent(
    requestUri
  )}&request_uri_method=post&client_id=${encodeURIComponent(client_id)}`;

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


x509Router.get("/generateVPRequestDCQLGET", async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const nonce = generateNonce(16);
  const responseMode = req.query.response_mode || "direct_post"; // Added for consistency if needed for JWT

  const response_uri = `${serverURL}/direct_post/${uuid}`;
  const client_id = "x509_san_dns:dss.aegean.gr";

 
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
    response_mode: responseMode // Store response mode
  });

  

  const requestUri = `${serverURL}/x509/x509VPrequest/${uuid}`;
  const vpRequest = `openid4vp://?request_uri=${encodeURIComponent(
    requestUri
  )}&client_id=${encodeURIComponent(client_id)}`;

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
  const client_id = "x509_san_dns:dss.aegean.gr";

  // For transaction data, we still need a presentation definition
  const presentation_definition = presentation_definition_sdJwt; 

  const credentialIds = presentation_definition.input_descriptors.map(descriptor => descriptor.id);
  const transactionDataObj = {
    type: "qes_authorization",
    credential_ids: credentialIds,
    transaction_data_hashes_alg: ["sha-256"],
    // Transaction-specific data
    purpose: "Verification of identity",
    timestamp: new Date().toISOString(),
    transaction_id: uuidv4(),
    "documentDigests": [
      {
       "hash": "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
       "label": "Example Contract",
       "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1",
       "documentLocations": [
        {
         "uri": "https://protected.rp.example/contract-01.pdf?token=HS9naJKWwp901hBcK348IUHiuH8374",
         "method": {
         "type": "public"
         }
        },
       ],
       "dtbsr": "VYDl4oTeJ5TmIPCXKdTX1MSWRLI9CKYcyMRz6xlaGg"
      }
     ]
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
    response_mode: responseMode, // Store response mode
    sdsRequested: getSDsFromPresentationDef(presentation_definition_sdJwt)
  });

  // JWT for request_uri
  const vpRequestJWT = await buildVpRequestJWT(
    client_id,
    response_uri,
    presentation_definition, 
    null, 
    clientMetadata,
    null, 
    serverURL,
    "vp_token",
    nonce,
    null, // No DCQL query when using transaction data with PD
    [base64UrlEncodedTxData],
    responseMode
  );

  const requestUri = `${serverURL}/x509/x509VPrequest/${uuid}`;
  const vpRequest = `openid4vp://?request_uri=${encodeURIComponent(
    requestUri
  )}&request_uri_method=post&client_id=${encodeURIComponent(client_id)}`;

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





// Request URI endpoint (now handles POST and GET)
x509Router.route("/x509VPrequest/:id") // Corrected path to match client requests
  .post(express.urlencoded({ extended: true }), async (req, res) => {
    console.log("POST request received");
    const uuid = req.params.id;

    // As per OpenID4VP spec, wallet can post wallet_nonce and wallet_metadata
    const { wallet_nonce, wallet_metadata } = req.body;
    if (wallet_nonce || wallet_metadata) {
      console.log(`Received from wallet: wallet_nonce=${wallet_nonce}, wallet_metadata=${wallet_metadata}`);
    }

    const result = await generateX509VPRequest(uuid, clientMetadata, serverURL, wallet_nonce, wallet_metadata);

    if (result.error) {
      return res.status(result.status).json({ error: result.error });
    }
    // For POST, the content type might differ based on wallet expectations
    // or specific protocol steps not detailed here.
    // Assuming JWT is expected directly for now.
    res.type("application/oauth-authz-req+jwt").send(result.jwt);
  })
  .get(async (req, res) => { // Added GET handler
    console.log("GET request received");
    const uuid = req.params.id;
    const result = await generateX509VPRequest(uuid, clientMetadata, serverURL);
   

    if (result.error) {
      return res.status(result.status).json({ error: result.error });
    }
    // As per OpenID4VP, the request_uri should return the request object (JWT)
    // with content type application/oauth-authz-req+jwt
    res.type("application/oauth-authz-req+jwt").send(result.jwt);
  });



// Helper function to process VP Request
async function generateX509VPRequest(uuid, clientMetadata, serverURL, wallet_nonce, wallet_metadata) {
  const vpSession = await getVPSession(uuid);

  if (!vpSession) {
    return { error: "Invalid session ID", status: 400 };
  }

  const response_uri = `${serverURL}/direct_post/${uuid}`;
  const client_id = "x509_san_dns:dss.aegean.gr";

  // console.log("wallet_nonce", wallet_nonce);
  // console.log("wallet_metadata", wallet_metadata);
  
  const vpRequestJWT = await buildVpRequestJWT(
    client_id,
    response_uri,
    vpSession.presentation_definition,
    null, // privateKey
    clientMetadata,
    null, // kid
    serverURL,
    "vp_token",
    vpSession.nonce,
    vpSession.dcql_query || null,
    vpSession.transaction_data || null,
    vpSession.response_mode, // Pass response_mode from session
    undefined, // audience, to use default
    wallet_nonce,
    wallet_metadata
  );

  return { jwt: vpRequestJWT, status: 200 };
}


export default x509Router; 