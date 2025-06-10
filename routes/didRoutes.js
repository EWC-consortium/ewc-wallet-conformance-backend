import express from "express";
import { v4 as uuidv4 } from "uuid";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { generateNonce, buildVpRequestJWT, didKeyToJwks } from "../utils/cryptoUtils.js";
import { getVPSession, storeVPSession } from "../services/cacheServiceRedis.js";
import { getSDsFromPresentationDef } from "../utils/vpHeplers.js";
import fs from "fs";

const didRouter = express.Router();
const serverURL = process.env.SERVER_URL || "http://localhost:3000";

// Load presentation definitions
const presentation_definition_sdJwt = JSON.parse(
  fs.readFileSync("./data/presentation_definition_pid.json", "utf-8")
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

  const requestUri = `${serverURL}/did/VPrequest/${uuid}`;
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

didRouter.get("/generateVPRequestGET", async (req, res) => {
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

  const requestUri = `${serverURL}/did/VPrequest/${uuid}`;
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
didRouter.get("/generateVPRequestDCQL", async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const nonce = generateNonce(16);
  const responseMode = req.query.response_mode || "direct_post";

  const response_uri = `${serverURL}/direct_post/${uuid}`;
  let controller = serverURL;
  if (process.env.PROXY_PATH) {
    controller = serverURL.replace("/" + process.env.PROXY_PATH, "") + ":" + process.env.PROXY_PATH;
  }
  controller = controller.replace("https://", "");
  const client_id = `did:web:${controller}`;
  const kid = `did:web:${controller}#keys-1`;

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

  const requestUri = `${serverURL}/did/VPrequest/${uuid}`;
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

// Transaction Data endpoint
didRouter.get("/generateVPRequestTransaction", async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const nonce = generateNonce(16);
  const responseMode = req.query.response_mode || "direct_post";

  const response_uri = `${serverURL}/direct_post/${uuid}`;
  let controller = serverURL;
  if (process.env.PROXY_PATH) {
    controller = serverURL.replace("/" + process.env.PROXY_PATH, "") + ":" + process.env.PROXY_PATH;
  }
  controller = controller.replace("https://", "");
  const client_id = `did:web:${controller}`;
  const kid = `did:web:${controller}#keys-1`;

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
    response_mode: responseMode,
    sdsRequested: getSDsFromPresentationDef(presentation_definition_sdJwt)
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

  const requestUri = `${serverURL}/did/VPrequest/${uuid}`;
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

// Request URI endpoint (now handles POST and GET)
didRouter.route("/VPrequest/:id")
  .post(async (req, res) => {
    const uuid = req.params.id;
    const vpSession = await getVPSession(uuid);
    // As per OpenID4VP spec, wallet can post wallet_nonce and wallet_metadata
    const { wallet_nonce, wallet_metadata } = req.body;
    if (wallet_nonce || wallet_metadata) {
      console.log(`Received from wallet: wallet_nonce=${wallet_nonce}, wallet_metadata=${wallet_metadata}`);
    }

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
      vpSession.transaction_data || null,
      wallet_nonce,
      wallet_metadata
    );

    // Respond with JWT as per OpenID4VP spec for request_uri
    res.type("application/oauth-authz-req+jwt").send(vpRequestJWT);
  })
  .get(async (req, res) => { // Added GET handler
    const uuid = req.params.id;
    const vpSession = await getVPSession(uuid);
    console.log("GET request for VP session ID: " + uuid);
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
      privateKey, // Assuming privateKey is accessible in this scope
      "did",
      clientMetadata, // Assuming clientMetadata is accessible
      kid,
      serverURL,
      "vp_token",
      vpSession.nonce,
      vpSession.dcql_query || null,
      vpSession.transaction_data || null
    );

    // Respond with JWT as per OpenID4VP spec for request_uri
    res.type("application/oauth-authz-req+jwt").send(vpRequestJWT);
  });

export default didRouter; 