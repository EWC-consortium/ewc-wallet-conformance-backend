import express from "express";
import { v4 as uuidv4 } from "uuid";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { generateNonce, buildVpRequestJWT, didKeyToJwks } from "../utils/cryptoUtils.js";
import { getVPSession, storeVPSession } from "../services/cacheServiceRedis.js";
import fs from "fs";
import * as jose from "jose";

const didRouter = express.Router();
const serverURL = process.env.SERVER_URL || "http://localhost:3000";

// DCQL query for PID
const dcql_query_pid = {
  "credentials": [
    {
      "id": "pid_credential",
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": [
          "urn:eu.europa.ec.eudi:pid:1"
        ]
      },
      "claims": [
        { "path": ["$.given_name"] },
        { "path": ["$.family_name"] },
        { "path": ["$.birth_date"] },
        { "path": ["$.age_over_18"] },
        { "path": ["$.issuance_date"] },
        { "path": ["$.expiry_date"] },
        { "path": ["$.issuing_authority"] },
        { "path": ["$.issuing_country"] }
      ]
    }
  ]
};

// Load client metadata
const clientMetadata = JSON.parse(
  fs.readFileSync("./data/verifier-config.json", "utf-8")
);

// Load DID private key
const privateKey = fs.readFileSync("./didjwks/did_private_pkcs8.key", "utf8");

// Standard VP Request with DCQL
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
  const client_id = `decentralized_identifier:did:web:${controller}`;
  const kid = `did:web:${controller}#keys-1`;

  // Create a sample verifier attestation
  const attestationPayload = {
      iss: client_id,
      sub: client_id,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      attestation: {
          "policy_uri": `${serverURL}/policy.html`,
          "tos_uri": `${serverURL}/tos.html`,
          "logo_uri": `${serverURL}/logo.png`
      }
  };
  const privateKeyObj = await jose.importPKCS8(privateKey, "ES256");
  const attestationJwt = await new jose.SignJWT(attestationPayload)
      .setProtectedHeader({ alg: 'ES256', kid: kid, typ: 'jwt' })
      .sign(privateKeyObj);
  const verifier_attestations = [attestationJwt];

  storeVPSession(uuid, {
    uuid: uuid,
    status: "pending",
    claims: null,
    dcql_query: dcql_query_pid,
    nonce: nonce,
    response_mode: responseMode,
    verifier_attestations: verifier_attestations
  });

  const vpRequestJWT = await buildVpRequestJWT(
    client_id,
    response_uri,
    privateKey,
    clientMetadata,
    kid,
    serverURL,
    "vp_token",
    nonce,
    dcql_query_pid,
    null,
    responseMode,
    undefined,
    null,
    null,
    verifier_attestations
  );

  const requestUri = `${serverURL}/did/VPrequest/${uuid}`;
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
  const client_id = `decentralized_identifier:did:web:${controller}`;
  const kid = `did:web:${controller}#keys-1`;

  // Create a sample verifier attestation
  const attestationPayload = {
    iss: client_id,
    sub: client_id,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    attestation: {
        "policy_uri": `${serverURL}/policy.html`,
        "tos_uri": `${serverURL}/tos.html`,
        "logo_uri": `${serverURL}/logo.png`
    }
  };
  const privateKeyObj = await jose.importPKCS8(privateKey, "ES256");
  const attestationJwt = await new jose.SignJWT(attestationPayload)
      .setProtectedHeader({ alg: 'ES256', kid: kid, typ: 'jwt' })
      .sign(privateKeyObj);
  const verifier_attestations = [attestationJwt];

  storeVPSession(uuid, {
    uuid: uuid,
    status: "pending",
    claims: null,
    dcql_query: dcql_query_pid,
    nonce: nonce,
    response_mode: responseMode,
    verifier_attestations: verifier_attestations
  });

  const vpRequestJWT = await buildVpRequestJWT(
    client_id,
    response_uri,
    privateKey,
    clientMetadata,
    kid,
    serverURL,
    "vp_token",
    nonce,
    dcql_query_pid,
    null,
    responseMode,
    undefined,
    null,
    null,
    verifier_attestations
  );

  const requestUri = `${serverURL}/did/VPrequest/${uuid}`;
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
  const client_id = `decentralized_identifier:did:web:${controller}`;
  const kid = `did:web:${controller}#keys-1`;

  // Create a sample verifier attestation
  const attestationPayload = {
    iss: client_id,
    sub: client_id,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    attestation: {
        "policy_uri": `${serverURL}/policy.html`,
        "tos_uri": `${serverURL}/tos.html`,
        "logo_uri": `${serverURL}/logo.png`
    }
  };
  const privateKeyObj = await jose.importPKCS8(privateKey, "ES256");
  const attestationJwt = await new jose.SignJWT(attestationPayload)
      .setProtectedHeader({ alg: 'ES256', kid: kid, typ: 'jwt' })
      .sign(privateKeyObj);
  const verifier_attestations = [attestationJwt];

  const credentialIds = dcql_query_pid.credentials.map(cred => cred.id);
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
    dcql_query: dcql_query_pid,
    nonce: nonce,
    transaction_data: [base64UrlEncodedTxData],
    response_mode: responseMode,
    verifier_attestations: verifier_attestations
  });

  const vpRequestJWT = await buildVpRequestJWT(
    client_id,
    response_uri,
    privateKey,
    clientMetadata,
    kid,
    serverURL,
    "vp_token",
    nonce,
    dcql_query_pid,
    [base64UrlEncodedTxData],
    responseMode,
    undefined,
    null,
    null,
    verifier_attestations
  );

  const requestUri = `${serverURL}/did/VPrequest/${uuid}`;
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
    const client_id = `decentralized_identifier:did:web:${controller}`;
    const kid = `did:web:${controller}#keys-1`;

    const vpRequestJWT = await buildVpRequestJWT(
      client_id,
      response_uri,
      privateKey,
      clientMetadata,
      kid,
      serverURL,
      "vp_token",
      vpSession.nonce,
      vpSession.dcql_query || null,
      vpSession.transaction_data || null,
      vpSession.response_mode,
      undefined, // audience
      wallet_nonce,
      wallet_metadata,
      vpSession.verifier_attestations || null
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
    const client_id = `decentralized_identifier:did:web:${controller}`;
    const kid = `did:web:${controller}#keys-1`;

    const vpRequestJWT = await buildVpRequestJWT(
      client_id,
      response_uri,
      privateKey,
      clientMetadata,
      kid,
      serverURL,
      "vp_token",
      vpSession.nonce,
      vpSession.dcql_query || null,
      vpSession.transaction_data || null,
      vpSession.response_mode,
      undefined,
      null,
      null,
      vpSession.verifier_attestations || null
    );

    // Respond with JWT as per OpenID4VP spec for request_uri
    res.type("application/oauth-authz-req+jwt").send(vpRequestJWT);
  });

export default didRouter; 