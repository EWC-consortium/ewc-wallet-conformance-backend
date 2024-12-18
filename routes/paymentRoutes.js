import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import { decodeSdJwt, getClaims } from "@sd-jwt/decode";
import {extractClaimsFromRequest} from "../utils/vpHeplers.js"
import { digest } from "@sd-jwt/crypto-nodejs";
import crypto from "crypto";
import { extractClaims } from "../utils/sdjwtUtils.js";

import {
  storePreAuthSession,
  getPreAuthSession,
  getCodeFlowSession,
  storeCodeFlowSession,
  storeVerificationSession,
  getVerificationSession,
} from "../services/cacheServiceRedis.js";

import {
  buildVpRequestJWT,
  buildPaymentVpRequestJWT,
} from "../utils/cryptoUtils.js";

import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";

const paymentRouter = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

const presentation_definition_sdJwt = JSON.parse(
  //fs.readFileSync("./data/presentation_definition_pid+pwa.json", "utf-8")
  // fs.readFileSync("./data/presentation_definition_pid|photoID+PWA.json", "utf-8")
  // fs.readFileSync("./data/presentation_definition_sdjwt.json", "utf-8")
  fs.readFileSync("./data/presentation_definition_pwa.json", "utf-8")
);

// *******************
// PRE-Auth Request
// *******************
paymentRouter.get(["/issue-pwa-pre-auth"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();

  let existingPreAuthSession = await getPreAuthSession(uuid);
  if (!existingPreAuthSession) {
    storePreAuthSession(uuid, {
      status: "pending",
      resulut: null,
      persona: null,
      accessToken: null,
      isPID: false,
    });
  }
  let credentialOffer = `openid-credential-offer://?credential_offer_uri=${serverURL}/pwa-pre-auth-offer/${uuid}`;
  let code = qr.image(credentialOffer, {
    type: "png",
    ec_level: "H",
    size: 10,
    margin: 10,
  });
  let mediaType = "PNG";
  let encodedQR = imageDataURI.encode(await streamToBuffer(code), mediaType);
  res.json({
    qr: encodedQR,
    deepLink: credentialOffer,
    sessionId: uuid,
  });
});

paymentRouter.get(["/pwa-pre-auth-offer/:id"], async (req, res) => {
  const credentialType = "PaymentWalletAttestation";
  console.log(credentialType);
  // assign a pre-auth code to session to verify afterwards
  let existingPreAuthSession = await getPreAuthSession(req.params.id);
  if (existingPreAuthSession) {
    existingPreAuthSession["preAuthCode"] = "1234"; //TODO generate a random code here
    storePreAuthSession(req.params.id, existingPreAuthSession);
  }

  res.json({
    credential_issuer: serverURL,
    credential_configuration_ids: [credentialType],
    grants: {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": req.params.id,
        tx_code: {
          length: 4,
          input_mode: "numeric",
          description:
            "Please provide the one-time code that was sent via e-mail or offline",
        },
      },
    },
  });
});

// *******************
// Auth Code Request
// *******************
paymentRouter.get(["/issue-pid-code"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const credentialType = "urn:eu.europa.ec.eudi.pid.1";

  const client_id_scheme = req.query.client_id_scheme
    ? req.query.client_id_scheme
    : "redirect_uri";

  let existingCodeSession = await getCodeFlowSession(uuid);
  if (!existingCodeSession) {
    storeCodeFlowSession(uuid, {
      walletSession: null,
      requests: null,
      results: null,
      status: "pending",
    });
  }

  let encodedCredentialOfferUri = encodeURIComponent(
    `${serverURL}/pid-code-offer/${uuid}?scheme=${client_id_scheme}`
  );
  let credentialOffer = `openid-credential-offer://?credential_offer_uri=${encodedCredentialOfferUri}`;

  let code = qr.image(credentialOffer, {
    type: "png",
    ec_level: "H",
    size: 10,
    margin: 10,
  });
  let mediaType = "PNG";
  let encodedQR = imageDataURI.encode(await streamToBuffer(code), mediaType);
  res.json({
    qr: encodedQR,
    deepLink: credentialOffer,
    sessionId: uuid,
  });
});

paymentRouter.get(["/pid-code-offer/:id"], (req, res) => {
  const credentialType = "urn:eu.europa.ec.eudi.pid.1";
  console.log(req.query.client_id_scheme);
  const client_id_scheme = req.query.scheme ? req.query.scheme : "redirect_uri";
  const issuer_state = `${req.params.id}|${client_id_scheme}`; // using "|" as a delimiter

  res.json({
    credential_issuer: serverURL,
    credential_configuration_ids: [credentialType],
    grants: {
      authorization_code: {
        issuer_state: issuer_state,
      },
    },
  });
});

// *********************************************************
// ************** PAYMENT ROUTES ***************************
// *********************************************************

paymentRouter.post("/generatePaymentRequest", async (req, res) => {
  const uuid = req.body.sessionId ? req.query.sessionId : uuidv4();
  const value = req.body.value ? req.body.value : null;
  const merchant = req.body.merchant ? req.body.merchant : null;
  const currency = req.body.currency ? req.body.currency : null;
  const isReccuring = req.body.isReccuring ? req.body.isReccuring : false;
  const startDate = req.body.startDate;
  const expiryDate = req.body.expiryDate;
  const frequency = req.body.frequency;

  let client_id = "dss.aegean.gr";
  let request_uri = `${serverURL}/payment-request/${uuid}`;
  let vpRequest =
    "openid4vp://?client_id=" +
    encodeURIComponent(client_id) +
    "&request_uri=" +
    encodeURIComponent(request_uri);

  console.log(`pushing to sessions ${uuid}`);
  storeVerificationSession(uuid, {
    walletSession: null,
    requests: null,
    results: null,
    value: value,
    merchant: merchant,
    currency: currency,
    isReccuring: isReccuring,
    startDate: startDate,
    expiryDate: expiryDate,
    frequency: frequency,
    status: "pending",
    paymentStatus: "pending",
  });

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

paymentRouter.get("/payment-request/:id", async (req, res) => {
  const uuid = req.params.id ? req.params.id : uuidv4();
  const response_uri = serverURL + "/payment_direct_post" + "/" + uuid;

  const client_metadata = {
    client_name: "Fast Ferries Demo Merchant",
    logo_uri:
      "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQM7KDXeOMPwTHaVRdSVf1D91HIk59_NnpHHA&s",
    location: "Greece",
    cover_uri: "string",
    description: "EWC pilot merchant",
    vp_formats: {
      jwt_vp: {
        alg: ["EdDSA", "ES256K"],
      },
    },
  };

  const clientId = "dss.aegean.gr";
  // check session, if it doesn't exist this should fail
  let session = getVerificationSession(uuid);
  if (!session) {
    return res.send(404);
  }

  const hash = crypto.createHash("sha256");
  hash.update(JSON.stringify(presentation_definition_sdJwt));
  storeVerificationSession(uuid, session);

  let signedVPJWT = await buildPaymentVpRequestJWT(
    clientId,
    response_uri,
    presentation_definition_sdJwt,
    "",
    "x509_san_dns",
    client_metadata,
    null,
    serverURL,
    "vp_token",
    session.merchant,
    session.currency,
    session.value,
    session.isReccuring,
    session.startDate,
    session.expiryDate,
    session.frequency
  );

  console.log(signedVPJWT);
  res.type("text/plain").send(signedVPJWT);
});

paymentRouter.post("/payment_direct_post/:id", async (req, res) => {
  try{
    console.log("payment_direct_post VP is below!");
    const { sessionId, extractedClaims } = await extractClaimsFromRequest(
      req,
      digest
    );
  
    console.log(extractedClaims)
    const session = getVerificationSession(sessionId);
  
    if (!session) {
      return res.sendStatus(404); //session not found
    }
    
  
    session.status = "success";
    storeVerificationSession(sessionId, session);
    return res.sendStatus(200);
  } catch (error) {
    console.error("Error processing request:", error.message);
    res.status(400).json({ error: error.message });
  }
  
});

export default paymentRouter;
