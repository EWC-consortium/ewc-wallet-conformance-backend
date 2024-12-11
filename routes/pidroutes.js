import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import {
  pemToJWK,
  generateNonce,
  base64UrlEncodeSha256,
} from "../utils/cryptoUtils.js";
import {
  buildAccessToken,
  generateRefreshToken,
  buildIdToken,
} from "../utils/tokenUtils.js";

import {
  storePreAuthSession,
  getPreAuthSession,
  getSessionKeyFromAccessToken,
  getCodeFlowSession,
  storeCodeFlowSession,
  getSessionKeyAuthCode,
} from "../services/cacheServiceRedis.js";

import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import {
  createSignerVerifier,
  digest,
  generateSalt,
} from "../utils/sdjwtUtils.js";
import jwt from "jsonwebtoken";

import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";

const pidRouter = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");

// *******************
// PRE-Auth Request
// *******************
pidRouter.get(["/issue-pid-pre-auth"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const credentialType = "urn:eu.europa.ec.eudi:pid:1";

  let existingPreAuthSession = await getPreAuthSession(uuid);
  if (!existingPreAuthSession) {
    storePreAuthSession(uuid, {
      status: "pending",
      resulut: null,
      persona: null,
      accessToken: null,
      isPID: true,
    });
  }
  let credentialOffer = `openid-credential-offer://?credential_offer_uri=${serverURL}/pid-pre-auth-offer/${uuid}?type=${credentialType}`;
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

pidRouter.get(["/pid-pre-auth-offer/:id"], async (req, res) => {
  const credentialType = req.query.type
    ? req.query.type
    : "urn:eu.europa.ec.eudi:pid:1";
  console.log(credentialType);
  if (credentialType !== "urn:eu.europa.ec.eudi:pid:1") {
    res.status(500);
    return;
  }

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
pidRouter.get(["/issue-pid-code"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const credentialType = "urn:eu.europa.ec.eudi:pid:1";

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

pidRouter.get(["/pid-code-offer/:id"], (req, res) => {
  const credentialType = "urn:eu.europa.ec.eudi:pid:1";
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

export default pidRouter;
