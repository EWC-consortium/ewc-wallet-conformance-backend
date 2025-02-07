import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";

import {
  storePreAuthSession,
  getPreAuthSession,
  getSessionKeyFromAccessToken,
  getCodeFlowSession,
  storeCodeFlowSession,
  getSessionKeyAuthCode,
} from "../services/cacheServiceRedis.js";

import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";

const batchRouter = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");

console.log("privateKey");
console.log(privateKey);

// ******************************************************************
// ************* CREDENTIAL OFFER ENDPOINTS *************************
// ******************************************************************

///pre-auth flow sd-jwt
 

/**
 * pre-authorised flow without a transaction code request
 */
batchRouter.get(["/offer-no-code-batch"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const credentialType = req.query.credentialType
    ? req.query.credentialType
    : "CombinedCredentials";

  let existingPreAuthSession = await getPreAuthSession(uuid);
  if (!existingPreAuthSession) {
    storePreAuthSession(uuid, {
      status: "pending",
      resulut: null,
      persona: null,
      accessToken: null,
      flowType: "pre-auth",
    });
  }
  let encodedCredentialOfferUri = encodeURIComponent(`${serverURL}/credential-offer-no-code-batch/${uuid}?type=${credentialType}`)
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

 
/**
 * pre-authorised flow no transaction code request endpoint
 */
batchRouter.get(["/credential-offer-no-code-batch/:id"], (req, res) => {
  const credentialType = req.query.type
    ? req.query.type
    : "CombinedCredentials";
  res.json({
    credential_issuer: serverURL,
    credential_configuration_ids: ["urn:eu.europa.ec.eudi:pid:1","PhotoID" ],
    grants: {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": req.params.id,
      },
    },
  });
});

 
 

export default batchRouter;
