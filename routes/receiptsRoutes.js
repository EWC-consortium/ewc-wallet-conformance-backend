import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import { decodeSdJwt, getClaims } from "@sd-jwt/decode";
import { extractClaimsFromRequest } from "../utils/vpHeplers.js";
import { digest } from "@sd-jwt/crypto-nodejs";
import crypto from "crypto";
import { extractClaims } from "../utils/sdjwtUtils.js";

import {
  storePreAuthSession,
  getPreAuthSession,
  getCodeFlowSession,
  storeCodeFlowSession,
  storeVPSession,
  getVPSession,
} from "../services/cacheServiceRedis.js";

import {
  buildVpRequestJWT,
  buildPaymentVpRequestJWT,
} from "../utils/cryptoUtils.js";

import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";

const receiptRouter = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

const presentation_definition_pwa = JSON.parse(
  //fs.readFileSync("./data/presentation_definition_pid+pwa.json", "utf-8")
  // fs.readFileSync("./data/presentation_definition_pid|photoID+PWA.json", "utf-8")
  // fs.readFileSync("./data/presentation_definition_sdjwt.json", "utf-8")
  fs.readFileSync("./data/presentation_definition_pwa.json", "utf-8")
);

const presentation_definition_pwa_stdId = JSON.parse(
  //fs.readFileSync("./data/presentation_definition_pid+pwa.json", "utf-8")
  // fs.readFileSync("./data/presentation_definition_pid|photoID+PWA.json", "utf-8")
  // fs.readFileSync("./data/presentation_definition_sdjwt.json", "utf-8")
  fs.readFileSync("./data/presentation_definition_pwa_studentid.json", "utf-8")
);



receiptRouter.post(["/pay-receipt"], async (req, res) => {
    const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
    const credentialType = req.query.credentialType
      ? req.query.credentialType
      : "VerifiableReceipt";
    
    const credentialPayload = req.body;

    const client_id_scheme = "payment"
  
    let existingCodeSession = await getCodeFlowSession(uuid);
    if (!existingCodeSession) {
      const sessionObj = {
        walletSession: null,
        requests: null,
        results: null,
        status: "pending",
        client_id_scheme: client_id_scheme,
        credentialPayload: credentialPayload,
        flowType: "code",
        isDeferred: false,
        merchant: credentialPayload.merchant,
        currency: credentialPayload.currency,
        value :credentialPayload.value,
        isReccuring :credentialPayload.isReccuring,
        startDate :credentialPayload.startDate,
        expiryDate :credentialPayload.expiryDate,
        frequency :credentialPayload.frequency,
      }
      storeCodeFlowSession(uuid, sessionObj);
    }
  
    let encodedCredentialOfferUri = encodeURIComponent(
      `${serverURL}/credential-offer-receipt-pay/${uuid}?scheme=${client_id_scheme}&credentialType=${credentialType}`
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



  receiptRouter.get(["/credential-offer-receipt-pay/:id"], (req, res) => {
    const credentialType = req.query.credentialType
      ? req.query.credentialType
      : "VerifiablePortableDocumentA2SDJWT";
  
    console.log(req.query);
    console.log(req.query.client_id_scheme);
    const client_id_scheme = req.query.scheme ? req.query.scheme : "redirect_uri";
  
    /*
      To support multiple client_id_schemas, this param  client_id_scheme 
      will be passed into the session of the issuer and fetched in the 
      authorize endpoint to decide what schema to use
    */
    // const issuer_state = `${req.params.id}|${client_id_scheme}`; // using "|" as a delimiter
  
    res.json({
      credential_issuer: serverURL,
      credential_configuration_ids: [credentialType],
      grants: {
        authorization_code: {
          issuer_state: req.params.id, //issuer_state,
        },
      },
    });
  });


  export default receiptRouter;