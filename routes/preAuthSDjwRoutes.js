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

const router = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");

console.log("privateKey");
console.log(privateKey);

// ******************************************************************
// ************* CREDENTIAL OFFER ENDPOINTS *************************
// ******************************************************************

///pre-auth flow sd-jwt
/*
 Generates a VCI request with  pre-authorised flow with a transaction code
*/
router.get(["/offer-tx-code"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const credentialType = req.query.credentialType
    ? req.query.credentialType
    : "VerifiablePortableDocumentA2SDJWT";

  let existingPreAuthSession = await getPreAuthSession(uuid);
  if (!existingPreAuthSession) {
    storePreAuthSession(uuid, {
      status: "pending",
      resulut: null,
      persona: null,
      accessToken: null,
      flowType: "pre-auth",
      isHaip:true
    });
  }
  

    let encodedCredentialOfferUri = encodeURIComponent(
    `${serverURL}/credential-offer-tx-code/${uuid}?type=${credentialType}`)

  let credentialOffer = `openid-credential-offer://?credential_offer_uri=${encodedCredentialOfferUri}`; //OfferUUID
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
 * pre-authorised flow with a transaction code, credential offer
 */
router.get(["/credential-offer-tx-code/:id"], (req, res) => {
  const credentialType = req.query.type
    ? req.query.type
    : "VerifiablePortableDocumentA2SDJWT";
  console.log(credentialType);
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

/**
 * pre-authorised flow without a transaction code request
 */
router.get(["/offer-no-code"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const credentialType = req.query.credentialType
    ? req.query.credentialType
    : "VerifiablePortableDocumentA2SDJWT";
  const signatureType = req.query.signatureType;

  let existingPreAuthSession = await getPreAuthSession(uuid);
  if (!existingPreAuthSession) {
    storePreAuthSession(uuid, {
      status: "pending",
      resulut: null,
      persona: null,
      accessToken: null,
      flowType: "pre-auth",
      isHaip: false,
      signatureType: signatureType
    });
  }
  let encodedCredentialOfferUri = encodeURIComponent(`${serverURL}/credential-offer-no-code/${uuid}?type=${credentialType}`)
  let credentialOffer = `openid-credential-offer://?credential_offer_uri=${encodedCredentialOfferUri}`; //OfferUUID
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
 * pre-authorised flow without a transaction code request AND REQUEST BODY
 */
router.post(["/offer-no-code"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const credentialType = req.query.credentialType
    ? req.query.credentialType
    : "VerifiablePortableDocumentA2SDJWT";

  const credentialPayload = req.body;

  let existingPreAuthSession = await getPreAuthSession(uuid);
  if (!existingPreAuthSession) {
    storePreAuthSession(uuid, {
      status: "pending",
      resulut: null,
      persona: null,
      accessToken: null,
      credentialPayload: credentialPayload,
      flowType: "pre-auth",
      isHaip: true
    });
  }
  let encodedCredentialOfferUri = encodeURIComponent(`${serverURL}/credential-offer-no-code/${uuid}?type=${credentialType}`)
  let credentialOffer = `openid-credential-offer://?credential_offer_uri=${encodedCredentialOfferUri}`; //OfferUUID
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
router.get(["/credential-offer-no-code/:id"], async(req, res) => {
  const credentialType = req.query.type
    ? req.query.type
    : "VerifiablePortableDocumentA2SDJWT";

  // const uuid = req.params.id;
  // let existingPreAuthSession = await getPreAuthSession(uuid);
  // if (!existingPreAuthSession) {
    
  //   storePreAuthSession(uuid, {
  //     status: "pending",
  //     resulut: null,
  //     persona: null,
  //     accessToken: null,
  //     isHaip: true,
  //     flowType: "pre-auth",
  //     scope: credentialType
  //   })
  // }
    
  res.json({
    credential_issuer: serverURL,
    credential_configuration_ids: [credentialType],
    grants: {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": req.params.id,
      },
    },
  });
});

/**
 * --------------------  HAIP ---------------------------------
 * pre-authorised flow with a transaction code, credential offer
 */

/*
  The Grant Types authorization_code and urn:ietf:params:oauth:grant-type:pre-authorized_code MUST be supported as defined in Section 4.1.1 in 
  [OIDF.OID4VCI]
  
  For Grant Type urn:ietf:params:oauth:grant-type:pre-authorized_code, the pre-authorized code is used by the issuer to identify the credential type(s).
  As a way to invoke the Wallet, at least a custom URL scheme haip:// MUST be supported. 
  Implementations MAY support other ways to invoke the wallets as agreed by trust frameworks/ecosystems/jurisdictions,
  not limited to using other custom URL schemes.
*/

router.get(["/haip-offer-tx-code"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();

  const credentialType = req.query.credentialType
    ? req.query.credentialType
    : "VerifiablePortableDocumentA2SDJWT";

  let existingPreAuthSession = await getPreAuthSession(uuid);
  if (!existingPreAuthSession) {
    storePreAuthSession(uuid, {
      status: "pending",
      resulut: null,
      persona: null,
      accessToken: null,
      isHaip: true,
      flowType: "pre-auth",
    });
  }
  let encodedCredentialOfferUri = encodeURIComponent(`${serverURL}/haip-credential-offer-tx-code/${uuid}?type=${credentialType}`)
  let credentialOffer = `haip://?credential_offer_uri=${encodedCredentialOfferUri}`; //OfferUUID
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
 * pre-authorised flow with a transaction code, credential offer
 */
router.get(["/haip-credential-offer-tx-code/:id"], (req, res) => {
  const credentialType = req.query.type
    ? req.query.type
    : "VerifiablePortableDocumentA2SDJWT";
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

export default router;
