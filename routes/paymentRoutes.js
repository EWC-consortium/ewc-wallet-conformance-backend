import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import { decodeSdJwt, getClaims } from "@sd-jwt/decode";
import { extractClaimsFromRequest, validatePoP, validateWUA } from "../utils/vpHeplers.js";
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

const paymentRouter = express.Router();

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

// *********************************************************
// ************** PAYMENT ROUTES ***************************
// *********************************************************

paymentRouter.post("/generatePaymentRequest", async (req, res) => {
  const uuid = req.body.sessionId ? req.body.sessionId : uuidv4();
  const value = req.body.value ? req.body.value : null;
  const merchant = req.body.merchant ? req.body.merchant : null;
  const currency = req.body.currency ? req.body.currency : null;
  const isReccuring = req.body.isReccuring ? req.body.isReccuring : false;
  const startDate = req.body.startDate;
  const expiryDate = req.body.expiryDate;
  const frequency = req.body.frequency;

  let client_id = "dss.aegean.gr";

  // let client_id = serverURL.replace("https://","")
  let request_uri = `${serverURL}/payment-request/${uuid}`;
  let vpRequest =
    "openid4vp://?client_id=" +
    encodeURIComponent(client_id) +
    "&request_uri=" +
    encodeURIComponent(request_uri);

  console.log(`pushing to sessions ${uuid}`);
  storeVPSession(uuid, {
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
    client_id: client_id
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

  const clientId = "dss.aegean.gr"; // serverURL.replace("https://","") // ; //TODO this should match the server url (without http stuff)
  // check session, if it doesn't exist this should fail
  let session = await getVPSession(uuid);
  if (!session) {
    session = await getCodeFlowSession(uuid);
    if (!session) return res.send(404);
  }

  const presentation_definition = presentation_definition_pwa; //presentation_definition_pwa_stdId

  const hash = crypto.createHash("sha256");
  hash.update(JSON.stringify(presentation_definition));

  let { jwt, base64EncodedTxData } = await buildPaymentVpRequestJWT(
    clientId,
    response_uri,
    presentation_definition,
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
    session.frequency,
    presentation_definition.input_descriptors[0].id
  );
  session.txData = base64EncodedTxData;
  session.presentation_definition = presentation_definition;
  //update session with tx data
  await storeVPSession(uuid, session);

  console.log(jwt);
  res.type("text/plain").send(jwt);
});

paymentRouter.post("/payment_direct_post/:id", async (req, res) => {
  try {
    console.log("payment_direct_post VP is below!");
    // FETCH headers
    // OAuth-Client-Attestation: <wallet-unit-attestation-jwt>
    // OAuth-Client-Attestation-PoP: <wallet-unit-attestation-pop-jwt></wallet-unit-attestation-pop-jwt>
    const oauthClientAttestation = req.get("OAuth-Client-Attestation");
    const oauthClientAttestationPoP = req.get("OAuth-Client-Attestation-PoP");
     

    const { sessionId, extractedClaims, keybindJwt } =
      await extractClaimsFromRequest(req, digest, true);

    const session = await getVPSession(sessionId);

    // console.log(extractedClaims);
    // console.log("keybindJwt -4");
    // console.log(keybindJwt);
    // let sdHash = keybindJwt.payload.sd_hash;
    let transactionDataHashesArray = keybindJwt.payload.transaction_data_hashes;
    // let xtDataHashAlg = keybindJwt.payload.transaction_data_hashes_alg;

 
    //STEP 1. Validate the VP Token as described in OpenID4VP [4] for the IETF SD-JWT VC credential format.
    // - validating the key binding JWT, as a PWA is always bound to a key ==>  the VP token validation is covered in : extractClaimsFromRequest
    // - checking that the timestamp (iat) in the key binding JWT is close (e.g. ±5 minutes) to receiving the input from the user (two-party model) or intermediary (three-party model), respectively
    const currentTimestamp = Math.floor(Date.now() / 1000);  
    const tokenTimestamp = keybindJwt.payload.iat;  
    const fiveMinutesInSeconds = 5 * 60;  
    if (Math.abs(currentTimestamp - tokenTimestamp) > fiveMinutesInSeconds) {
      return res.status(422).json({ error: 'Keyebinding JWT has expired' });
    }

    //STEP 2. Validate the transaction_data
    // -  original base64url encoded transaction_data string ===
    // the same hash value when hashed with the given function as the hash contained in transaction_data_hashes in the key binding JWT.
    const txData = session.txData; // base64EncodedTxData
    const hash = crypto.createHash("sha256").update(txData).digest("hex");
    if( !transactionDataHashesArray.includes(hash)){
      return res.status(422).json({ error: 'TxData Hashes Do not Match' });
    }

    // STEP 3. Validate the suitability of the PWA
    // The PWA is submitted inside the vpToken and is validated as part 
    // of the extractClaimsFromRequest call
    // - Ensure that the PWA was issued by a suitable entity, most likely the issuer should be the same entity as verifier.
    const pwaPayload = extractedClaims.find(item => item.vct === "PaymentWalletAttestation");
    console.log("PWA issued by " + pwaPayload.iss)

    if (!session) {
      return res.status(404).json({ error: 'Session Not Found' });
    }
     // - Ensure that the PWA is valid for the funding source (card or account) in question (including non-revoked).
     // this is a check that the bank will exectue... 

    // STEP 4. In addition to the above, the verifier may want to validate the user’s Wallet Unit Attestation.
    // See EWC RFC 004 [10] for further details.
    const popValidationResults = await validatePoP(oauthClientAttestation, oauthClientAttestationPoP)
    if( !popValidationResults){
      return  res.status(422).json({ error: 'PoP Validation failed' });
    }

    const wuaValidationResults = await validateWUA(oauthClientAttestation, oauthClientAttestationPoP)
    if( !wuaValidationResults){
      return res.status(422).json({ error: 'PoP Validation failed' });
    }



    // STEP 5. send to bank to process 
   /*
      to be sent to the bank:
      {
          “payment_wallet_attestation”: “<VP Token>”,
          “wallet_unit_attestation”: “<WUA>~<KB JWT>”,
          “transaction_data_hashes_alg”: [“sha-256”],
          “transaction_data”: “Base64URL({….})”
      }
    */


    session.status = "success";
    storeVPSession(sessionId, session);
    return res.status(200).json({ status: "ok" });
  } catch (error) {
    console.error("Error processing request:", error.message);
    res.status(400).json({ error: error.message });
  }
});

export default paymentRouter;
