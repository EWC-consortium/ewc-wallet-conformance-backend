import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import {
  pemToJWK,
  generateNonce,
  base64UrlEncodeSha256,
  jarOAutTokenResponse,
} from "../utils/cryptoUtils.js";
import {
  buildAccessToken,
  generateRefreshToken,
  buildIdToken,
} from "../utils/tokenUtils.js";

import {
  getAuthCodeSessions,
  getAuthCodeAuthorizationDetail,
} from "../services/cacheService.js";

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
  createSignerVerifierX509,
} from "../utils/sdjwtUtils.js";
import jwt from "jsonwebtoken";

import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { request } from "http";
import {
  createPIDPayload,
  createStudentIDPayload,
  createAllianceIDPayload,
  createFerryBoardingPassPayload,
  getPIDSDJWTData,
  getStudentIDSDJWTData,
  getAllianceIDSDJWTData,
  getFerryBoardingPassSDJWTData,
  getGenericSDJWTData,
  getEPassportSDJWTData,
  createEPassportPayload,
  getVReceiptSDJWTData,
  getVReceiptSDJWTDataWithPayload
} from "../utils/credPayloadUtil.js";

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
    });
  }

  let credentialOffer = `openid-credential-offer://?credential_offer_uri=${serverURL}/credential-offer-tx-code/${uuid}?type=${credentialType}`; //OfferUUID
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

  let existingPreAuthSession = await getPreAuthSession(uuid);
  if (!existingPreAuthSession) {
    storePreAuthSession(uuid, {
      status: "pending",
      resulut: null,
      persona: null,
      accessToken: null,
    });
  }
  let credentialOffer = `openid-credential-offer://?credential_offer_uri=${serverURL}/credential-offer-no-code/${uuid}?type=${credentialType}`; //OfferUUID
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
    });
  }
  let credentialOffer = `openid-credential-offer://?credential_offer_uri=${serverURL}/credential-offer-no-code/${uuid}?type=${credentialType}`; //OfferUUID
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
router.get(["/credential-offer-no-code/:id"], (req, res) => {
  const credentialType = req.query.type
    ? req.query.type
    : "VerifiablePortableDocumentA2SDJWT";
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
  uudi = uuid + "x509";

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
    });
  }
  let credentialOffer = `haip://?credential_offer_uri=${serverURL}/haip-credential-offer-tx-code/${uuid}?type=${credentialType}`; //OfferUUID
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

// *********************************************************************

// *****************************************************************
// ************* TOKEN ENDPOINTS ***********************************
// *****************************************************************

router.post("/token_endpoint", async (req, res) => {
  // Fetch the Authorization header
  const authorizationHeader = req.headers["authorization"]; // Fetch the 'Authorization' header
  console.log("token_endpoint authorizatiotn header-" + authorizationHeader);

  //pre-auth code flow
  const preAuthorizedCode = req.body["pre-authorized_code"]; // req.body["pre-authorized_code"]
  const tx_code = req.body["tx_code"];

  //code flow
  const grantType = req.body.grant_type;
  const client_id = req.body.client_id;
  const code = req.body["code"]; //TODO check the code ...
  const code_verifier = req.body["code_verifier"];
  const redirect_uri = req.body["redirect_uri"];

  let generatedAccessToken = buildAccessToken(serverURL, privateKey);

  //TODO CHECK IF THE  AUTHORIZATION REQUEST WAS done via a authorization_details or scope parameter
  let authorization_details = getAuthCodeAuthorizationDetail().get(code);

  if (!(code || preAuthorizedCode)) {
    res.sendStatus(400); // if authorization code or preAuthorizedCode is not submitted return BAD Request
  } else {
    if (grantType == "urn:ietf:params:oauth:grant-type:pre-authorized_code") {
      console.log("pre-auth code flow");
      let existingPreAuthSession = await getPreAuthSession(preAuthorizedCode);
      //if (index >= 0) {
      if (existingPreAuthSession) {
        console.log(
          `credential for session ${preAuthorizedCode} has been issued`
        );
        existingPreAuthSession.status = "success";
        existingPreAuthSession.accessToken = generatedAccessToken;
        let personaId = getPersonaPart(preAuthorizedCode);
        if (personaId) {
          existingPreAuthSession.persona = personaId;
        }
        storePreAuthSession(preAuthorizedCode, existingPreAuthSession);
      }
    } else {
      if (grantType == "authorization_code") {
        console.log("codeSessions ==> grantType == authorization_code");
        console.log(code);
        let issuanceSessionId = await getSessionKeyAuthCode(code);
        if (issuanceSessionId) {
          let existingCodeSession = await getCodeFlowSession(issuanceSessionId);
          if (existingCodeSession) {
            //TODO if PKCE validattiton fails the flow should
            validatePKCE(
              existingCodeSession,
              code,
              code_verifier,
              existingCodeSession.results
            );

            existingCodeSession.results.status = "success";
            existingCodeSession.status = "success";
            storeCodeFlowSession(
              existingCodeSession.results.issuerState,
              existingCodeSession
            );
          }
        }
      }
    }
    //TODO return error if code flow validation fails and is not a pre-auth flow

    if (authorization_details) {
      res.json({
        access_token: generatedAccessToken,
        refresh_token: generateRefreshToken(),
        token_type: "bearer",
        expires_in: 86400,
        // id_token: buildIdToken(serverURL, privateKey),
        c_nonce: generateNonce(),
        c_nonce_expires_in: 86400,
        authorization_details: authorizatiton_details,
      });
    } else {
      res.json({
        access_token: generatedAccessToken,
        refresh_token: generateRefreshToken(),
        token_type: "bearer",
        expires_in: 86400,
        id_token: buildIdToken(serverURL, privateKey),
        c_nonce: generateNonce(),
        c_nonce_expires_in: 86400,
      });
    }
  }
});

// *****************************************************************
// ************* CREDENTIAL ENDPOINTS ******************************
// *****************************************************************

router.post("/credential", async (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Split "Bearer" and the token
  const requestBody = req.body;
  const format = requestBody.format;
  const requestedCredentials = requestBody.credential_definition
    ? requestBody.credential_definition.type
    : null;
  const decodedHeaderSubjectDID =
    requestBody.proof && requestBody.proof.jwt
      ? jwt.decode(requestBody.proof.jwt, { complete: true }).payload.iss
      : null;

  if (!requestBody.proof || !requestBody.proof.jwt) {
    console.log("NO keybinding info found!!!");
    return res.status(400).json({ error: "No proof information found" });
  }

  let payload = {};

  const sessionKey = await getSessionKeyFromAccessToken(token);
  let sessionObject;
  if (sessionKey) {
    sessionObject = await getPreAuthSession(sessionKey);
  }

  if (format === "jwt_vc_json") {
    console.log("jwt ", requestedCredentials);
    if (requestedCredentials && requestedCredentials[0] === "PID") {
      payload = createPIDPayload(token, serverURL, decodedHeaderSubjectDID);
    } else if (
      requestedCredentials &&
      requestedCredentials[0] === "ePassportCredential"
    ) {
      payload = createEPassportPayload(serverURL, decodedHeaderSubjectDID);
    } else if (
      requestedCredentials &&
      requestedCredentials[0] === "StudentID"
    ) {
      payload = createStudentIDPayload(serverURL, decodedHeaderSubjectDID);
    } else if (
      requestedCredentials &&
      requestedCredentials[0] === "ferryBoardingPassCredential"
    ) {
      payload = createEPassportPayload(serverURL, decodedHeaderSubjectDID);
    }

    const signOptions = { algorithm: "ES256" };
    const additionalHeaders = { kid: "aegean#authentication-key", typ: "JWT" };
    const idtoken = jwt.sign(payload, privateKey, {
      ...signOptions,
      header: additionalHeaders,
    });

    res.json({
      format: "jwt_vc_json",
      credential: idtoken,
      c_nonce: generateNonce(),
      c_nonce_expires_in: 86400,
    });
  } else if (format === "vc+sd-jwt") {
    let vct = requestBody.vct;
    console.log("vc+sd-jwt ", vct);

    let decodedHeaderSubjectDID;
    if (requestBody.proof && requestBody.proof.jwt) {
      // console.log(requestBody.proof.jwt)
      let decodedWithHeader = jwt.decode(requestBody.proof.jwt, {
        complete: true,
      });
      let holderJWKS = decodedWithHeader.header;
      // console.log("Token:", token);
      // console.log("Request Body:", requestBody);
      let credType = vct; // VerifiablePortableDocumentA1SDJWT or VerifiablePortableDocumentA2SDJWT

      //TODO
      // check if the this is a HAIP flow...  (for pre-auth flow...)
      // if this is a HAIP flow then we need to sign this with an X509 certificate
      //................
      let sdjwt = null;
      if (false) {
        const privateKeyPem = fs.readFileSync(
          "./x509/client_private_pkcs8.key",
          "utf8"
        );
        const certificatePem = fs.readFileSync(
          "./x509/client_certificate.crt",
          "utf8"
        );

        const { signer, verifier } = await createSignerVerifier(
          privateKeyPem,
          certificatePem
        );
        sdjwt = new SDJwtVcInstance({
          signer,
          verifier,
          signAlg: "ES256",
          hasher: digest,
          hashAlg: "sha-256",
          saltGenerator: generateSalt,
        });
      } else {
        const { signer, verifier } = await createSignerVerifier(
          pemToJWK(privateKey, "private"),
          pemToJWK(publicKeyPem, "public")
        );
        sdjwt = new SDJwtVcInstance({
          signer,
          verifier,
          signAlg: "ES256",
          hasher: digest,
          hashAlg: "sha-256",
          saltGenerator: generateSalt,
        });
      }

      let credPayload = {};
      try {
        if (credType === "VerifiablePIDSDJWT") {
          credPayload = getPIDSDJWTData(decodedHeaderSubjectDID);
        } else if (credType === "VerifiableePassportCredentialSDJWT") {
          credPayload = getEPassportSDJWTData(decodedHeaderSubjectDID);
        } else if (credType === "VerifiableStudentIDSDJWT") {
          credPayload = getStudentIDSDJWTData(decodedHeaderSubjectDID);
        } else if (credType === "ferryBoardingPassCredential") {
          credPayload = VerifiableFerryBoardingPassCredentialSDJWT(
            decodedHeaderSubjectDID
          );
        } else if (credType === "VerifiablePortableDocumentA1SDJWT") {
          credPayload = getGenericSDJWTData(decodedHeaderSubjectDID);
        } else if (credType === "VerifiablevReceiptSDJWT") {
          if (sessionObject) {
            credPayload = getVReceiptSDJWTDataWithPayload(
              sessionObject.credentialPayload,
              decodedHeaderSubjectDID
            );
          } else {
            credPayload = getVReceiptSDJWTData(decodedHeaderSubjectDID);
          }
        } else if (credType === "VerifiablePortableDocumentA2SDJWT") {
          credPayload = getGenericSDJWTData(decodedHeaderSubjectDID);
        }

        const cnf = { jwk: holderJWKS.jwk };
        // console.log(credType);
        // console.log(credPayload.claims);
        // console.log(credPayload.disclosureFrame);

        const credential = await sdjwt.issue(
          {
            iss: serverURL,
            iat: Math.floor(Date.now() / 1000),
            vct: credType,
            ...credPayload.claims,
            cnf: cnf,
          },
          credPayload.disclosureFrame
        );

        console.log("sending credential");
        // console.log({
        //   format: "vc+sd-jwt",
        //   credential: credential,
        //   c_nonce: generateNonce(),
        //   c_nonce_expires_in: 86400,
        // });

        res.json({
          format: "vc+sd-jwt",
          credential: credential,
          c_nonce: generateNonce(),
          c_nonce_expires_in: 86400,
        });
      } catch (error) {
        console.log(error);
      }
    } else {
      console.log(
        "requestBody.proof && requestBody.proof.jwt not found",
        requestBody
      );
      return res.status(400).json({ error: "proof not found" });
    }

    //
  } else {
    console.log("UNSUPPORTED FORMAT:", format);
    return res.status(400).json({ error: "Unsupported format" });
  }
});

//issuerConfig.credential_endpoint = serverURL + "/credential";

//ITB
router.get(["/issueStatus"], async (req, res) => {
  let sessionId = req.query.sessionId;
  let existingPreAuthSession = await getPreAuthSession(sessionId);
  let perAuthStatus = existingPreAuthSession
    ? existingPreAuthSession.status
    : null;

  let codeFlowSession = await getCodeFlowSession(sessionId);
  let codeFlowStatus = codeFlowSession ? codeFlowSession.status : null;

  let result = perAuthStatus || codeFlowStatus;
  if (result) {
    console.log("wi9ll send result");
    console.log({
      status: result,
      reason: "ok",
      sessionId: sessionId,
    });
    res.json({
      status: result,
      reason: "ok",
      sessionId: sessionId,
    });
  } else {
    res.json({
      status: "failed",
      reason: "not found",
      sessionId: sessionId,
    });
  }
});

function checkIfExistsIssuanceStatus(
  sessionId,
  sessions,
  sessionResults,
  walletCodeSessions = null,
  codeFlowRequests = null
) {
  let index = sessions.indexOf(sessionId);
  console.log("index is");
  console.log(index);
  // if (index < 0) {
  //   sessions.forEach((value, _index) => {
  //     console.log("checking value to " + value.replace(/-persona=\s+$/, "") +"-checking vs" + sessionId)
  //     if (value.replace(/-persona=.*$/, "") === sessionId) {
  //       console.log("updated index")
  //       index = _index;
  //     }
  //   });
  // }
  if (index >= 0 && sessionResults[index]) {
    let status = sessionResults[index].status;
    console.log(`sending status ${status} for session ${sessionId}`);
    console.log(`new sessions`);
    console.log(sessions);
    console.log("new session statuses");
    console.log(sessionResults);
    if (status === "success") {
      sessions.splice(index, 1);
      sessionResults.splice(index, 1);
      if (walletCodeSessions) walletCodeSessions.splice(index, 1);
      if (codeFlowRequests) codeFlowRequests.splice(index, 1);
    }
    return status;
  }
  return null;
}

// async function validatePKCE(sessions, code, code_verifier, issuanceResults) {
//   for (let i = 0; i < sessions.length; i++) {
//     let element = sessions[i];
//     if (code === element.sessionId) {
//       let challenge = element.challenge;
//       let tester = await base64UrlEncodeSha256(code_verifier);
//       if (tester === challenge) {
//         issuanceResults[i].status = "success";
//         console.log("code flow status:" + issuanceResults[i].status);
//       } else {
//         console.log(
//           "PCKE ERROR tester and challenge do not match " +
//             tester +
//             "-" +
//             challenge
//         );
//       }
//     }
//   }
// }

async function validatePKCE(sessions, code, code_verifier, issuanceResults) {
  if ((code = sessions.requests.challenge)) {
    let challenge = sessions.challenge;
    let tester = await base64UrlEncodeSha256(code_verifier);
    if (tester === challenge) {
      codeSessions.results.status = "success";
      console.log("PKCE verification success");
      return true;
    }
  }
  console.log("PKCE verification FAILED!!!");
  return false;
}

function getPersonaPart(inputString) {
  const personaKey = "persona=";
  const personaIndex = inputString.indexOf(personaKey);

  if (personaIndex === -1) {
    return null; // "persona=" not found in the string
  }

  // Split the string based on "persona="
  const parts = inputString.split(personaKey);

  // Return the part after "persona="
  return parts[1] || null;
}

export default router;
