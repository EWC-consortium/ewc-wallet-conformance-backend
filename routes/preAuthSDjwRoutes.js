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
  getCredentialSubjectForPersona,
  getPersonaFromAccessToken,
} from "../utils/personasUtils.js";

import {
  getAuthCodeSessions,
  getPreCodeSessions,
  getAuthCodeAuthorizationDetail,
} from "../services/cacheService.js";

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
router.get(["/offer-tx-code/:type"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const credentialType = req.params.type
    ? req.params.type
    : "VerifiablePortableDocumentA2SDJWT";

  const preSessions = getPreCodeSessions();
  if (preSessions.sessions.indexOf(uuid) < 0) {
    preSessions.sessions.push(uuid);
    preSessions.results.push({ sessionId: uuid, status: "pending" });
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
router.get(["/offer-no-code/:type"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const credentialType = req.params.type
    ? req.params.type
    : "VerifiablePortableDocumentA2SDJWT";
  const preSessions = getPreCodeSessions();
  if (preSessions.sessions.indexOf(uuid) < 0) {
    preSessions.sessions.push(uuid);
    preSessions.results.push({ sessionId: uuid, status: "pending" });
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

  if (grantType == "urn:ietf:params:oauth:grant-type:pre-authorized_code") {
    console.log("pre-auth code flow");
    const preSessions = getPreCodeSessions();
    let index = preSessions.sessions.indexOf(preAuthorizedCode);
    if (index >= 0) {
      console.log(
        `credential for session ${preAuthorizedCode} has been issued`
      );
      preSessions.results[index].status = "success";
      preSessions.accessTokens[index] = generatedAccessToken;
      let personaId = getPersonaPart(preAuthorizedCode);
      if (personaId) {
        preSessions.personas[index] = personaId;
      } else {
        preSessions.personas[index] = null;
      }
      // console.log("pre-auth code flow" + preSessions.results[index].status);
    }
  } else {
    if (grantType == "authorization_code") {
      const codeSessions = getAuthCodeSessions();
      validatePKCE(
        codeSessions.requests,
        code,
        code_verifier,
        codeSessions.results
      );
    }
  }
  //TODO return error if code flow validation fails and is not a pre-auth flow

  if (authorization_details) {
    /*{  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
  "token_type": "bearer",
  "expires_in": 86400,
  "c_nonce": "tZignsnFbp",
  "c_nonce_expires_in": 86400,
  "authorization_details": [
    {
      "type": "openid_credential",
      "credential_configuration_id": "VerifiablePortableDocumentA1",
      "credential_identifiers": [ "VerifiablePortableDocumentA1-Spain", "VerifiablePortableDocumentA1-Sweden", "VerifiablePortableDocumentA1-Germany" ]
    }]}*/
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
      /*   "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
    "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI4a5k..zEF",
    "token_type": "bearer",
    "expires_in": 86400,
    "id_token": "eyJodHRwOi8vbWF0dHIvdGVuYW50L..3Mz",
    "c_nonce": "PAPPf3h9lexTv3WYHZx8ajTe",
    "c_nonce_expires_in": 86400 */

      access_token: generatedAccessToken,
      refresh_token: generateRefreshToken(),
      token_type: "bearer",
      expires_in: 86400,
      id_token: buildIdToken(serverURL, privateKey),
      c_nonce: generateNonce(),
      c_nonce_expires_in: 86400,
    });
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

  if (format === "jwt_vc_json") {
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
    // Handle other credentials similarly...
  } else if (format === "vc+sd-jwt") {
    let vct = requestBody.vct;
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
      const { signer, verifier } = await createSignerVerifier(
        pemToJWK(privateKey, "private"),
        pemToJWK(publicKeyPem, "public")
      );
      const sdjwt = new SDJwtVcInstance({
        signer,
        verifier,
        signAlg: "ES256",
        hasher: digest,
        hashAlg: "SHA-256",
        saltGenerator: generateSalt,
      });

      // const claims = {
      //   given_name: "John",
      //   last_name: "Doe",
      // };

      // const disclosureFrame = {
      //   _sd: ["given_name", "last_name"],
      // };
      let credPayload = {};
      try {
        
        if (credType === "VerifiablePIDSDJWT") {
          credPayload = getPIDSDJWTData(decodedHeaderSubjectDID);
        } else if (credType === "VerifiableePassportCredentialSDJWT") {
          credPayload = getEPassportSDJWTData(decodedHeaderSubjectDID);
        } else if (credType === "VerifiableStudentIDSDJWT") {
          credPayload = getStudentIDSDJWTData(decodedHeaderSubjectDID);
        } else if (credType === "ferryBoardingPassCredential") {
          credPayload = VerifiableFerryBoardingPassCredentialSDJWT(decodedHeaderSubjectDID);
        }

        const cnf = { jwk: holderJWKS };
        console.log(credType);
        console.log(credPayload.claims);
        console.log(credPayload.disclosureFrame);

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
});

//issuerConfig.credential_endpoint = serverURL + "/credential";

//ITB
router.get(["/issueStatus"], (req, res) => {
  let sessionId = req.query.sessionId;

  // walletCodeSessions,codeFlowRequestsResults,codeFlowRequests
  const preSessions = getPreCodeSessions();
  const codeSessions = getAuthCodeSessions();
  let result =
    checkIfExistsIssuanceStatus(
      sessionId,
      preSessions.sessions,
      preSessions.results
    ) ||
    checkIfExistsIssuanceStatus(
      sessionId,
      codeSessions.sessions,
      codeSessions.results,
      codeSessions.walletSessions,
      codeSessions.requests
    );
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

async function validatePKCE(sessions, code, code_verifier, issuanceResults) {
  for (let i = 0; i < sessions.length; i++) {
    let element = sessions[i];
    if (code === element.sessionId) {
      let challenge = element.challenge;
      let tester = await base64UrlEncodeSha256(code_verifier);
      if (tester === challenge) {
        issuanceResults[i].status = "success";
        console.log("code flow status:" + issuanceResults[i].status);
      } else {
        console.log(
          "PCKE ERROR tester and challenge do not match " +
            tester +
            "-" +
            challenge
        );
      }
    }
  }
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
