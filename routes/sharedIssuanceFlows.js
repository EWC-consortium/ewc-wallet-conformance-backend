import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import {
  pemToJWK,
  generateNonce,
  base64UrlEncodeSha256,
  jarOAutTokenResponse,
  didKeyToJwks,
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
  getSessionAccessToken,
  getDeferredSessionTransactionId,
} from "../services/cacheServiceRedis.js";

import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import {
  createSignerVerifier,
  digest,
  generateSalt,
  createSignerVerifierX509,
  pemToBase64Der,
} from "../utils/sdjwtUtils.js";
import jwt from "jsonwebtoken";

import {
  createPIDPayload,
  createStudentIDPayload,
  getPIDSDJWTData,
  getStudentIDSDJWTData,
  getGenericSDJWTData,
  getEPassportSDJWTData,
  createEPassportPayload,
  getVReceiptSDJWTData,
  getVReceiptSDJWTDataWithPayload,
  createPaymentWalletAttestationPayload,
  createPhotoIDAttestationPayload,
  getFerryBoardingPassSDJWTData,
  createPCDAttestationPayload,
} from "../utils/credPayloadUtil.js";

const sharedRouter = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");
const privateKeyPemX509 = fs.readFileSync(
  "./x509EC/ec_private_pkcs8.key",
  "utf8"
);
const certificatePemX509 = fs.readFileSync(
  "./x509EC/client_certificate.crt",
  "utf8"
);

const { signer, verifier } = await createSignerVerifierX509(
  privateKeyPemX509,
  certificatePemX509
);

//   console.log("privateKey");
//   console.log(privateKey);

// *********************************************************************

// *****************************************************************
// ************* TOKEN ENDPOINTS ***********************************
// *****************************************************************

sharedRouter.post("/token_endpoint", async (req, res) => {
  // Fetch the Authorization header
  const authorizationHeader = req.headers["authorization"]; // Fetch the 'Authorization' header
  // console.log("token_endpoint authorizatiotn header-" + authorizationHeader);

  const clientAttestation = req.headers["OAuth-Client-Attestation"]; //this is the WUA
  const pop = req.headers["OAuth-Client-Attestation-PoP"];

  //pre-auth code flow
  const preAuthorizedCode = req.body["pre-authorized_code"]; // req.body["pre-authorized_code"]
  const tx_code = req.body["tx_code"];
  //TODO check tx_code as well

  // check if for this auth session we are issuing a PID credential to validate the WUA and PoP
  if (preAuthorizedCode) {
    let existingPreAuthSession = await getPreAuthSession(preAuthorizedCode);
    //TODO validatte WUA and PoP
    if (existingPreAuthSession && existingPreAuthSession.isPID) {
      console.log("pid issuance detected will check WUA and PoP");
      console.log(clientAttestation);
      console.log(pop);
    }
  }

  //code flow
  const grantType = req.body.grant_type;
  const client_id = req.body.client_id;
  const code = req.body["code"];
  const code_verifier = req.body["code_verifier"];
  const redirect_uri = req.body["redirect_uri"];

  let generatedAccessToken = buildAccessToken(serverURL, privateKey);

  //TODO CHECK IF THE  AUTHORIZATION REQUEST WAS done via a authorization_details or scope parameter
  let authorization_details = getAuthCodeAuthorizationDetail().get(code);

  if (!(code || preAuthorizedCode)) {
    return res.sendStatus(400); // if authorization code or preAuthorizedCode is not submitted return BAD Request
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
        // console.log(code);
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
            existingCodeSession.requests.accessToken = generatedAccessToken;
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
        authorization_details: authorization_details,
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

sharedRouter.post("/credential", async (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Split "Bearer" and the token
  const requestBody = req.body;
  const format = requestBody.format;
  const requestedCredentials = requestBody.credential_definition
    ? requestBody.credential_definition.type
    : null;

  if (!requestBody.proof || !requestBody.proof.jwt) {
    /*
       Object containing the proof of possession of the cryptographic key material the issued Credential would be bound to. 
       The proof object is REQUIRED if the proof_types_supported parameter is non-empty and present in the credential_configurations_supported parameter 
       of the Issuer metadata for the requested Credential
  
       This issuer atm only supports jwt proof types
      */
    console.log("NO keybinding info found!!!");
    return res.status(400).json({ error: "No proof information found" });
  }

  let payload = {};

  const preAuthsessionKey = await getSessionKeyFromAccessToken(token); //this only works for pre-auth flow..
  let sessionObject;
  if (preAuthsessionKey) {
    sessionObject = await getPreAuthSession(preAuthsessionKey);
    if (!sessionObject)
      sessionObject = await getCodeFlowSession(preAuthsessionKey);
  }

  const codeSessionKey = await getSessionAccessToken(token); //this only works for pre-auth flow..
  if (codeSessionKey) {
    sessionObject = await getCodeFlowSession(codeSessionKey);
  }

  if (sessionObject && sessionObject.isDeferred) {
    //Defered flow
    let transaction_id = generateNonce();
    sessionObject.transaction_id = transaction_id;
    sessionObject.requested_credential = requestBody.vct
      ? requestBody.vct
      : requestedCredentials;
    sessionObject.isCredentialReady = false;
    if (sessionObject.flowType == "code") {
      await storeCodeFlowSession(preAuthsessionKey, sessionObject);
    } else {
      await storePreAuthSession(preAuthsessionKey, sessionObject);
    }

    res.json({
      transaction_id: transaction_id,
      c_nonce: generateNonce(),
      c_nonce_expires_in: 86400,
    });
  } else {
    //On time flow
    if (format === "jwt_vc_json") {
      console.log("jwt ", requestedCredentials);
      if (requestedCredentials && requestedCredentials[0] === "PID") {
        payload = createPIDPayload(token, serverURL, "");
      } else if (
        requestedCredentials &&
        requestedCredentials[0] === "ePassportCredential"
      ) {
        payload = createEPassportPayload(serverURL, "");
      } else if (
        requestedCredentials &&
        requestedCredentials[0] === "StudentID"
      ) {
        payload = createStudentIDPayload(serverURL, "");
      } else if (
        requestedCredentials &&
        requestedCredentials[0] === "ferryBoardingPassCredential"
      ) {
        payload = createEPassportPayload(serverURL, "");
      } else if (
        requestedCredentials &&
        requestedCredentials[0] === "PaymentWalletAttestationAccount"
      ) {
        payload = createPIDPayload(token, serverURL, "");
      }

      const signOptions = { algorithm: "ES256" };
      const additionalHeaders = {
        kid: "aegean#authentication-key",
        typ: "JWT",
      };
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

      // holder wallet binding
      if (requestBody.proof && requestBody.proof.jwt) {
        // console.log(requestBody.proof.jwt)
        let decodedWithHeader = jwt.decode(requestBody.proof.jwt, {
          complete: true,
        });
        let holderJWKS = decodedWithHeader.header;

        //TODO validate the jwt that is part of the proof.jwt to ensure the
        // holder wallet is in control of the presented key...

        // console.log("Token:", token);
        // console.log("Request Body:", requestBody);
        let credType = vct; // VerifiablePortableDocumentA1SDJWT or VerifiablePortableDocumentA2SDJWT

        // if this is a HAIP flow then we need to sign this with an X509 certificate
        //................
        let sdjwt = null;
        let isHaip = sessionObject ? sessionObject.isHaip : false;
        if (isHaip) {
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
          if (
            credType === "VerifiablePIDSDJWT" ||
            credType === "urn:eu.europa.ec.eudi:pid:1"
          ) {
            credPayload = getPIDSDJWTData();
          } else if (credType === "VerifiableePassportCredentialSDJWT") {
            credPayload = getEPassportSDJWTData();
          } else if (credType === "VerifiableStudentIDSDJWT") {
            credPayload = getStudentIDSDJWTData();
          } else if (
            credType === "ferryBoardingPassCredential" ||
            credType === "VerifiableFerryBoardingPassCredentialSDJWT"
          ) {
            credPayload = await getFerryBoardingPassSDJWTData();
          } else if (credType === "VerifiablePortableDocumentA1SDJWT") {
            credPayload = getGenericSDJWTData();
          }
          if (credType === "PaymentWalletAttestation") {
            credPayload = createPaymentWalletAttestationPayload();
          } else if (credType === "VerifiablevReceiptSDJWT") {
            if (sessionObject) {
              credPayload = getVReceiptSDJWTDataWithPayload(
                sessionObject.credentialPayload
              );
            } else {
              credPayload = getVReceiptSDJWTData();
            }
          } else if (credType === "VerifiablePortableDocumentA2SDJWT") {
            credPayload = getGenericSDJWTData();
          } else if (credType === "eu.europa.ec.eudi.photoid.1") {
            credPayload = createPhotoIDAttestationPayload();
          } else if (credType === "eu.europa.ec.eudi.pcd.1") {
            credPayload = createPCDAttestationPayload();
          }

          let cnf = { jwk: holderJWKS.jwk };
          if (!cnf.jwk) {
            cnf = await didKeyToJwks(holderJWKS.kid);
          }

          // console.log(credType);
          // console.log(credPayload.claims);
          // console.log(credPayload.disclosureFrame);

          let credential;
          /*
           {
        header: { typ: 'dc+sd-jwt', custom: 'data' }, // You can add custom header data to the SD JWT
      }
          */

          if (isHaip) {
            console.log("HAIP issue flow.. will add x509 header");
            console.log("client certificate pem is");
            console.log(certificatePemX509);
            const certBase64 = pemToBase64Der(certificatePemX509);

            const x5cHeader = [certBase64];

            // let disclosureFrame = { _sd: credPayload.disclosureFrame._sd };

            credential = await sdjwt.issue(
              {
                iss: serverURL,
                iat: Math.floor(Date.now() / 1000),
                vct: credType,
                ...credPayload.claims,
                cnf: cnf,
              },
              credPayload.disclosureFrame,
              {
                header: { x5c: x5cHeader },
              }
            );
          } else {
            credential = await sdjwt.issue(
              {
                iss: serverURL,
                iat: Math.floor(Date.now() / 1000),
                vct: credType,
                ...credPayload.claims,
                cnf: cnf,
              },
              credPayload.disclosureFrame,
              {
                header: { kid: "aegean#authentication-key" },
              }
            );
          }

          console.log("sending credential");
          console.log({
            format: "vc+sd-jwt",
            credential: credential,
            c_nonce: generateNonce(),
            c_nonce_expires_in: 86400,
          });

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
  }
});

// *****************************************************************
// ************* deferred ENDPOINTS ******************************
// *****************************************************************
sharedRouter.post("/credential_deferred", async (req, res) => {
  const authorizationHeader = req.headers["authorization"]; // Fetch the 'Authorization' header
  // console.log(
  //   "credential_deferred authorizatiotn header-" + authorizationHeader
  // );
  const transaction_id = req.body.transaction_id;
  const session = await getDeferredSessionTransactionId(transaction_id);

  console.log(transaction_id);
  if (!session) {
    return res.status(400).json({
      error: "invalid_transaction_id",
    });
  }else{
    session
  }
});

//ITB
sharedRouter.get(["/issueStatus"], async (req, res) => {
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

export default sharedRouter;
