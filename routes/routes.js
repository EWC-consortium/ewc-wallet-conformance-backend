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
  getAuthCodeSessions,
  getPreCodeSessions,
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

const router = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");

console.log("privateKey");
console.log(privateKey);

///pre-auth flow
router.get(["/offer"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const preSessions = getPreCodeSessions();
  if (preSessions.sessions.indexOf(uuid) < 0) {
    preSessions.sessions.push(uuid);
    preSessions.results.push({ sessionId: uuid, status: "pending" });
  }

  // console.log("active sessions");
  // console.log(issuanceResults);
  let credentialOffer = `openid-credential-offer://?credential_offer_uri=${serverURL}/credential-offer/${uuid}`; //OfferUUID

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

//pre-auth flow request
router.get(["/credential-offer/:id"], (req, res) => {
  res.json({
    credential_issuer: serverURL,
    credentials: ["VerifiablePortableDocumentA1"],
    grants: {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": req.params.id,
        user_pin_required: true,
      },
    },
  });
});

router.post("/token_endpoint", async (req, res) => {
  //pre-auth code flow
  const grantType = req.body.grant_type;
  const preAuthorizedCode = req.body["pre-authorized_code"]; // req.body["pre-authorized_code"]
  const userPin = req.body["user_pin"];
  //code flow
  const code = req.body["code"]; //TODO check the code ...
  const code_verifier = req.body["code_verifier"];
  const redirect_uri = req.body["redirect_uri"];

  // console.log("token_endpoint parameters received");
  // console.log(grantType);
  // console.log(preAuthorizedCode);
  // console.log(userPin);
  // console.log("---------");

  if (grantType == "urn:ietf:params:oauth:grant-type:pre-authorized_code") {
    console.log("pre-auth code flow");
    const preSessions = getPreCodeSessions();
    let index = preSessions.sessions.indexOf(preAuthorizedCode);
    if (index >= 0) {
      console.log(
        `credential for session ${preAuthorizedCode} has been issued`
      );
      preSessions.results[index].status = "success";
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
  res.json({
    access_token: buildAccessToken(serverURL, privateKey),
    refresh_token: generateRefreshToken(),
    token_type: "bearer",
    expires_in: 86400,
    id_token: buildIdToken(serverURL, privateKey),
    c_nonce: generateNonce(),
    c_nonce_expires_in: 86400,
  });
});

router.post("/credential", async (req, res) => {
  // console.log("7 ROUTE /credential CALLED!!!!!!");
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Split "Bearer" and the token
  // Accessing the body data
  const requestBody = req.body;
  const format = requestBody.format;
  //TODO valiate bearer header
  let decodedWithHeader;
  let decodedHeaderSubjectDID;
  if (requestBody.proof && requestBody.proof.jwt) {
    // console.log(requestBody.proof.jwt)
    decodedWithHeader = jwt.decode(requestBody.proof.jwt, { complete: true });
    // console.log(decodedWithHeader.payload.iss);
    decodedHeaderSubjectDID = decodedWithHeader.payload.iss;
  }

  // console.log(credential);
  if (format === "jwt_vc") {
    //sign as jwt
    const payload = {
      iss: serverURL,
      sub: decodedHeaderSubjectDID || "",
      exp: Math.floor(Date.now() / 1000) + 60 * 60, // Token expiration time (1 hour from now)
      iat: Math.floor(Date.now() / 1000), // Token issued at time
      // nbf: Math.floor(Date.now() / 1000),
      jti: "urn:did:1904a925-38bd-4eda-b682-4b5e3ca9d4bc",
      vc: {
        credentialSubject: {
          id: null,
          given_name: "John",
          last_name: "Doe",
        },
        expirationDate: new Date(
          (Math.floor(Date.now() / 1000) + 60 * 60) * 1000
        ).toISOString(),
        id: "urn:did:1904a925-38bd-4eda-b682-4b5e3ca9d4bc",
        issuanceDate: new Date(
          Math.floor(Date.now() / 1000) * 1000
        ).toISOString(),
        issued: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString(),
        issuer: serverURL,
        type: ["VerifiablePortableDocumentA2"],
        validFrom: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString(),
      },
      // Optional claims
    };

    const signOptions = {
      algorithm: "ES256", // Specify the signing algorithm
    };

    // Define additional JWT header fields
    const additionalHeaders = {
      kid: "aegean#authentication-key",
      typ: "JWT",
    };
    // Sign the token
    const idtoken = jwt.sign(payload, privateKey, {
      ...signOptions,
      header: additionalHeaders, // Include additional headers separately
    });

    // console.log(idtoken);

    /* jwt format */
    res.json({
      format: "jwt_vc",
      credential: idtoken,
      c_nonce: generateNonce(),
      c_nonce_expires_in: 86400,
    });
  } else {
    // console.log("Token:", token);
    // console.log("Request Body:", requestBody);
    const { signer, verifier } = await createSignerVerifier(
      pemToJWK(privateKey, "private"),
      pemToJWK(publicKeyPem, "public")
    );
    const sdjwt = new SDJwtVcInstance({
      signer,
      verifier,
      signAlg: "ES384",
      hasher: digest,
      hashAlg: "SHA-256",
      saltGenerator: generateSalt,
    });
    const claims = {
      given_name: "John",
      last_name: "Doe",
    };
    const disclosureFrame = {
      _sd: ["given_name", "last_name"],
    };
    const credential = await sdjwt.issue(
      {
        iss: serverURL,
        iat: new Date().getTime(),
        type: "VerifiablePortableDocumentA1",
        ...claims,
      },
      disclosureFrame
    );
    res.json({
      format: "vc+sd-jwt",
      credential: credential,
      c_nonce: generateNonce(),
      c_nonce_expires_in: 86400,
    });
  }
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
  if (index >= 0) {
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
      }
    }
  }
}

export default router;
