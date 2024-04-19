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
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import {
  createSignerVerifier,
  digest,
  generateSalt,
} from "../utils/sdjwtUtils.js";

import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";

const router = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");

console.log("privateKey");
console.log(privateKey);

const issuerConfig = JSON.parse(
  fs.readFileSync("./data/issuer-config.json", "utf-8")
);
const oauthConfig = JSON.parse(
  fs.readFileSync("./data/oauth-config.json", "utf-8")
);

const jwks = pemToJWK(publicKeyPem, "public");

//TODO  move this into a service that caches these (e.g via redis or something)
let sessions = [];
let issuanceResults = [];
let codeSessions = [];
let codeFlowRequests = [];
let codeFlowRequestsResults = [];

router.get("/.well-known/openid-credential-issuer", async (req, res) => {
  // console.log("1 ROUTE /.well-known/openid-credential-issuer CALLED!!!!!!");
  // issuerConfig.authorization_servers = [serverURL];
  issuerConfig.credential_issuer = serverURL;
  // issuerConfig.authorization_servers = [serverURL];
  issuerConfig.authorization_server = serverURL;
  issuerConfig.credential_endpoint = serverURL + "/credential";
  issuerConfig.deferred_credential_endpoint =
    serverURL + "/credential_deferred";

  res.type("application/json").send(issuerConfig);
});

router.get(
  [
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/oauth-authorization-server/rfc-issuer", //this is required in case the issuer is behind a reverse proxy: see https://www.rfc-editor.org/rfc/rfc8414.html
  ],
  async (req, res) => {
    oauthConfig.issuer = serverURL;
    oauthConfig.authorization_endpoint = serverURL + "/authorize";
    oauthConfig.token_endpoint = serverURL + "/token_endpoint";
    oauthConfig.jwks_uri = serverURL + "/jwks";
    res.type("application/json").send(oauthConfig);
  }
);

router.get(["/", "/jwks"], (req, res) => {
  res.json({
    keys: [
      { ...jwks, kid: `aegean#authentication-key`, use: "sig" },
      { ...jwks, kid: `aegean#authentication-key`, use: "keyAgreement" }, //key to encrypt the sd-jwt response])
    ],
  });
});

///pre-auth flow
router.get(["/offer"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  sessions.push(uuid);
  issuanceResults.push({ sessionId: uuid, status: "pending" });
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

// auth code flow
router.get(["/offer-code"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  sessions.push(uuid);
  issuanceResults.push({ sessionId: uuid, status: "pending" });
  console.log("active sessions");
  console.log(issuanceResults); //TODO associate this with a different "cache"
  let credentialOffer = `openid-credential-offer://?credential_offer_uri=${serverURL}/credential-offer-code/${uuid}`;

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

// auth code-flow request
router.get(["/credential-offer-code/:id"], (req, res) => {
  res.json({
    credential_issuer: serverURL,
    credentials: ["VerifiablePortableDocumentA1"],
    grants: {
      authorization_code: {
        issuer_state: req.params.id,
      },
    },
  });
});

router.get("/authorize", async (req, res) => {
  const responseType = req.query.response_type;
  const scope = req.query.scope;
  const issuerState = decodeURIComponent(req.query.issuer_state); // This can be associated with the ITB session
  const state = req.query.state;
  const clientId = decodeURIComponent(req.query.client_id); //DID of the holder requesting the credential
  const authorizationDetails = JSON.parse(
    decodeURIComponent(req.query.authorization_details) //TODO this contains the credentials requested
  );
  const redirectUri = decodeURIComponent(req.query.redirect_uri);
  const nonce = req.query.nonce;
  const codeChallenge = decodeURIComponent(req.query.code_challenge);
  const codeChallengeMethod = req.query.code_challenge_method; //this should equal to S256

  const clientMetadata = JSON.parse(
    decodeURIComponent(req.query.client_metadata)
  );
  //validations
  let errors = [];
  if (authorizationDetails.credential_definition) {
    console.log(
      `credential ${authorizationDetails.credential_definition.type} was requested`
    );
  } else {
    if (authorizationDetails.types) {
      //EBSI style
      console.log(`credential ${authorizationDetails.types} was requested`);
    } else {
      //errors.push("no credentials requested");
      console.log(`no credentials requested`);
    }
  }

  if (responseType !== "code") {
    errors.push("Invalid response_type");
  }
  if (!scope.includes("openid")) {
    errors.push("Invalid scope");
  }

  // If validations pass, redirect with a 302 Found response
  const authorizationCode = generateNonce(16); //"SplxlOBeZQQYbYS6WxSbIA";
  codeFlowRequests.push({
    challenge: codeChallenge,
    method: codeChallengeMethod,
    sessionId: authorizationCode,
    issuerState: issuerState,
  });
  codeFlowRequestsResults.push({
    sessionId: authorizationCode,
    issuerState: issuerState,
    status: "pending",
  });
  codeSessions.push(issuerState); // push issuerState

  // for normal response not requesting VP from wallet 
  //const redirectUrl = `${redirectUri}?code=${authorizationCode}&state=${state}`;


  //5.1.5. Dynamic Credential Request https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-12.html#name-successful-authorization-re
  const redirectUrl = `http://localhost:8080?state=${state}&client_id=${clientId}&redirect_uri=${serverURL}/direct_post_vci&response_type=id_token&
  response_mode=direct_post&scope=openid&nonce=${nonce}&request_uri=http://localhost:8080`


  if (errors.length > 0) {
    console.error("Validation errors:", errors);
    let error_description = "";
    errors.forEach((element) => {
      error_description += element + " ";
    });
    const encodedErrorDescription = encodeURIComponent(
      error_description.trim()
    );
    const errorRedirectUrl = `${redirectUri}?error=invalid_request&error_description=${encodedErrorDescription}`;
    //TODO mark the codeFlowSession as failed
    return res.redirect(302, errorRedirectUrl);
  } else {
    return res.redirect(302, redirectUrl);
  }
});

router.post("/direct_post_vci", async (req, res) => {
  console.log("direct_post VP for VCI is below!");
  let state = req.body["state"]
  let jwt = req.body["id_token"];
  if (jwt) {
    const authorizationCode = generateNonce(16);  
    const redirectUrl = `http://localhost:8080?code=${authorizationCode}&state=${state}`;
    return res.redirect(302, redirectUrl);
  } else {
    return res.sendStatus(500);
  }
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

  console.log("token_endpoint parameters received");
  console.log(grantType);
  console.log(preAuthorizedCode);
  console.log(userPin);
  console.log("---------");

  if (grantType == "urn:ietf:params:oauth:grant-type:pre-authorized_code") {
    console.log("pre-auth code flow");
    let index = sessions.indexOf(preAuthorizedCode);
    if (index >= 0) {
      console.log(
        `credential for session ${preAuthorizedCode} has been issued`
      );
      issuanceResults[index].status = "success";
      console.log("pre-auth code flow" + issuanceResults[index].status);
    }
  } else {
    if (grantType == "authorization_code") {
      validatePKCE(
        codeFlowRequests,
        code,
        code_verifier,
        codeFlowRequestsResults
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
  //TODO valiate bearer header

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
      vct: "VerifiablePortableDocumentA1",
      ...claims,
    },
    disclosureFrame
  );
  console.log(credential);
  res.json({
    format: "vc+sd-jwt",
    credential: credential,
    c_nonce: generateNonce(),
    c_nonce_expires_in: 86400,
  });
});
//issuerConfig.credential_endpoint = serverURL + "/credential";

//ITB
router.get(["/issueStatus"], (req, res) => {
  let sessionId = req.query.sessionId;

  // let index = sessions.indexOf(sessionId);
  // console.log("index is");
  // console.log(index);
  // if (index >= 0) {
  //   let status = issuanceResults[index].status;
  //   console.log(`sending status ${status} for session ${sessionId}`);
  //   if (status === "success") {
  //     sessions.splice(index, 1);
  //     issuanceResults.splice(index, 1);
  //   }
  //   console.log(`new sessions`);
  //   console.log(sessions);
  //   console.log("new session statuses");
  //   console.log(issuanceResults);

  let result =
    checkIfExistsIssuanceStatus(sessionId, sessions, issuanceResults) ||
    checkIfExistsIssuanceStatus(
      sessionId,
      codeSessions,
      codeFlowRequestsResults
    );
  if (result) {
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

function checkIfExistsIssuanceStatus(sessionId, sessions, sessionResults) {
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
