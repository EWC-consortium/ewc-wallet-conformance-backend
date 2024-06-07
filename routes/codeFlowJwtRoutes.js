import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import { generateNonce, buildVpRequestJwt } from "../utils/cryptoUtils.js";

import { getAuthCodeSessions } from "../services/cacheService.js";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";

const codeFlowRouter = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");

// auth code flow
codeFlowRouter.get(["/offer-code"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();

  const codeSessions = getAuthCodeSessions();
  if (codeSessions.sessions.indexOf(uuid) < 0) {
    codeSessions.sessions.push(uuid);
    // codeSessions.results.push({ sessionId: uuid, status: "pending" });
  }

  // console.log("active sessions");
  // console.log(issuanceResults);
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

// auth code-flow request
codeFlowRouter.get(["/credential-offer-code/:id"], (req, res) => {
  res.json({
    credential_issuer: serverURL,
    credentials: ["VerifiablePortableDocumentA2"],
    grants: {
      authorization_code: {
        issuer_state: req.params.id,
      },
    },
  });
});

codeFlowRouter.get("/authorize", async (req, res) => {
  const responseType = req.query.response_type;
  const scope = req.query.scope;
  const issuerState = decodeURIComponent(req.query.issuer_state); // This can be associated with the ITB session
  const state = req.query.state;
  const clientId = decodeURIComponent(req.query.client_id); //DID of the holder requesting the credential
  let authorizationDetails = "";
  try {
    authorizationDetails = decodeURIComponent(req.query.authorization_details); //TODO this contains the credentials requested
  } catch (error) {
    console.log(
      "No credentials requested! req.query.authorization_details missing!"
    );
    errors.push(
      "No credentials requested! req.query.authorization_details missing!"
    );
  }

  const redirectUri = decodeURIComponent(req.query.redirect_uri);
  const nonce = req.query.nonce;
  const codeChallenge = decodeURIComponent(req.query.code_challenge);
  const codeChallengeMethod = req.query.code_challenge_method; //this should equal to S256
  try {
    const clientMetadata = JSON.parse(
      decodeURIComponent(req.query.client_metadata)
    );
  } catch (error) {
    console.log("client_metadata was missing");
    console.log(error);
  }

  //validations
  let errors = [];
  if (!authorizationDetails) {
    //errors.push("no credentials requested");
    console.log(`no credentials requested`);
  } else if (authorizationDetails.credential_definition) {
    console.log(
      `credential ${authorizationDetails.credential_definition.type} was requested`
    );
  } else if (authorizationDetails.types) {
    //EBSI style
    console.log(`credential ${authorizationDetails.types} was requested`);
  }

  if (responseType !== "code") {
    errors.push("Invalid response_type");
  }
  if (!scope.includes("openid")) {
    errors.push("Invalid scope");
  }

  // If validations pass, redirect with a 302 Found response
  const authorizationCode = null; //"SplxlOBeZQQYbYS6WxSbIA";
  const codeSessions = getAuthCodeSessions();
  if (codeSessions.sessions.indexOf(issuerState) >= 0) {
    codeSessions.requests.push({
      challenge: codeChallenge,
      method: codeChallengeMethod,
      sessionId: authorizationCode,
      issuerState: issuerState,
      state: state,
    });
    codeSessions.results.push({
      sessionId: authorizationCode,
      issuerState: issuerState,
      state: state,
      status: "pending",
    });
    codeSessions.walletSessions.push(state); // push state as send by wallet
  } else {
    console.log("ITB session not found");
  }

  // codeSessions.sessions.push(issuerState);

  // for normal response not requesting VP from wallet
  //const redirectUrl = `${redirectUri}?code=${authorizationCode}&state=${state}`;

  //5.1.5. Dynamic Credential Request https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-12.html#name-successful-authorization-re
  const vpRequestJWT = buildVpRequestJwt(
    state,
    nonce,
    clientId,
    "response_uri",
    null,
    "jwk",
    serverURL,
    privateKey
  );
  const redirectUrl = `http://localhost:8080?state=${state}&client_id=${clientId}&redirect_uri=${serverURL}/direct_post_vci&response_type=id_token&response_mode=direct_post&scope=openid&nonce=${nonce}&request=${vpRequestJWT}`;

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

codeFlowRouter.post("/direct_post_vci", async (req, res) => {
  console.log("direct_post VP for VCI is below!");
  let state = req.body["state"];
  let jwt = req.body["id_token"];
  if (jwt) {
    const codeSessions = getAuthCodeSessions();
    const authorizationCode = generateNonce(16);
    updateIssuerStateWithAuthCode(
      authorizationCode,
      state,
      codeSessions.walletSessions,
      codeSessions.results,
      codeSessions.requests
    );
    const redirectUrl = `http://localhost:8080?code=${authorizationCode}&state=${state}`;
    return res.redirect(302, redirectUrl);
  } else {
    return res.sendStatus(500);
  }
});

function updateIssuerStateWithAuthCode(
  code,
  walletState,
  walletSessions,
  codeFlowRequestsResults,
  codeFlowRequests
) {
  let index = walletSessions.indexOf(walletState);
  if (index >= 0) {
    codeFlowRequestsResults[index].sessionId = code;
    codeFlowRequests[index].sessionId = code;
  } else {
    console.log("issuer state will not be updated");
  }
}

export default codeFlowRouter;
