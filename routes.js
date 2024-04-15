import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import {
  pemToJWK,
  generateNonce,
  base64UrlEncodeSha256,
} from "./utils/cryptoUtils.js";
import {
  buildAccessToken,
  generateRefreshToken,
  buildIdToken,
} from "./utils/tokenUtils.js";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import {
  createSignerVerifier,
  digest,
  generateSalt,
} from "./utils/sdjwtUtils.js";

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
let codeFlowSessions = [];
let codeFlowSessionsResults = [];

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
    // console.log("2 ROUTE /.well-known/oauth-authorization-server CALLED!!!!!!");
    oauthConfig.issuer = serverURL;
    oauthConfig.authorization_endpoint = serverURL + "/authorize";
    oauthConfig.token_endpoint = serverURL + "/token_endpoint";
    oauthConfig.jwks_uri = serverURL + "/jwks";

    res.type("application/json").send(oauthConfig);
  }
);

router.get(["/", "/jwks"], (req, res) => {
  console.log("3 ROUTE ./jwks CALLED!!!!!!");
  res.json(
    {
      keys: [
        { ...jwks, kid: `aegean#authentication-key`, use: "sig" },
        { ...jwks, kid: `aegean#authentication-key`, use: "keyAgreement" }, //key to encrypt the sd-jwt response])
      ],
    }
    // res.json({ keys: jwks });
  );
});

router.get(["/credential-offer/:id"], (req, res) => {
  //TODO assosiate the code with the credential offer
  res.json({
    credential_issuer: serverURL,
    credentials: ["VerifiablePortableDocumentA1"],
    grants: {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": req.params.id, //"adhjhdjajkdk1hjhdj",
        user_pin_required: true,
      },
    },
  });
});

router.get(["/credential-offer-code/:id"], (req, res) => {
  res.json({
    credential_issuer: serverURL,
    credentials: ["VerifiablePortableDocumentA1"],
    grants: {
      authorization_code: {
        issuer_state: req.params.id, //"adhjhdjajkdk1hjhdj",
      },
    },
  });
});

router.get("/authorize", async (req, res) => {
  const responseType = req.query.response_type;
  const scope = req.query.scope;
  const issuerState = decodeURIComponent(req.query.issuer_state);
  const state = req.query.state;
  const clientId = decodeURIComponent(req.query.client_id); //DID of the holder requesting the credential
  const authorizationDetails = JSON.parse(
    decodeURIComponent(req.query.authorization_details) //TODO this contains the credentials requested
  );
  const redirectUri = decodeURIComponent(req.query.redirect_uri);
  const nonce = req.query.nonce;
  const codeChallenge = decodeURIComponent(req.query.code_challenge); //secret TODO cache this with challenge method under client state.
  const codeChallengeMethod = req.query.code_challenge_method; //challenge method

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
      errors.push("no credentials requested");
    }
  }

  if (responseType !== "code") {
    errors.push("Invalid response_type");
  }
  if (!scope.includes("openid")) {
    errors.push("Invalid scope");
  }

  // If validations pass, redirect with a 302 Found response
  const authorizationCode = "SplxlOBeZQQYbYS6WxSbIA"; //TODO make this dynamic
  codeFlowSessions.push({
    challenge: codeChallenge,
    method: codeChallengeMethod,
    sessionId: authorizationCode,
  });
  codeFlowSessionsResults.push({
    sessionId: authorizationCode,
    status: "pending",
  });

  const redirectUrl = `${redirectUri}?code=${authorizationCode}`;
  // If there are errors, log errors
  if (errors.length > 0) {
    console.error("Validation errors:", errors);
    let error_description = "";
    error.array.forEach((element) => {
      error_description += element + " ";
    });
    const errorRedirectUrl = `${redirectUri}?error=invalid_request
    &error_description=${error_description}`;
    return res.redirect(302, errorRedirectUrl);
  } else {
    // This sets the HTTP status to 302 and the Location header to the redirectUrl
    return res.redirect(302, redirectUrl);
  }
});

router.post("/token_endpoint", async (req, res) => {
  // console.log("6 ROUTE /token_endpoint CALLED!!!!!!");
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
      //check PKCE
      for (let i = 0; i < codeFlowSessions.array.length; i++) {
        let element = codeFlowSessions.array[i];
        if (code === element.sessionId) {
          let challenge = element.challenge;
          // let method = element.method;
          if (base64UrlEncodeSha256(code_verifier) === challenge) {
            index = i;
            codeFlowSessionsResults[i].status = "success";
            console.log("code flow" + issuanceResults[index].status);
          }
        }
      }
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
//TODO move these to a separate route
router.get(["/issueStatus"], (req, res) => {
  let sessionId = req.query.sessionId;
  // console.log("sessions found");
  // console.log(sessions);
  // console.log("searching for sessionId" + sessionId);
  // issuanceSession itbSession[sessionId] == offerUUID

  let index = sessions.indexOf(sessionId);
  console.log("index is");
  console.log(index);
  if (index >= 0) {
    let status = issuanceResults[index].status;
    console.log(`sending status ${status} for session ${sessionId}`);
    if (status === "success") {
      sessions.splice(index, 1);
      issuanceResults.splice(index, 1);
    }
    console.log(`new sessions`);
    console.log(sessions);
    console.log("new session statuses");
    console.log(issuanceResults);
    res.json({
      status: status,
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

///credential-offer
router.get(["/offer"], async (req, res) => {
  // console.log("4 ROUTE ./offer CALLED!!!!!!");
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  sessions.push(uuid);
  issuanceResults.push({ sessionId: uuid, status: "pending" });
  console.log("active sessions");
  console.log(issuanceResults);
  // res.json({
  //   request: `openid-credential-offer://?credential_offer_uri=${serverURL}/credential-offer/${uuid}`,
  // });

  // generateGreOff...  offerUUID
  // itbSession.push({itbSession, offerUUID})

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

router.get(["/offer-code"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  sessions.push(uuid);
  issuanceResults.push({ sessionId: uuid, status: "pending" });
  console.log("active sessions");
  console.log(issuanceResults);
  // res.json({
  //   request: `openid-credential-offer://?credential_offer_uri=${serverURL}/credential-offer/${uuid}`,
  // });

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

export default router;
