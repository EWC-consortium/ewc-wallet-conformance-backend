import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import { pemToJWK, generateNonce } from "./utils/cryptoUtils.js";
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

router.get("/.well-known/openid-credential-issuer", async (req, res) => {
  // console.log("1 ROUTE /.well-known/openid-credential-issuer CALLED!!!!!!");
  // issuerConfig.authorization_servers = [serverURL];
  issuerConfig.credential_issuer = serverURL;
  issuerConfig.authorization_servers = [serverURL];
  issuerConfig.credential_endpoint = serverURL + "/credential";
  issuerConfig.deferred_credential_endpoint =
    serverURL + "/credential_deferred";

  res.type("application/json").send(issuerConfig);
});

router.get(
  [
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
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
  res.json({ keys: jwks });
});

///credential-offer
router.get(["/offer"], async (req, res) => {
  console.log("4 ROUTE ./offer CALLED!!!!!!");
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  sessions.push(uuid);
  issuanceResults.push({ sessionId: uuid, status: "pending" });
  // res.json({
  //   request: `openid-credential-offer://?credential_offer_uri=${serverURL}/credential-offer/${uuid}`,
  // });

  let credentialOffer = `openid-credential-offer://?credential_offer_uri=${serverURL}/credential-offer/${uuid}`;

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

router.get(["/credential-offer/:id"], (req, res) => {
  // console.log("5 ROUTE ./credential-offer CALLED!!!!!!");
  // console.log(`id ${req.params.id}`);

  //TODO assosiate the code with the credential offer

  res.json({
    credential_issuer: serverURL,
    credentials: ["VerifiablePortableDocumentA1"],
    grants: {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": "adhjhdjajkdk1hjhdj",
        user_pin_required: true,
      },
    },
  });
});

router.post("/token_endpoint", async (req, res) => {
  // console.log("6 ROUTE /token_endpoint CALLED!!!!!!");
  const grantType = req.body.grant_type;
  const preAuthorizedCode = req.body.pre_authorized_code;
  const userPin = req.body.user_pin;

  let index = sessions.indexOf(preAuthorizedCode);
  if (index > 0) {
    sessions.splice(index, 1);
    issuanceResults[index].status = "completed";
  }

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
  let index = sessions.indexOf(sessionId);
  let status = issuanceResults[index].status;

  res.json({
    status: status,
    reason: "ok",
    sessionId: sessionId,
  });
});

export default router;
