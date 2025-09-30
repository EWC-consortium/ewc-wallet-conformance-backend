import express from "express";
import fs from "fs";
import { pemToJWK } from "../utils/cryptoUtils.js";
const metadataRouter = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");

const issuerConfig = JSON.parse(
  fs.readFileSync("./data/issuer-config.json", "utf-8")
);
const oauthConfig = JSON.parse(
  fs.readFileSync("./data/oauth-config.json", "utf-8")
);

// Load defaultSigningKid from issuer-config.json, similar to credGenerationUtils.js
let issuerConfigValues = {};
try {
  const issuerConfigRaw = fs.readFileSync("./data/issuer-config.json", "utf-8");
  issuerConfigValues = JSON.parse(issuerConfigRaw);
} catch (err) {
  console.warn("Could not load ./data/issuer-config.json for defaultSigningKid in metadataroutes, using defaults.", err);
}
const defaultSigningKid = issuerConfigValues.default_signing_kid || "aegean#authentication-key";

const jwks = pemToJWK(publicKeyPem, "public");


/**
 * Credential Issuer metadata
 */

metadataRouter.get(
  ["/.well-known/openid-credential-issuer",
  "/openid-credential-issuer/rfc-issuer"],
  async (req, res) => {
    issuerConfig.credential_issuer = serverURL;
    issuerConfig.authorization_servers = [serverURL];
    issuerConfig.credential_endpoint = serverURL + "/credential";
    issuerConfig.deferred_credential_endpoint =
      serverURL + "/credential_deferred";
    issuerConfig.nonce_endpoint = serverURL + "/nonce";
    issuerConfig.notification_endpoint = serverURL + "/notification";

    if (issuerConfig.batch_credential_endpoint) {
      console.warn("Warning: batch_credential_endpoint is part of issuerConfig but removed from spec draft -14. Consider removing from data/issuer-config.json");
    }

    res.type("application/json").send(issuerConfig);
  }
);

/**
 * Authorization Server Metadata
 */
metadataRouter.get(
  [
    "/.well-known/oauth-authorization-server",
    // "/.well-known/openid-configuration",
    "/oauth-authorization-server/rfc-issuer", //this is required in case the issuer is behind a reverse proxy: see https://www.rfc-editor.org/rfc/rfc8414.html
  ],
  async (req, res) => {
    oauthConfig.issuer = serverURL;
    oauthConfig.authorization_endpoint = serverURL + "/authorize";
    oauthConfig.pushed_authorization_request_endpoint = serverURL + "/par";
    oauthConfig.token_endpoint = serverURL + "/token_endpoint";
    oauthConfig.jwks_uri = serverURL + "/jwks";
    res.type("application/json").send(oauthConfig);
  }
);




metadataRouter.get(["/", "/jwks"], (req, res) => {
  res.json({
    keys: [
      { ...jwks, kid: defaultSigningKid, use: "sig" },
      { ...jwks, kid: `${defaultSigningKid}-agreement`, use: "keyAgreement" },
    ],
  });
});


/*
*If the iss value contains a path component, any terminating / MUST 
be removed before inserting /.well-known/ and the well-known URI suffix between the host component and the path component.
*/
metadataRouter.get(
  ["/.well-known/jwt-vc-issuer", "/.well-known/jwt-vc-issuer/rfc-issuer", "/jwt-vc-issuer/rfc-issuer"  ],
  
  /*
  issuer:  REQUIRED. The Issuer identifier, which MUST be identical to the iss value in the JWT. 
  jwks_uri: OPTIONAL. URL string referencing the Issuer's JSON Web Key (JWK) Set [RFC7517] 
document which contains the Issuer's public keys. The value of this field MUST point to a valid JWK Set document.
  jwks : OPTIONAL. Issuer's JSON Web Key Set [RFC7517] document value, 
which contains the Issuer's public keys. The value of this field MUST be a JSON object containing a valid JWK Set.
  */
  
  async (req, res) => {
    const metadata ={
      issuer: serverURL,
      jwks : {
        keys: [
          { ...jwks, kid: defaultSigningKid, use: "sig" },
          { ...jwks, kid: `${defaultSigningKid}-agreement`, use: "keyAgreement" },
        ]
      }

    }

    res.type("application/json").send(metadata);
  }
);



export default metadataRouter;