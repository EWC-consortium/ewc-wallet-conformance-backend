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

const jwks = pemToJWK(publicKeyPem, "public");

metadataRouter.get(
  "/.well-known/openid-credential-issuer",
  async (req, res) => {
    issuerConfig.credential_issuer = serverURL;
    issuerConfig.authorization_server = serverURL;
    issuerConfig.credential_endpoint = serverURL + "/credential";
    issuerConfig.deferred_credential_endpoint =
      serverURL + "/credential_deferred";

    res.type("application/json").send(issuerConfig);
  }
);

metadataRouter.get(
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

metadataRouter.get(["/", "/jwks"], (req, res) => {
  res.json({
    keys: [
      { ...jwks, kid: `aegean#authentication-key`, use: "sig" },
      { ...jwks, kid: `aegean#authentication-key`, use: "keyAgreement" }, //key to encrypt the sd-jwt response])
    ],
  });
});


export default metadataRouter;