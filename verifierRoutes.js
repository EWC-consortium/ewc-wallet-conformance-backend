import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import {
  pemToJWK,
  generateNonce,
  decryptJWE,
  buildVpRequestJwt,
} from "./utils/cryptoUtils.js";
import { decodeSdJwt, getClaims } from "@sd-jwt/decode";
import { digest } from "@sd-jwt/crypto-nodejs";

const verifierRouter = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");

// console.log("privateKey");
// console.log(privateKey);

const issuerConfig = JSON.parse(
  fs.readFileSync("./data/issuer-config.json", "utf-8")
);
const oauthConfig = JSON.parse(
  fs.readFileSync("./data/oauth-config.json", "utf-8")
);

const presentation_definition = JSON.parse(
  fs.readFileSync("./data/presentation_definition.json", "utf-8")
);
const jwks = pemToJWK(publicKeyPem, "public");

verifierRouter.get("/makeVP", async (req, res) => {
  const uuid = uuidv4();
  const stateParam = uuidv4();
  const nonce = generateNonce(16);

  let request_uri = serverURL + "/vpRequest";
  const response_uri = serverURL + "/direct_post";

  const vpRequest = buildVP(
    serverURL,
    response_uri,
    request_uri,
    stateParam,
    nonce,
    encodeURIComponent(JSON.stringify(presentation_definition))
  );

  res.json({ vpRequest: vpRequest });
});

verifierRouter.get("/vpRequest", async (req, res) => {
  console.log("VPRequest called Will send JWT");
  // console.log(jwtToken);
  const uuid = uuidv4();

  //url.searchParams.get("presentation_definition");
  const stateParam = uuidv4();
  const nonce = generateNonce(16);

  let request_uri = serverURL + "/vpRequest";
  const response_uri = serverURL + "/direct_post";

  let jwtToken = buildVpRequestJwt(
    stateParam,
    nonce,
    serverURL + "/direct_post",
    serverURL + "/direct_post",
    presentation_definition,
    jwks,
    serverURL,
    privateKey
  );
  res.type("text/plain").send(jwtToken);
});


verifierRouter.post("/direct_post", async (req, res) => {
  console.log("direct_post VP is below!");

  let sdjwt = req.body["vp_token"];
  let presentationSubmission = req.body["presentation_submission"];
  let state = req.body["state"];
  console.log(state)
  // console.log(response);
  const decodedSdJwt = await decodeSdJwt(sdjwt, digest);
  console.log("The decoded SD JWT is:");
  console.log(JSON.stringify(decodedSdJwt, null, 2));
  console.log(
    "================================================================"
  );
  // Get the claims from the SD JWT
  const claims = await getClaims(
    decodedSdJwt.jwt.payload,
    decodedSdJwt.disclosures,
    digest
  );

  res.sendStatus(200);
});


function buildVP(
  client_id,
  redirect_uri,
  request_uri,
  state,
  nonce,
  presentation_definition
) {
  let result =
    "openid4vp://?client_id=" +
    encodeURIComponent(client_id) +
    "&response_type=vp_token" +
    "&scope=openid" +
    "&redirect_uri=" +
    encodeURIComponent(redirect_uri) +
    "&request_uri=" +
    encodeURIComponent(request_uri) +
    "&response_uri=" +
    encodeURIComponent(redirect_uri) +
    "&response_mode=direct_post" +
    "&state=" +
    state +
    "&nonce=" +
    nonce +
    // "&presentation_definition_uri="+ngrok+"/presentation_definition"
    // +
    "&presentation_definition=" +
    presentation_definition;

  return result;
}

export default verifierRouter;
