import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import {
  pemToJWK,
  generateNonce,
  decryptJWE,
  buildVpRequestJwt,
} from "../utils/cryptoUtils.js";
import { decodeSdJwt, getClaims } from "@sd-jwt/decode";
import { digest } from "@sd-jwt/crypto-nodejs";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";

const verifierRouter = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");

const presentation_definition = JSON.parse(
  fs.readFileSync("./data/presentation_definition.json", "utf-8")
);
const jwks = pemToJWK(publicKeyPem, "public");

let verificationSessions = []; //TODO these should be redis or something a proper cache...
let sessions = [];

verifierRouter.get("/generateVPRequest", async (req, res) => {
  const stateParam = req.query.id ? req.query.id : uuidv4();
  const nonce = generateNonce(16);

  let request_uri = serverURL + "/vpRequest/" + stateParam;
  const response_uri = serverURL + "/direct_post"; //not used

  const vpRequest = buildVP(
    serverURL,
    response_uri,
    request_uri,
    stateParam,
    nonce,
    encodeURIComponent(JSON.stringify(presentation_definition))
  );

  let code = qr.image(vpRequest, {
    type: "png",
    ec_level: "H",
    size: 10,
    margin: 10,
  });
  let mediaType = "PNG";
  let encodedQR = imageDataURI.encode(await streamToBuffer(code), mediaType);
  res.json({
    qr: encodedQR,
    deepLink: vpRequest,
    sessionId: stateParam,
  });

  // res.json({ vpRequest: vpRequest });
});

verifierRouter.get("/vpRequest/:id", async (req, res) => {
  console.log("VPRequest called Will send JWT");
  // console.log(jwtToken);
  const uuid = req.params.id ? req.params.id : uuidv4();

  //url.searchParams.get("presentation_definition");
  const stateParam = uuidv4();
  const nonce = generateNonce(16);

  const response_uri = serverURL + "/direct_post" + "/" + uuid;
  let clientId = serverURL + "/direct_post" + "/" + uuid;
  sessions.push(uuid);
  verificationSessions.push({
    uuid: uuid,
    status: "pending",
    claims: null,
  });

  let jwtToken = buildVpRequestJwt(
    stateParam,
    nonce,
    clientId,
    response_uri,
    presentation_definition,
    jwks,
    serverURL,
    privateKey
  );
  res.type("text/plain").send(jwtToken);
});

verifierRouter.post("/direct_post/:id", async (req, res) => {
  console.log("direct_post VP is below!");
  const sessionId = req.params.id;

  let sdjwt = req.body["vp_token"];
  if (sdjwt) {
    let presentationSubmission = req.body["presentation_submission"];
    let state = req.body["state"];
    console.log(state);
    // console.log(response);
    const decodedSdJwt = await decodeSdJwt(sdjwt, digest);
    const claims = await getClaims(
      decodedSdJwt.jwt.payload,
      decodedSdJwt.disclosures,
      digest
    );
    console.log(claims);
    let index = sessions.indexOf(sessionId);
    console.log("index is");
    console.log(index);
    if (index >= 0) {
      verificationSessions[index].status = "success";
      verificationSessions[index].claims = claims;
      console.log(`verificatiton success`);
      console.log(verificationSessions[index]);
    }
    res.sendStatus(200);
  } else {
    res.sendStatus(500);
  }
});











verifierRouter.get(["/verificationStatus"], (req, res) => {
  let sessionId = req.query.sessionId;
  let index = sessions.indexOf(sessionId);
  console.log("index is");
  console.log(index);
  let result = null;
  if (index >= 0) {
    let status = verificationSessions[index].status;
    console.log(`sending status ${status} for session ${sessionId}`);
    if (status === "success") {
      result = verificationSessions[index].claims;
      sessions.splice(index, 1);
      verificationSessions.splice(index, 1);
    }
    // console.log(`new sessions`);
    // console.log(sessions);
    // console.log("new session statuses");
    // console.log(issuanceResults);
    res.json({
      status: status,
      reason: "ok",
      sessionId: sessionId,
      claims: result,
    });
  } else {
    res.json({
      status: "failed",
      reason: "not found",
      sessionId: sessionId,
    });
  }
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
    // "&response_type=vp_token" +
    // "&scope=openid" +
    // "&redirect_uri=" +
    // encodeURIComponent(redirect_uri) +
    "&request_uri=" +
    encodeURIComponent(request_uri);
  // "&response_uri=" +
  // encodeURIComponent(redirect_uri) +
  // "&response_mode=direct_post" +
  // "&state=" +
  // state +
  // "&nonce=" +
  // nonce
  // "&presentation_definition_uri="+ngrok+"/presentation_definition"
  // +
  // "&presentation_definition=" +
  // presentation_definition;

  return result;
}

export default verifierRouter;
