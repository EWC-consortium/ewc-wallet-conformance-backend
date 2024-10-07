import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import { generateNonce, buildVpRequestJSON } from "../utils/cryptoUtils.js";

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





export function updateIssuerStateWithAuthCode(
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
