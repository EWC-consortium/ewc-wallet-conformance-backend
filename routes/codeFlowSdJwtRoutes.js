import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import { getAuthCodeSessions } from "../services/cacheService.js";

import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";

const codeFlowRouterSDJWT = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";



// auth code flow
codeFlowRouterSDJWT.get(["/offer-code-sd-jwt"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const codeSessions = getAuthCodeSessions();
  if (codeSessions.sessions.indexOf(uuid) < 0) {
    codeSessions.sessions.push(uuid);
    codeSessions.results.push({ sessionId: uuid, status: "pending" });
  }
  let credentialOffer = `openid-credential-offer://?credential_offer_uri=${serverURL}/credential-offer-code-sd-jwt/${uuid}`;

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
codeFlowRouterSDJWT.get(["/credential-offer-code-sd-jwt/:id"], (req, res) => {
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

export default codeFlowRouterSDJWT;
