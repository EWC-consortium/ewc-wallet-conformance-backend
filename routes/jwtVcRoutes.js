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

import {
  getAuthCodeSessions,
  getPreCodeSessions,
} from "../services/cacheService.js";

import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import {
  createSignerVerifier,
  digest,
  generateSalt,
} from "../utils/sdjwtUtils.js";
import jwt from "jsonwebtoken";

import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { request } from "http";

const router = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");

 

 

// ***************
///pre-auth flow jwt_vc_json
router.get(["/pre-offer-jwt"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const preSessions = getPreCodeSessions();
  if (preSessions.sessions.indexOf(uuid) < 0) {
    preSessions.sessions.push(uuid);
    preSessions.results.push({ sessionId: uuid, status: "pending" });
  }
  let credentialOffer = `openid-credential-offer://?credential_offer_uri=${serverURL}/credential-offer-pre-jwt/${uuid}`; //OfferUUID
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

 

function getPersonaPart(inputString) {
  const personaKey = "persona=";
  const personaIndex = inputString.indexOf(personaKey);

  if (personaIndex === -1) {
    return null; // "persona=" not found in the string
  }

  // Split the string based on "persona="
  const parts = inputString.split(personaKey);

  // Return the part after "persona="
  return parts[1] || null;
}



 

export default router;
