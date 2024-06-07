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

const educationalRouter = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");

educationalRouter.get(["/pre-offer-jwt-edu"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const personaId = req.query.persona;
  const preSessions = getPreCodeSessions();
  if (preSessions.sessions.indexOf(uuid + "-persona=" + personaId) < 0) {
    preSessions.sessions.push(uuid + "-persona=" + personaId);
    preSessions.results.push({ sessionId: uuid, status: "pending" });
    preSessions.personas.push(null);
    preSessions.accessTokens.push(null);
  }
  let credentialOffer = "";
  if (personaId) {
    credentialOffer = `openid-credential-offer://?credential_offer_uri=${serverURL}/credential-offer-pre-jwt-edu/${uuid}?persona=${personaId}`; //OfferUUID
  } else {
    credentialOffer = `openid-credential-offer://?credential_offer_uri=${serverURL}/credential-offer-pre-jwt-edu/${uuid}`;
  }

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

educationalRouter.get(["/credential-offer-pre-jwt-edu/:id"], (req, res) => {
  let persona = req.query.persona;
  if (!persona) {
    res.json({
      credential_issuer: serverURL,
      credentials: ["EducationalID"],
      grants: {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
          "pre-authorized_code": req.params.id,
          user_pin_required: true,
        },
      },
    });
  } else {
    res.json({
      credential_issuer: serverURL,
      credentials: ["EducationalID"],
      grants: {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
          "pre-authorized_code": req.params.id + "-persona=" + persona,
          user_pin_required: true,
        },
      },
    });
  }
});

educationalRouter.get(["/pre-offer-jwt-alliance"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const preSessions = getPreCodeSessions();
  if (preSessions.sessions.indexOf(uuid) < 0) {
    preSessions.sessions.push(uuid);
    preSessions.results.push({ sessionId: uuid, status: "pending" });
  }
  let credentialOffer = `openid-credential-offer://?credential_offer_uri=${serverURL}/credential-offer-pre-jwt-alliance/${uuid}`;
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

educationalRouter.get(
  ["/credential-offer-pre-jwt-alliance/:id"],
  (req, res) => {
    res.json({
      credential_issuer: serverURL,
      credentials: ["allianceIDCredential"],
      grants: {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
          "pre-authorized_code": req.params.id,
          user_pin_required: true,
        },
      },
    });
  }
);

export default educationalRouter;
