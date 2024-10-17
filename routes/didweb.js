import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import { convertPemToJwk } from "../utils/didjwks.js";

const didWebRouter = express.Router();
const serverURL = process.env.SERVER_URL || "http://localhost:3000";
const proxyPath = process.env.PROXY_PATH || null;

didWebRouter.get(["/.well-known/did.json", "/.well-known/jwks.json"], async (req, res) => {
  let jwks = await convertPemToJwk();
  // console.log(jwks);
  let contorller = serverURL;
  if (proxyPath) {
    contorller = serverURL + ":" + proxyPath;
  }

  let didDoc = {
    "@context": "https://www.w3.org/ns/did/v1",
    id: `${contorller}`,
    verificationMethod: [
      {
        id: `${contorller}#keys-1`, //"did:web:example.com#keys-1",
        type: "JsonWebKey2020",
        controller: `${contorller}`,
        publicKeyJwk: jwks,
      },
    ],
    authentication: [`${contorller}#keys-1`],

    didResolutionMetadata: {
      contentType: "application/did+json",
    },
    didDocumentMetadata: {},
  };

  res.json(didDoc);
});

export default didWebRouter;
