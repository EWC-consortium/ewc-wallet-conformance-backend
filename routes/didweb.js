import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import { convertPemToJwk } from "../utils/didjwks.js";

const didWebRouter = express.Router();
const serverURL = process.env.SERVER_URL || "http://localhost:3000";
const proxyPath = process.env.PROXY_PATH || null;

didWebRouter.get(["/.well-known/did.json","/did.json"], async (req, res) => {
  let jwks = await convertPemToJwk();
  // console.log(jwks);
  let contorller = serverURL;
  let serviceURL = serverURL
  if (proxyPath) {
    contorller = serverURL.replace("/"+proxyPath,"") + ":" + proxyPath;
    serviceURL = serverURL //+ "/" + proxyPath;
  }
  
  contorller = contorller.replace("https://","")
  let didDoc = {
    "@context": "https://www.w3.org/ns/did/v1",
    id: `did:web:${contorller}`,
    verificationMethod: [
      {
        id: `did:web:${contorller}#keys-1`, //"did:web:example.com#keys-1",
        type: "JsonWebKey2020",
        controller: `${contorller}`,
        publicKeyJwk: jwks,
      },
    ],
    authentication: [`${contorller}#keys-1`],

    service: [
      {
        id: `did:web:${contorller}#jwks`,
        type: "JsonWebKey2020",
        serviceEndpoint: `${serviceURL}/.well-known/jwks.json`,
      },
    ],
  };

  res.json(didDoc);
});

didWebRouter.get(["/.well-known/jwks.json"], async (req, res) => {
  let contorller = serverURL;
  if (proxyPath) {
    contorller = serverURL.replace("/"+proxyPath,"") + ":" + proxyPath;
  }
  contorller = contorller.replace("https://","")
  let jwks = await convertPemToJwk();
  let result = {
    keys: [{ ...jwks, use: "sig", kid: `${contorller}#keys-1` }],
  };

  res.json(result);
});

export default didWebRouter;
