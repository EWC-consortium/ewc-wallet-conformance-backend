import express from "express";
import { v4 as uuidv4 } from "uuid";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { generateNonce } from "../utils/cryptoUtils.js";
import { buildVpRequestJWT } from "../utils/cryptoUtils.js";
import { storeVPSession } from "../services/cacheServiceRedis.js";
import { getSDsFromPresentationDef } from "../utils/vpHeplers.js";
import fs from "fs";

const mdlRouter = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

// Load presentation definitions
const presentation_definition_mdl = JSON.parse(
  fs.readFileSync("./data/presentation_definition_mdl.json", "utf-8")
);

// Load client metadata
const clientMetadata = JSON.parse(
  fs.readFileSync("./data/verifier-config.json", "utf-8")
);

// Standard VP Request with presentation_definition
mdlRouter.get("/generateVPRequest", async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const responseMode = req.query.response_mode || "direct_post";
  const nonce = generateNonce(16);

  const response_uri = `${serverURL}/direct_post/${uuid}`;
  const client_id = "mdl-verifier";

  // Store session data
  storeVPSession(uuid, {
    uuid: uuid,
    status: "pending",
    claims: null,
    presentation_definition: presentation_definition_mdl,
    nonce: nonce,
    sdsRequested: getSDsFromPresentationDef(presentation_definition_mdl),
    response_mode: responseMode // Store response mode in session
  });

  const requestUri = `${serverURL}/mdl/mdlVPRequest/${uuid}`;
  
  // For mDL, the request is not a JWT, so we don't build a vpRequestJWT here.
  // The openid4vp:// URL will contain the request by value.

  const vpRequest = `openid4vp://?response_uri=${encodeURIComponent(response_uri)}&response_mode=${responseMode}&presentation_definition=${encodeURIComponent(JSON.stringify(presentation_definition_mdl))}&client_id=${encodeURIComponent(client_id)}&nonce=${nonce}`;

  // Generate QR code
  let code = qr.image(vpRequest, {
    type: "png",
    ec_level: "M",
    size: 20,
    margin: 10,
  });
  let mediaType = "PNG";
  let encodedQR = imageDataURI.encode(await streamToBuffer(code), mediaType);
  
  res.json({
    qr: encodedQR,
    deepLink: vpRequest,
    sessionId: uuid,
  });
});

export default mdlRouter; 