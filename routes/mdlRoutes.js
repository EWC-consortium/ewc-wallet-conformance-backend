import express from "express";
import { v4 as uuidv4 } from "uuid";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { generateNonce } from "../utils/cryptoUtils.js";
import { buildVpRequestJWT } from "../utils/cryptoUtils.js";
import { storeVPSession } from "../services/cacheServiceRedis.js";
import { getSDsFromPresentationDef } from "../utils/vpHeplers.js";
import { getVPSession } from "../services/cacheServiceRedis.js";
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
    const client_id = "x509_san_dns:dss.aegean.gr";
  
    storeVPSession(uuid, {
      uuid: uuid,
      status: "pending",
      claims: null,
      presentation_definition: presentation_definition_mdl,
      nonce: nonce,
      sdsRequested: getSDsFromPresentationDef(presentation_definition_mdl),
      response_mode: responseMode
    });
  
    // Note: buildVpRequestJWT is called by the /x509/x509VPrequest/:id endpoint
    // So we don't need to call it here directly for the QR code generation step.
  
    const requestUri = `${serverURL}/mdl/VPrequest/${uuid}`;  
    // openid4vp:// URL without request_uri_method, defaulting to GET for request_uri
    const vpRequest = `openid4vp://?request_uri=${encodeURIComponent(
      requestUri
    )}&client_id=${encodeURIComponent(client_id)}`;
  
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




// Request URI endpoint (now handles POST and GET)
mdlRouter.route("/VPrequest/:id") // Corrected path to match client requests
  .post(express.urlencoded({ extended: true }), async (req, res) => {
    console.log("POST request received");
    const uuid = req.params.id;
    // As per OpenID4VP spec, wallet can post wallet_nonce and wallet_metadata
    const { wallet_nonce, wallet_metadata } = req.body;
    if (wallet_nonce || wallet_metadata) {
      console.log(`Received from wallet: wallet_nonce=${wallet_nonce}, wallet_metadata=${wallet_metadata}`);
    }

    const result = await generateX509MDLVPRequest(uuid, clientMetadata, serverURL, wallet_nonce, wallet_metadata);

    if (result.error) {
      return res.status(result.status).json({ error: result.error });
    }
    // For POST, the content type might differ based on wallet expectations
    // or specific protocol steps not detailed here.
    // Assuming JWT is expected directly for now.
    res.type("application/oauth-authz-req+jwt").send(result.jwt);
  })
  .get(async (req, res) => { // Added GET handler
    console.log("GET request received for mDL");
    const uuid = req.params.id;
    const result = await generateX509MDLVPRequest(uuid, clientMetadata, serverURL);

    if (result.error) {
      return res.status(result.status).json({ error: result.error });
    }
    // As per OpenID4VP, the request_uri should return the request object (JWT)
    // with content type application/oauth-authz-req+jwt
    console.log("result.jwt", result.jwt);
    res.type("application/oauth-authz-req+jwt").send(result.jwt);
  });



  async function generateX509MDLVPRequest(uuid, clientMetadata, serverURL, wallet_nonce, wallet_metadata) {
    const vpSession = await getVPSession(uuid);
  
    if (!vpSession) {
      return { error: "Invalid session ID", status: 400 };
    }
  
    const response_uri = `${serverURL}/direct_post/${uuid}`;
    const client_id = "x509_san_dns:dss.aegean.gr";
  
    
    const vpRequestJWT = await buildVpRequestJWT(
      client_id,
      response_uri,
      vpSession.presentation_definition_mdl,
      null, // privateKey
      clientMetadata,
      null, // kid
      serverURL,
      "vp_token",
      vpSession.nonce,
      vpSession.dcql_query || null,
      vpSession.transaction_data || null,
      vpSession.response_mode, // Pass response_mode from session
      undefined, // audience, to use default
      wallet_nonce,
      wallet_metadata
    );
    return { jwt: vpRequestJWT, status: 200 };
  }


export default mdlRouter; 