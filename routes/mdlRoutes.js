import express from "express";
import { v4 as uuidv4 } from "uuid";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { generateNonce, buildVpRequestJWT } from "../utils/cryptoUtils.js";
import { storeVPSession, getVPSession } from "../services/cacheServiceRedis.js";
import fs from "fs";

const mdlRouter = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

// DCQL query for mDL
const dcql_query_mdl = {
  "credentials": [
    {
      "id": "mdl_credential",
      "format": "mso_mdoc",
      "meta": {
        "doctype_value": "org.iso.18013.5.1.mDL" 
      },
      "claims": [
        {"path": ["$.org.iso.18013.5.1.family_name"]},
        {"path": ["$.org.iso.18013.5.1.given_name"]},
        {"path": ["$.org.iso.18013.5.1.birth_date"]},
        {"path": ["$.org.iso.18013.5.1.issuance_date"]},
        {"path": ["$.org.iso.18013.5.1.expiry_date"]},
        {"path": ["$.org.iso.18013.5.1.issuing_country"]}
      ]
    }
  ]
};

// Load client metadata
const clientMetadata = JSON.parse(
  fs.readFileSync("./data/verifier-config.json", "utf-8")
);

// Standard VP Request with DCQL
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
      dcql_query: dcql_query_mdl,
      nonce: nonce,
      response_mode: responseMode
    });
  
    const requestUri = `${serverURL}/mdl/VPrequest/${uuid}`;  
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
mdlRouter.route("/VPrequest/:id") 
  .post(express.urlencoded({ extended: true }), async (req, res) => {
    const uuid = req.params.id;
    const { wallet_nonce, wallet_metadata } = req.body;
    if (wallet_nonce || wallet_metadata) {
      console.log(`Received from wallet: wallet_nonce=${wallet_nonce}, wallet_metadata=${wallet_metadata}`);
    }

    const result = await generateX509MDLVPRequest(uuid, clientMetadata, serverURL, wallet_nonce, wallet_metadata);

    if (result.error) {
      return res.status(result.status).json({ error: result.error });
    }
    res.type("application/oauth-authz-req+jwt").send(result.jwt);
  })
  .get(async (req, res) => { 
    const uuid = req.params.id;
    const result = await generateX509MDLVPRequest(uuid, clientMetadata, serverURL);

    if (result.error) {
      return res.status(result.status).json({ error: result.error });
    }
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
      null, // privateKey will be loaded in buildVpRequestJWT
      clientMetadata,
      null, // kid
      serverURL,
      "vp_token",
      vpSession.nonce,
      vpSession.dcql_query || null,
      vpSession.transaction_data || null,
      vpSession.response_mode, 
      undefined, 
      wallet_nonce,
      wallet_metadata,
      vpSession.verifier_attestations || null
    );
    return { jwt: vpRequestJWT, status: 200 };
  }

export default mdlRouter; 