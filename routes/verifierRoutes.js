import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import {
  pemToJWK,
  generateNonce,
  decryptJWE,
  buildVpRequestJSON,
  buildVpRequestJWT,
} from "../utils/cryptoUtils.js";

import {
  extractClaimsFromRequest,
  hasOnlyAllowedFields,
  getSDsFromPresentationDef,
} from "../utils/vpHeplers.js";

import { buildVPbyValue } from "../utils/tokenUtils.js";
import { decodeSdJwt, getClaims } from "@sd-jwt/decode";
import { digest } from "@sd-jwt/crypto-nodejs";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import jwt from "jsonwebtoken";
import TimedArray from "../utils/timedArray.js";

import { getVPSession, storeVPSession } from "../services/cacheServiceRedis.js";
import redirectUriRouter from "./redirectUriRoutes.js";
import x509Router from "./x509Routes.js";
import didRouter from "./didRoutes.js";
import didJwkRouter from "./didJwkRoutes.js";

const verifierRouter = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";
const proxyPath = process.env.PROXY_PATH || null;

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");

const presentation_definition_sdJwt = JSON.parse(
  fs.readFileSync("./data/presentation_definition_sdjwt.json", "utf-8")
);

const presentation_definition_amadeus = JSON.parse(
  fs.readFileSync("./data/presentation_definition_amadeus.json", "utf-8")
);

const presentation_definition_cff = JSON.parse(
  fs.readFileSync("./data/presentation_definition_cff.json", "utf-8")
);

//
const presentation_definition_sicpa = JSON.parse(
  fs.readFileSync("./data/presentation_definition_sicpa.json", "utf-8")
);

const presentation_definition_jwt = JSON.parse(
  fs.readFileSync("./data/presentation_definition_jwt.json", "utf-8")
);

const presentation_definition_pid = JSON.parse(
  fs.readFileSync("./data/presentation_definition_pid.json", "utf-8")
);
const presentation_definition_epass = JSON.parse(
  fs.readFileSync("./data/presentation_definition_epass.json", "utf-8")
);
const presentation_definition_educational_id = JSON.parse(
  fs.readFileSync("./data/presentation_definition_education_id.json", "utf-8")
);
const presentation_definition_alliance_id = JSON.parse(
  fs.readFileSync("./data/presentation_definition_alliance_id.json", "utf-8")
);

const presentation_definition_ferryboardingpass = JSON.parse(
  fs.readFileSync(
    "./data/presentation_definition_ferryboardingpass.json",
    "utf-8"
  )
);
const presentation_definition_photoId_or_pid_and_studentID = JSON.parse(
  fs.readFileSync(
    "./data/presentation_definition_alliance_and_education_Id.json",
    "utf-8"
  )
);
const presentation_definition_photo_or_pid_and_std = JSON.parse(
  fs.readFileSync(
    "./data/presentation_definition_photo_or_pid_and_std.json",
    "utf-8"
  )
);

const client_metadata = JSON.parse(
  fs.readFileSync("./data/verifier-config.json", "utf-8")
);

const presentation_definition_alliance_and_education_Id = JSON.parse(
  fs.readFileSync(
    "./data/presentation_definition_alliance_and_education_Id.json",
    "utf-8"
  )
);
//
const clientMetadata = JSON.parse(
  fs.readFileSync("./data/verifier-config.json", "utf-8")
);

const jwks = pemToJWK(publicKeyPem, "public");

let verificationSessions = []; //TODO these should be redis or something a proper cache...
let sessions = [];
let sessionHistory = new TimedArray(30000); //cache data for 30sec
let verificationResultsHistory = new TimedArray(30000); //cache data for 30sec



/* *****************************************  
      AUTHIORIZATION REQUESTS
/*************************************** */

/*  *******************************************************
  using : CLIENT_ID_SCHEME_REDIRECT_URI
  request by  value 
*********************************************************** */
// Use the redirect_uri specific router
verifierRouter.use("/redirect-uri", redirectUriRouter);


/*  *******************************************************
  using : CLIENT_ID_SCHEME x509_dns_san
  request by referance and JAR
*********************************************************** */
// Use the x509 specific router
verifierRouter.use("/x509", x509Router);

/*  *******************************************************
  using : CLIENT_ID_SCHEME did:web
  request by referance and JAR
*********************************************************** */
// Use the did specific router for did:web
verifierRouter.use("/did", didRouter);

/*  *******************************************************
  using : CLIENT_ID_SCHEME did:jwk
  request by referance and JAR
*********************************************************** */
// Use the did:jwk specific router
verifierRouter.use("/did-jwk", didJwkRouter);




/* ********************************************
         Authorization RESPONSES
*******************************************/

verifierRouter.post("/direct_post/:id", async (req, res) => {
  try {
    const sessionId = req.params.id;
    const vpSession = await getVPSession(sessionId);
    
    if (!vpSession) {
      console.warn(`Session ID ${sessionId} not found.`);
      return res.status(400).json({ error: `Session ID ${sessionId} not found.` });
    }

    // Handle direct_post.jwt response mode
    // The response is a signed JWT containing the VP token
    // The JWT signature provides an additional layer of security
    // Format: {
    //   "iss": "wallet_identifier", 
    //   "aud": "verifier_id",
    //   "iat": timestamp,
    //   "vp_token": "verifiable_presentation_jwt_or_sd_jwt"
    // }
    console.log("response mode" + vpSession.response_mode);
    let claimsFromExtraction;
    let jwtFromKeybind;

    if (vpSession. response_mode === 'direct_post.jwt') {
      const jwtResponse = req.body;
      try {
        // Verify the JWT signature
        const decodedJWT = jwt.verify(jwtResponse, publicKeyPem, { algorithms: ['ES256'] });
        
        // Extract VP token from the JWT payload
        const vpToken = decodedJWT.vp_token;
        if (!vpToken) {
          return res.status(400).json({ error: "No VP token in JWT response" });
        }

        // Process the VP token as before
        const result = await extractClaimsFromRequest({ body: { vp_token: vpToken } }, digest);
        claimsFromExtraction = result.extractedClaims;
        jwtFromKeybind = result.keybindJwt;


        // Verify nonce
        let submittedNonce;
        if (jwtFromKeybind && jwtFromKeybind.payload) {
          submittedNonce = jwtFromKeybind.payload.nonce;
        } else {
          let decodedVpToken = jwt.decode(vpToken, { complete: true });
          if (decodedVpToken && decodedVpToken.payload) {
            submittedNonce = decodedVpToken.payload.nonce;
          }
        }

        if (!submittedNonce) {
          return res.status(400).json({ error: "submitted nonce not found in vp_token" });
        }
        
        if (vpSession.nonce != submittedNonce) {
          console.log(`error nonces do not match ${submittedNonce} ${vpSession.nonce}`);
          return res.status(400).json({ error: "submitted nonce doesn't match the auth request one" });
        }

        // Process claims as before
        if (vpSession.sdsRequested && !hasOnlyAllowedFields(claimsFromExtraction, vpSession.sdsRequested)) {
          return res.status(400).json({
            error: "requested " + JSON.stringify(vpSession.sdsRequested) + "but received " + JSON.stringify(claimsFromExtraction),
          });
        }

        vpSession.status = "success";
        vpSession.claims = { ...claimsFromExtraction };
        storeVPSession(sessionId, vpSession);
        return res.status(200).json({ status: "ok" });

      } catch (error) {
        console.error("Error processing JWT response:", error);
        return res.status(400).json({ error: "Invalid JWT response" });
      }
    } 
    // Handle regular direct_post response mode
    else {
     

      try {
        const result = await extractClaimsFromRequest(req, digest);
        claimsFromExtraction = result.extractedClaims;
        jwtFromKeybind = result.keybindJwt;
      }catch(error){
        console.error("Error processing direct_post response:", error);
        return res.status(400).json({ error: error.message });
      }
      const vpToken = req.body["vp_token"];

      // Verify nonce
      let submittedNonce;
      if (jwtFromKeybind && jwtFromKeybind.payload) {
        // If a key-binding JWT was extracted, this is an SD-JWT presentation.
        // The nonce MUST be taken from the key-binding JWT.
        submittedNonce = jwtFromKeybind.payload.nonce;
      } else {
        // For regular JWT-based VPs
        const decodedVpToken = jwt.decode(vpToken, { complete: true });
        if (decodedVpToken && decodedVpToken.payload) {
          submittedNonce = decodedVpToken.payload.nonce;
        }
      }

      if (!submittedNonce) {
        return res.status(400).json({ error: "submitted nonce not found in vp_token" });
      }

      if (vpSession.nonce != submittedNonce) {
        console.log(`error nonces do not match ${submittedNonce} ${vpSession.nonce}`);
        return res.status(400).json({ error: "submitted nonce doesn't match the auth request one" });
      }

      if (vpSession.sdsRequested && !hasOnlyAllowedFields(claimsFromExtraction, vpSession.sdsRequested)) {
        return res.status(400).json({
          error: "requested " + JSON.stringify(vpSession.sdsRequested) + "but received " + JSON.stringify(claimsFromExtraction),
        });
      }

      vpSession.status = "success";
      vpSession.claims = { ...claimsFromExtraction };
      storeVPSession(sessionId, vpSession);
      console.log(`vp session ${sessionId} status is success`);
      return res.status(200).json({ status: "ok" });
    }
  } catch (error) {
    console.error("Error processing request:", error.message);
    return res.status(400).json({ error: error.message });
  }
});

 



/* *******************************************************
    HELPERS 
*/
verifierRouter.get("/generateVPRequest-jwt", async (req, res) => {
  const stateParam = req.query.id ? req.query.id : uuidv4();
  const nonce = generateNonce(16);

  let request_uri = serverURL + "/vpRequestJwt/" + stateParam;
  const response_uri = serverURL + "/direct_post_jwt"; //not used

  const vpRequest = buildVP(
    serverURL,
    response_uri,
    request_uri,
    stateParam,
    nonce,
    encodeURIComponent(JSON.stringify(presentation_definition_jwt))
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

verifierRouter.get("/vpRequestJwt/:id", async (req, res) => {
  const uuid = req.params.id ? req.params.id : uuidv4();
  //url.searchParams.get("presentation_definition");
  const stateParam = uuidv4();
  const nonce = generateNonce(16);

  const response_uri = serverURL + "/direct_post_jwt" + "/" + uuid;
  let clientId = serverURL + "/direct_post_jwt" + "/" + uuid;
  sessions.push(uuid);
  verificationSessions.push({
    uuid: uuid,
    status: "pending",
    claims: null,
  });

  clientMetadata.presentation_definition_uri =
    serverURL + "/presentation-definition/1";
  clientMetadata.redirect_uris = [response_uri];
  clientMetadata.client_id = clientId;

  let vpRequest = {
    client_id: clientId,
    client_id_scheme: "redirect_uri",
    response_uri: response_uri,
    response_type: "vp_token",
    response_mode: "direct_post",
    presentation_definition: presentation_definition_jwt,
    nonce: nonce,
    state: uuid,
  };

  // console.log("will send vpRequest");
  // console.log(vpRequest);

  res.json(vpRequest);
});

// *******************PILOT USE CASES ******************************
verifierRouter.get("/vp-request/:type", async (req, res) => {
  const { type } = req.params;
  const stateParam = req.query.id ? req.query.id : uuidv4();
  const nonce = generateNonce(16);

  let request_uri = `${serverURL}/vpRequest/${type}/${stateParam}`;
  const response_uri = `${serverURL}/direct_post_jwt`; // not used

  const vpRequest = buildVP(
    serverURL,
    response_uri,
    request_uri,
    stateParam,
    nonce,
    null
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
});

verifierRouter.get("/vpRequest/:type/:id", async (req, res) => {
  const { type, id } = req.params;
  const uuid = id ? id : uuidv4();
  const stateParam = uuidv4();
  const nonce = generateNonce(16);

  const response_uri = `${serverURL}/direct_post_jwt/${uuid}`;
  let clientId = `${serverURL}/direct_post_jwt/${uuid}`;
  sessions.push(uuid);
  verificationSessions.push({
    uuid: uuid,
    status: "pending",
    claims: null,
  });

  let presentationDefinition;
  if (type === "pid") {
    presentationDefinition = presentation_definition_pid;
  } else if (type === "epassport") {
    presentationDefinition = presentation_definition_epass;
  } else if (type === "educationId" || type === "educationid") {
    presentationDefinition = presentation_definition_educational_id;
  } else if (type === "allianceId" || type === "allianceid") {
    presentationDefinition = presentation_definition_alliance_id;
  } else if (type === "ferryboardingpass") {
    presentationDefinition = presentation_definition_ferryboardingpass;
  } else if (type === "erua-id") {
    presentationDefinition = presentation_definition_alliance_and_education_Id;
  } else if (type === "cff") {
    presentationDefinition = presentation_definition_cff;
  } else {
    return res.status(400).type("text/plain").send("Invalid type parameter");
  }

  const vpRequestJWT = await buildVpRequestJWT(
    clientId,
    response_uri,
    presentationDefinition,
    null, // privateKey will be loaded in buildVpRequestJWT
    "redirect_uri", // client_id_scheme
    client_metadata,
    null, // kid
    serverURL, // issuer
    "vp_token", // response_type
    nonce,
    null, // dcql_query
    null, // transaction_data
    "direct_post" // response_mode
  );
  
  res.type("application/oauth-authz-req+jwt").send(vpRequestJWT);
});

verifierRouter.post("/direct_post_jwt/:id", async (req, res) => {
  const sessionId = req.params.id;
  const jwtVp = req.body.vp_token;
  // Log received request
  console.log("Received direct_post VP for session:", sessionId);
  if (!jwtVp) {
    console.error("No VP token provided.");
    return res.sendStatus(400); // Bad Request
  }
  let decodedWithHeader;
  try {
    decodedWithHeader = jwt.decode(jwtVp, { complete: true });
  } catch (error) {
    console.error("Failed to decode JWT:", error);
    return res.sendStatus(400); // Bad Request due to invalid JWT
  }
  const credentialsJwtArray =
    decodedWithHeader?.payload?.vp?.verifiableCredential;
  if (!credentialsJwtArray) {
    console.error("Invalid JWT structure.");
    return res.sendStatus(400); // Bad Request
  }
  // Convert credentials to claims
  let claims;
  try {
    console.log(credentialsJwtArray);
    claims = await flattenCredentialsToClaims(credentialsJwtArray);
    console.log(claims);
    if (!claims) {
      throw new Error("Claims conversion returned null or undefined.");
    }
  } catch (error) {
    console.error("Error processing claims:", error);
    return res.sendStatus(500); // Internal Server Error
  }
  // Update session status
  const index = sessions.indexOf(sessionId);
  console.log("Session index:", index);
  if (index === -1) {
    console.error("Session ID not found.");
    return res.sendStatus(404); // Not Found
  }
  // Log successful verification
  verificationSessions[index].status = "success";
  verificationSessions[index].claims = claims;
  console.log("Verification success:", verificationSessions[index]);
  res.sendStatus(200); // OK
});

verifierRouter.get(["/verificationStatus"], async (req, res) => {
  let sessionId = req.query.sessionId;
  // let index = sessions.indexOf(sessionId); // sessions.indexOf(sessionId+""); //
  const vpSession = await getVPSession(sessionId);

  // console.log("index is");
  // console.log(index);
  let result = null;
  if (vpSession) {
    let status = vpSession.status;
    console.log(`sending status ${status} for session ${sessionId}`);
    if (status === "success") {
      result = vpSession.claims;
      // sessions.splice(index, 1);
      // verificationSessions.splice(index, 1);
      // sessionHistory.addElement(sessionId);
      // verificationResultsHistory.addElement(result);
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

verifierRouter.get(["/verificationStatusHistory"], async (req, res) => {
  let sessionId = req.query.sessionId;
  const vpSession = await getVPSession(sessionId);
  // let index = sessionHistory.getCurrentArray().indexOf(sessionId);
  if (vpSession) {
    res.json(vpSession);
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

async function flattenCredentialsToClaims(credentials) {
  let claimsResult = {};
  credentials.forEach((credentialJwt) => {
    let decodedCredential = jwt.decode(credentialJwt, {
      complete: true,
    });
    if (decodedCredential) {
      let claims = decodedCredential.payload.vc.credentialSubject;
      console.log(claims);
      claimsResult = { ...claimsResult, ...claims };
    }
  });
  return claimsResult;
}

function getPresentationDefinitionFromCredType(type) {
  let presentationDefinition;
  if (type === "pid") {
    presentationDefinition = presentation_definition_pid;
  } else if (type === "epassport") {
    presentationDefinition = presentation_definition_epass;
  } else if (type === "educationId" || type === "educationid") {
    presentationDefinition = presentation_definition_educational_id;
  } else if (type === "allianceId" || type === "allianceid") {
    presentationDefinition = presentation_definition_alliance_id;
  } else if (type === "ferryboardingpass") {
    presentationDefinition = presentation_definition_ferryboardingpass;
  } else if (type === "erua-id") {
    presentationDefinition = presentation_definition_alliance_and_education_Id;
  } else if (
    type === "itbsdjwt" ||
    type === "VerifiablePortableDocumentA1SDJWT" ||
    type == "VerifiablePIDSDJWT"
  ) {
    presentationDefinition = presentation_definition_sdJwt;
  } else if (type === "amadeus") {
    presentationDefinition = presentation_definition_amadeus;
  } else if (type === "beni") {
    presentationDefinition = presentation_definition_sicpa;
  } else if (type === "cff") {
    presentationDefinition = presentation_definition_cff;
  } else {
    return null;
  }

  return presentationDefinition;
}


export default verifierRouter;
