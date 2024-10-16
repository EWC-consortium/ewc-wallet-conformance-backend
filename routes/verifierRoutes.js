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

import { buildVPbyValue } from "../utils/tokenUtils.js";
import { decodeSdJwt, getClaims } from "@sd-jwt/decode";
import { digest } from "@sd-jwt/crypto-nodejs";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import jwt from "jsonwebtoken";
import TimedArray from "../utils/timedArray.js";

const verifierRouter = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");

const presentation_definition_sdJwt = JSON.parse(
  fs.readFileSync("./data/presentation_definition_sdjwt.json", "utf-8")
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

/*  *******************************************************
  CLIENT_ID_SCHEME_REDIRECT_URI

*********************************************************** */
verifierRouter.get("/generateVPRequest", async (req, res) => {
  const stateParam = req.query.id ? req.query.id : uuidv4();
  const nonce = generateNonce(16);

  // The Verifier may send an Authorization Request as Request Object by value
  // or by reference as defined in JWT-Secured Authorization Request (JAR)
  // The Verifier articulates requirements of the Credential(s) that
  // are requested using presentation_definition and presentation_definition_uri

  const uuid = req.params.id ? req.params.id : uuidv4();
  //url.searchParams.get("presentation_definition");
  const response_uri = serverURL + "/direct_post" + "/" + uuid;
  const presentation_definition_uri =
    serverURL + "/presentation-definition/itbsdjwt";
  const client_metadata_uri = serverURL + "/client-metadata";
  const clientId = serverURL + "/direct_post" + "/" + uuid;
  sessions.push(uuid);
  verificationSessions.push({
    uuid: uuid,
    status: "pending",
    claims: null,
  });
  const vpRequest = buildVPbyValue(
    clientId,
    presentation_definition_uri,
    "redirect_uri",
    client_metadata_uri,
    response_uri
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

//***********PRESENTATION DEFINITON endpoint to support presentation_definition_uri Parameter */
verifierRouter.get("/presentation-definition/:type", async (req, res) => {
  const { type } = req.params;
  const presentationDefinitions = {
    1: presentation_definition_jwt,
    jwt: presentation_definition_jwt,
    2: presentation_definition_sdJwt,
    itbsdjwt: presentation_definition_sdJwt,
    3: presentation_definition_pid,
    pid: presentation_definition_pid,
    4: presentation_definition_epass,
    epass: presentation_definition_epass,
    5: presentation_definition_alliance_and_education_Id,
    eduId: presentation_definition_alliance_and_education_Id,
    6: presentation_definition_ferryboardingpass, // Changed from '5' to '6' to avoid duplication
    ferryboarding: presentation_definition_ferryboardingpass,
  };

  // Retrieve the appropriate presentation definition based on the type
  const selectedDefinition = presentationDefinitions[type];

  if (selectedDefinition) {
    res.type("application/json").send(selectedDefinition);
  } else {
    // Log the error for debugging purposes (optional)
    console.error(`No presentation definition found for type: ${type}`);

    // Send a 500 Internal Server Error response
    res.status(500).json({
      error: "Internal Server Error",
      message: `No presentation definition found for type: ${type}`,
    });
  }
});

// CLIENT VERIFIER METADATA
verifierRouter.get("/client-metadata", async (req, res) => {
  res.type("application/json").send(clientMetadata);
});

/*  *******************************************************
  CLIENT_ID_SCHEME x509_dns_san
*********************************************************** */
verifierRouter.get("/generateVPRequestx509", async (req, res) => {
  const uuid = req.params.uuid ? req.params.uuid : uuidv4();

  let client_id = "dss.aegean.gr";
  let request_uri = `${serverURL}/x509VPrequest/${uuid}`;
  let vpRequest =
    "openid4vp://?client_id=" +
    encodeURIComponent(client_id) +
    "&request_uri=" +
    encodeURIComponent(request_uri);

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

verifierRouter.get("/x509VPrequest/:id", async (req, res) => {
  //TODO pass state and nonce to the jwt request
  const stateParam = req.params.id; //req.query.id ? req.query.id : uuidv4();
  const nonce = generateNonce(16);

  const uuid = req.params.id ? req.params.id : uuidv4();
  const response_uri = serverURL + "/direct_post" + "/" + uuid;

  const client_metadata = {
    client_name: "UAegean EWC Verifier",
    logo_uri: "https://studyingreece.edu.gr/wp-content/uploads/2023/03/25.png",
    location: "Greece",
    cover_uri: "string",
    description: "EWC pilot case verification",
  };

  const clientId = "dss.aegean.gr";
  sessions.push(uuid);
  verificationSessions.push({
    uuid: uuid,
    status: "pending",
    claims: null,
  });

  let signedVPJWT = await buildVpRequestJWT(
    clientId,
    response_uri,
    presentation_definition_sdJwt,
    "",
    "x509_san_dns",
    client_metadata
  );

  console.log(signedVPJWT)
  res.type("text/plain").send(signedVPJWT);
});

/* ********************************************
              RESPONSES
*******************************************/

verifierRouter.post("/direct_post/:id", async (req, res) => {
  console.log("direct_post VP is below!");
  const sessionId = req.params.id;

  let sdjwt = req.body["vp_token"];
  if (sdjwt) {
    let presentationSubmission = req.body["presentation_submission"];
    let state = req.body["state"];
    // console.log(state);
    // console.log(response);
    const decodedSdJwt = await decodeSdJwt(sdjwt, digest);
    const claims = await getClaims(
      decodedSdJwt.jwt.payload,
      decodedSdJwt.disclosures,
      digest
    );
    console.log(claims);
    let index = sessions.indexOf(sessionId);
    console.log("index is");
    console.log(index);
    if (index >= 0) {
      verificationSessions[index].status = "success";
      verificationSessions[index].claims = claims;
      console.log(`verificatiton success`);
      console.log(verificationSessions[index]);
    }
    res.sendStatus(200);
  } else {
    res.sendStatus(500);
  }
});

// this endpoint returns the autthorization requqest object (by reference), and  is to be set on the request_uri
// however, when combined with client_id_scheme=redirect_uri then, the Authorization Request MUST NOT be signed,
// this causes incompatibilities with JAR, which is the expected result form this endpoint:
// The Verifier may send an Authorization Request as Request Object by value or by reference
// as defined in JWT-Secured Authorization Request (JAR)
// as a result this endpoint will not be used and we will only use request object by Value
/*
 ******************DEPRECATED******************************************************************************
 */
verifierRouter.get("/vpRequest/:id", async (req, res) => {
  console.log("VPRequest called Will send JWT");
  // console.log(jwtToken);
  const uuid = req.params.id ? req.params.id : uuidv4();

  //url.searchParams.get("presentation_definition");
  const stateParam = uuidv4();
  const nonce = generateNonce(16);

  const response_uri = serverURL + "/direct_post" + "/" + uuid;
  let clientId = serverURL + "/direct_post" + "/" + uuid;
  sessions.push(uuid);
  verificationSessions.push({
    uuid: uuid,
    status: "pending",
    claims: null,
  });

  let client_id_scheme = "redirect_uri";
  let jwtToken = buildVpRequestJWT(
    clientId,
    response_uri,
    presentation_definition_sdJwt,
    privateKey,
    client_id_scheme,
    clientMetadata
  );

  console.log("VP request ");
  //console.log(JSON.stringify(jwtToken, null, 2));
  console.log(jwtToken);

  res.type("text/plain").send(jwtToken);
});

// *******************************************************

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
  } else {
    return res.status(400).type("text/plain").send("Invalid type parameter");
  }
  /*
 TODO the vpRequest/:type/:id endpoint defined in routes/verifierRoutes.js, 
 that is used for JWT secured Authorization Requests (JAR), 
 returns a raw JSON object instead of a JWT. 
 
 According to the JAR standard (RFC9101), the endpoint defined in request_uri should present a JWT in the response body,
  never raw JSON. 
  Also, as has been mentioned before, when a client_id_scheme of redirect_uri is used, 
  the authorization request must not be signed, 
  so perhaps the conformance backend shouldn't use JAR at all with this scheme.
*/

  let vpRequest = {
    client_metadata: {
      client_name: "UAegean EWC Verifier",
      logo_uri:
        "https://studyingreece.edu.gr/wp-content/uploads/2023/03/25.png",
      location: "Greece",
      cover_uri: "string",
      description: "EWC pilot case verification",
    },
    client_id: clientId,
    client_id_scheme: "redirect_uri", //TODO change this
    response_uri: response_uri,
    response_type: "vp_token",
    response_mode: "direct_post",
    presentation_definition: presentationDefinition,
    nonce: nonce,
    state: uuid,
  };
  res.json(vpRequest);
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

verifierRouter.get(["/verificationStatus"], (req, res) => {
  let sessionId = req.query.sessionId;
  let index = sessions.indexOf(sessionId); // sessions.indexOf(sessionId+""); //
  console.log("index is");
  console.log(index);
  let result = null;
  if (index >= 0) {
    let status = verificationSessions[index].status;
    console.log(`sending status ${status} for session ${sessionId}`);
    if (status === "success") {
      result = verificationSessions[index].claims;
      sessions.splice(index, 1);
      verificationSessions.splice(index, 1);
      sessionHistory.addElement(sessionId);
      verificationResultsHistory.addElement(result);
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

verifierRouter.get(["/verificationStatusHistory"], (req, res) => {
  let sessionId = req.query.sessionId;
  let index = sessionHistory.getCurrentArray().indexOf(sessionId);
  if (index >= 0) {
    res.json({
      status: "success",
      reason: "ok",
      sessionId: sessionId,
      claims: verificationResultsHistory.getCurrentArray()[index],
    });
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

export default verifierRouter;
