import express from "express";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { v4 as uuidv4 } from "uuid";
import {
  getAuthCodeSessions,
  getPushedAuthorizationRequests,
  getSessionsAuthorizationDetail,
  getAuthCodeAuthorizationDetail,
} from "../services/cacheService.js";

import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { generateNonce, buildVpRequestJWT } from "../utils/cryptoUtils.js";
import { updateIssuerStateWithAuthCode } from "./codeFlowJwtRoutes.js";

const codeFlowRouterSDJWT = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";
const privateKey = fs.readFileSync("./private-key.pem", "utf-8");

// ******************************************************************
// ************* CREDENTIAL OFFER ENDPOINTS *************************
// ******************************************************************
codeFlowRouterSDJWT.get(["/offer-code-sd-jwt"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const codeSessions = getAuthCodeSessions();
  if (codeSessions.sessions.indexOf(uuid) < 0) {
    codeSessions.sessions.push(uuid);
    // codeSessions.results.push({ sessionId: uuid, status: "pending" });
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
    credential_configuration_ids: ["VerifiablePortableDocumentA1SDJWT"],
    grants: {
      authorization_code: {
        issuer_state: req.params.id,
      },
    },
  });
});

/***************************************************************
 *               Push Authoriozation Request Endpoints
 * https://datatracker.ietf.org/doc/html/rfc9126
 ***************************************************************/
codeFlowRouterSDJWT.post("/par", async (req, res) => {
  const client_id = req.body.client_id; //DID of the holder requesting the credential
  const scope = req.body.scope;
  const response_type = req.body.response_type;
  const redirect_uri = req.body.redirect_uri;
  const code_challenge = req.body.code_challenge;
  const code_challenge_method = req.body.code_challenge_method;
  const claims = req.body.claims;
  const state = req.body.state;
  const authorizationHeader = req.get("Authorization");
  const responseType = req.body.response_type;
  const issuerState = decodeURIComponent(req.body.issuer_state); // This can be associated with the ITB session
  let authorizationDetails = req.body.authorization_details;
  const clientMetadata = req.body.client_metadata;

  let requestURI = "urn:aegean.gr:" + uuidv4();
  let parRequests = getPushedAuthorizationRequests();
  parRequests.set(requestURI, {
    client_id: client_id,
    scope: scope,
    response_type: response_type,
    redirect_uri: redirect_uri,
    code_challenge: code_challenge,
    code_challenge_method: code_challenge_method,
    claims: claims,
    state: state,
    authorizationHeader: authorizationHeader,
    responseType: responseType,
    issuerState: issuerState,
    authorizationDetails: authorizationDetails,
    clientMetadata: clientMetadata,
  });

  res.json({
    request_uri: requestURI,
    expires_in: 90,
  });
});

/*********************************************************************************
 *               Authorisation request
 *
 * Two ways to request authorization
 * One way is to use the authorization_details request parameter with one or more authorization details objects of type openid_credential
 * Second way is through the use of scope
 ****************************************************************/
codeFlowRouterSDJWT.get("/authorize", async (req, res) => {
  let response_type = req.query.response_type;
  let scope = req.query.scope;
  let issuerState = decodeURIComponent(req.query.issuer_state); // This can be associated with the ITB session
  let state = req.query.state;
  let client_id = decodeURIComponent(req.query.client_id); //DID of the holder requesting the credential
  let authorizationDetails = req.query.authorization_details;
  let redirect_uri = req.query.redirect_uri;
  let code_challenge = req.query.code_challenge;
  let code_challenge_method = req.query.code_challenge_method;
  let authorizationHeader = req.headers["authorization"]; // Fetch the 'Authorization' header
  let claims = "";
  let client_metadata = req.query.client_metadata;

  //validations
  let errors = [];

  //check for par
  const request_uri = req.query.request_uri;
  if (request_uri) {
    const parRequest = getPushedAuthorizationRequests()
      ? getPushedAuthorizationRequests().get(request_uri)
      : null;
    if (parRequest) {
      client_id = parRequest.client_id;
      scope = parRequest.scope;
      response_type = parRequest.response_type;
      redirect_uri = parRequest.redirect_uri;
      code_challenge = parRequest.code_challenge;
      code_challenge_method = parRequest.code_challenge_method;
      claims = parRequest.claims;
      state = parRequest.state;
      authorizationHeader = parRequest.authorizationHeader;
      issuerState = parRequest.issuerState;
      authorizationDetails = parRequest.authorizationDetails;
      response_type = parRequest.response_type;
      client_metadata = parRequest.clientMetadata;
    } else {
      console.log(
        "ERROR: request_uri present in authorization endpoint, but no par request cached for request_uri" +
          request_uri
      );
    }
  }

  const redirectUri = redirect_uri
    ? decodeURIComponent(redirect_uri)
    : "openid4vp://";
  const nonce = req.query.nonce;
  const codeChallenge = decodeURIComponent(req.query.code_challenge);
  const codeChallengeMethod = req.query.code_challenge_method; //this should equal to S256
  try {
    if (client_metadata) {
      const clientMetadata = JSON.parse(decodeURIComponent(client_metadata));
    } else {
      console.log("client_metadata was missing");
    }
  } catch (error) {
    console.log("client_metadata was missing");
    console.log(error);
  }

  // ************CASE 1: With authorizationDetails
  /* required parameters: response_type, client_id, code_challenge, 
    optional: code_challenge_method, authorization_details, redirect_uri, issuer_state
  */
  if (authorizationDetails) {
    if (authorizationDetails && !response_type)
      errors.push("authorizationDetails missing response_type");
    if (authorizationDetails && !client_id)
      errors.push("authorizationDetails missing client_id");
    if (authorizationDetails && !code_challenge)
      errors.push("authorizationDetails missing code_challenge");

    try {
      if (authorizationDetails) {
        authorizationDetails = JSON.parse(
          decodeURIComponent(authorizationDetails)
        );
      } else {
        console.log("authorization_details was missing");
      }
      if (authorizationDetails.length > 0) {
        authorizationDetails.forEach((item) => {
          let cred = fetchVCTorCredentialConfigId(item);
          // cache authorizationDetails for the direct_post endpoint (it is needed to assosiate it with the auth. code generated there)
          getSessionsAuthorizationDetail().set(
            issuerState,
            decodeURIComponent(authorizationDetails)
          );
          console.log("requested credentials: " + cred);
        });
      }
    } catch (error) {
      console.log("error parsing authorization details" + authorizationDetails);
      errors.push("error parsing authorization details");
    }
  }

  // ************CASE 2: With Scope instead of authorization_details

  /*
  [{"format":"jwt_vc",
  "locations":["https://issuer.example.com"],
  "type":"openid_credential",
  "types":["VerifiableCredential","VerifiableAttestation","VerifiablePortableDocumentA1"]}]
  */
  if (!authorizationDetails) {
    console.log("authorization_details not found trying scope");
    if (scope) {
      console.log("requested credentials: " + scope);
    } else {
      errors.push("no credentials requested");
      console.log(`no credentials requested`);
    }
  }

  if (response_type !== "code") {
    errors.push("Invalid response_type");
  }
  // removed due to https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#name-using-scope-parameter-to-re
  // if (!scope.includes("openid")) {
  //   errors.push("Invalid scope");
  // }

  const authorizationCode = null; //"SplxlOBeZQQYbYS6WxSbIA";
  const codeSessions = getAuthCodeSessions();
  if (codeSessions.sessions.indexOf(issuerState) >= 0) {
    codeSessions.requests.push({
      redirectUri: redirectUri,
      challenge: codeChallenge,
      method: codeChallengeMethod,
      sessionId: authorizationCode,
      issuerState: issuerState,
      state: state,
    });
    codeSessions.results.push({
      sessionId: authorizationCode,
      issuerState: issuerState,
      state: state,
      status: "pending",
    });
    codeSessions.walletSessions.push(state); // push state as send by wallet
  } else {
    console.log("ITB session not found");
  }

  /*
    Authorizatiton Endpoint Response:  
  */

  //The holder wallet then responds with an id_token signed by the DID to the direct post endpoint.

  if (errors.length > 0) {
    console.error("Validation errors:", errors);
    let error_description = "";
    errors.forEach((element) => {
      error_description += element + " ";
    });
    const encodedErrorDescription = encodeURIComponent(
      error_description.trim()
    );
    const errorRedirectUrl = `${redirectUri}?error=invalid_request&error_description=${encodedErrorDescription}`;
    //TODO mark the codeFlowSession as failed
    return res.redirect(302, errorRedirectUrl);
  } else {
    /*
    //5.1.5. Dynamic Credential Request https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-12.html#name-successful-authorization-requesttt
     The credential issuer can optionally request additional details to authenticate the client e.g. DID authentication. In this case, the authorisation response will contain a response_mode parameter with the value direct_post. A sample response is as given:
   
    client_id, Decentralised identifier
    redirect_uri, For redirection of the response
    response_type ( if the issuer requests DID authentication.),
    response_mode (The value must be direct_post)
    scope, The value must be openid 
    nonce,
    request_uri: The authorisation server’s private key signed the request.
    */
   const vpRedirectURI="openid4vp://"
   console.log(redirect_uri + " but i will request the vp based on " + vpRedirectURI)
    const redirectUrl = `${vpRedirectURI}?state=${state}&client_id=${client_id}&redirect_uri=${serverURL}/direct_post_vci&response_type=id_token&response_mode=direct_post&scope=openid&nonce=${nonce}&request_uri=${serverURL}/request_uri_dynamic`;
    return res.redirect(302, redirectUrl);
  }
});

codeFlowRouterSDJWT.get("/request_uri_dynamic", async (req, res) => {
  let uuid = uuidv4();
  let client_id = serverURL + "/direct_post" + "/" + uuid;
  const response_uri = serverURL + "/direct_post" + "/" + uuid;

  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  // Construct the absolute path to verifier-config.json
  const configPath = path.join(__dirname, "..", "data", "verifier-config.json");
  const presentation_definition_sdJwt = JSON.parse(
    fs.readFileSync(
      path.join(__dirname, "..", "data", "presentation_definition_sdjwt.json")
    )
  );

  // Read and parse the JSON file
  // const clientMetadata = JSON.parse(fs.readFileSync(configPath, "utf-8"));

  // clientMetadata.presentation_definition_uri =
  //   serverURL + "/presentation-definition/" + uuid;
  // clientMetadata.redirect_uris = [response_uri];
  // clientMetadata.client_id = client_id;
  const clientMetadata = {
    vp_formats: {
      jwt_vp: {
        alg: ["EdDSA", "ES256K"],
      },
      ldp_vp: {
        proof_type: ["Ed25519Signature2018"],
      },
    },
  };

  const vpRequestJWT = buildVpRequestJWT(
    client_id,
    response_uri,
    presentation_definition_sdJwt,
    privateKey,
    "redirect_uri",
    clientMetadata
  );

  // console.log("Dynamic VP request ")
  // console.log(JSON.stringify(vpRequestJWT, null, 2));

  res.send(vpRequestJWT);
});

/*
  presentation by the wallet during an Issuance part of the Dynamic Credential Request 
*/
codeFlowRouterSDJWT.post("/direct_post_vci", async (req, res) => {
  console.log("direct_post VP for VCI is below!");
  let state = req.body["state"];
  let jwt = req.body["id_token"];
  console.log("direct_post_vci received jwt is::");
  console.log(jwt);

  //
  const authorizatiton_details = getSessionsAuthorizationDetail().get(state);

  if (jwt) {
    const codeSessions = getAuthCodeSessions();
    const authorizationCode = generateNonce(16);
    //cache authorizatiton_detatils witth the generated code. this is needed for the token_endpoint
    getAuthCodeAuthorizationDetail().set(
      authorizationCode,
      authorizatiton_details
    );

    updateIssuerStateWithAuthCode(
      authorizationCode,
      state,
      codeSessions.walletSessions,
      codeSessions.results,
      codeSessions.requests
    );
    const redirectUrl = `${codeSessions.requests.redirectUri}?code=${authorizationCode}&state=${state}`;
    return res.redirect(302, redirectUrl);
  } else {
    return res.sendStatus(500);
  }
});

// Function to fetch either vct or credential_configuration_id
function fetchVCTorCredentialConfigId(data) {
  // Check for vct first, fallback to credential_configuration_id if not found
  if (data.vct) {
    return data.vct;
  } else if (data.credential_configuration_id) {
    return data.credential_configuration_id;
  } else {
    return null; // Return null if neither is found
  }
}

export default codeFlowRouterSDJWT;
