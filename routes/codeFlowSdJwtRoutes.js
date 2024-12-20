import express from "express";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { v4 as uuidv4 } from "uuid";
import {
  getPushedAuthorizationRequests,
  getSessionsAuthorizationDetail,
  getAuthCodeAuthorizationDetail,
} from "../services/cacheService.js";
import { buildVPbyValue } from "../utils/tokenUtils.js";

import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { generateNonce, buildVpRequestJWT } from "../utils/cryptoUtils.js";
import {
  updateIssuerStateWithAuthCode,
  updateIssuerStateWithAuthCodeAfterVP,
} from "./codeFlowJwtRoutes.js";
import {
  getCodeFlowSession,
  storeCodeFlowSession,
} from "../services/cacheServiceRedis.js";

const codeFlowRouterSDJWT = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";
const proxyPath = process.env.PROXY_PATH || null;
const privateKey = fs.readFileSync("./private-key.pem", "utf-8");

// ******************************************************************
// ************* CREDENTIAL OFFER ENDPOINTS *************************
// ******************************************************************
codeFlowRouterSDJWT.get(["/offer-code-sd-jwt"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const credentialType = req.query.credentialType
    ? req.query.credentialType
    : "VerifiablePortableDocumentA2SDJWT";

  const client_id_scheme = req.query.client_id_scheme
    ? req.query.client_id_scheme
    : "redirect_uri";

  let existingCodeSession = await getCodeFlowSession(uuid);
  if (!existingCodeSession) {
    storeCodeFlowSession(uuid, {
      walletSession: null,
      requests: null,
      results: null,
      status: "pending",
    });
    // codeSessions.results.push({ sessionId: uuid, status: "pending" });
  }

  let encodedCredentialOfferUri = encodeURIComponent(
    `${serverURL}/credential-offer-code-sd-jwt/${uuid}?scheme=${client_id_scheme}&credentialType=${credentialType}`
  );
  let credentialOffer = `openid-credential-offer://?credential_offer_uri=${encodedCredentialOfferUri}`;

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
// with dynamic cred request and client_id_scheme == redirect_uri
codeFlowRouterSDJWT.get(["/credential-offer-code-sd-jwt/:id"], (req, res) => {
  const credentialType = req.query.credentialType
    ? req.query.credentialType
    : "VerifiablePortableDocumentA2SDJWT";

  console.log(req.query);
  console.log(req.query.client_id_scheme);
  const client_id_scheme = req.query.scheme ? req.query.scheme : "redirect_uri";

  /*
    To support multiple client_id_schemas, this param  client_id_scheme 
    will be passed into the session of the issuer and fetched in the 
    authorize endpoint to decide what schema to use
  */
  const issuer_state = `${req.params.id}|${client_id_scheme}`; // using "|" as a delimiter

  res.json({
    credential_issuer: serverURL,
    credential_configuration_ids: [credentialType],
    grants: {
      authorization_code: {
        issuer_state: issuer_state,
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

  console.log("par state " + state);
  console.log("issuer state " + issuerState);

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
  let state = req.query.state; //wallet state
  let client_id = decodeURIComponent(req.query.client_id); // DID:key  of the holder requesting the credential
  let authorizationDetails = req.query.authorization_details; //contains the requested credentals
  let redirect_uri = req.query.redirect_uri; // typically this will be openid
  let code_challenge = req.query.code_challenge;

  let client_metadata = req.query.client_metadata; //details of the wallet

  const nonce = req.query.nonce;
  code_challenge = decodeURIComponent(req.query.code_challenge);
  let code_challenge_method = req.query.code_challenge_method; //this should equal to S256
  let claims;
  let authorizationHeader;

  let isPIDIssuanceFlow = false;

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

  let credentialsRequested = null;
  // ************CASE 1: With authorizationDetails
  /* required parameters: response_type, client_id, code_challenge, 
    optional: code_challenge_method, authorization_details, redirect_uri, issuer_state
  */
  if (authorizationDetails) {
    if (authorizationDetails && !response_type)
      errors.push("authorizationDetails missing response_type");
    // if (authorizationDetails && !client_id)
    //   errors.push("authorizationDetails missing client_id");
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
          credentialsRequested = cred;
          if (
            cred === "urn:eu.europa.ec.eudi.pid.1" ||
            cred.indexOf("urn:eu.europa.ec.eudi.pid.1") >= 0
          ) {
            isPIDIssuanceFlow = true;
          }
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
      credentialsRequested = scope;
      if (scope.indexOf("urn:eu.europa.ec.eudi.pid.1") >= 0) {
        isPIDIssuanceFlow = true;
      }
    } else {
      errors.push("no credentials requested");
      console.log(`no credentials requested`);
    }
  }

  // retrive cleaned ITB session and also get (if specified) the client_id_scheme
  const [originalUuid, client_id_scheme] = issuerState.split("|");
  // issuerState = originalUuid;
  const authorizationCode = null; //"SplxlOBeZQQYbYS6WxSbIA";
  let existingCodeSession = await getCodeFlowSession(issuerState);
  existingCodeSession =
    existingCodeSession == null
      ? await getCodeFlowSession(originalUuid)
      : existingCodeSession;
  if (existingCodeSession) {
    await storeCodeFlowSession(issuerState, {
      walletSession: state,
      requests: {
        redirectUri: redirectUri,
        challenge: code_challenge,
        method: code_challenge_method,
        sessionId: authorizationCode,
        issuerState: issuerState,
        state: state,
      },
      results: {
        sessionId: authorizationCode,
        issuerState: issuerState,
        state: state,
        status: "pending",
      },
      status: "pending",
      isPIDIssuanceFlow: isPIDIssuanceFlow,
    });
  } else {
    console.log("ITB session not found");
  }

  if (response_type !== "code") {
    errors.push("Invalid response_type");
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
    existingCodeSession["status"] = "failed";
    existingCodeSession["results"]["status"] = "failed";
    storeCodeFlowSession(issuerState, existingCodeSession);
    return res.redirect(302, errorRedirectUrl);
  } else {
    /*
    //5.1.5. Dynamic Credential Request https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-12.html#name-successful-authorization-requesttt
     The credential issuer can optionally request additional details to authenticate the client e.g. DID authentication. In this case, the authorisation response will contain a response_mode parameter with the value direct_post. A sample response is as given:
    */

    if (client_id_scheme == "redirect_uri") {
      console.log("client_id_scheme redirect_uri");
      const vpRedirectURI = "openid4vp://";
      // changed this to support auth request by value not reference
      //const redirectUrl = `${vpRedirectURI}?state=${state}&client_id=${client_id}&redirect_uri=${serverURL}/direct_post_vci&response_type=id_token&response_mode=direct_post&scope=openid&nonce=${nonce}&request_uri=${serverURL}/request_uri_dynamic`;
      const response_uri = serverURL + "/direct_post_vci" + "/" + issuerState;
      const presentation_definition_uri =
        serverURL + "/presentation-definition/itbsdjwt";
      const client_metadata_uri = serverURL + "/client-metadata";

      // client_id_scheme is set to redirect_uri in OIDC4VP v20, the client_id becomes the redirect_uri
      let redirectUrl = buildVPbyValue(
        response_uri,
        presentation_definition_uri,
        "redirect_uri",
        client_metadata_uri,
        response_uri
      );
      if (credentialsRequested.indexOf("urn:eu.europa.ec.eudi.pid.1") >= 0) {
        //we should request only DID binding in this case
        console.log("passing id_token!!");
        redirectUrl = buildVPbyValue(
          response_uri,
          null,
          "redirect_uri",
          client_metadata_uri,
          response_uri,
          existingCodeSession.state,
          "id_token"
        );
      }

      return res.redirect(302, redirectUrl);
    } else if (client_id_scheme == "x509_san_dns") {
      console.log("client_id_scheme x509_san_dns");
      let request_uri = `${serverURL}/x509VPrequest_dynamic/${issuerState}`;
      if (credentialsRequested.indexOf("urn:eu.europa.ec.eudi.pid.1") >= 0) {
        //for x509 no id_token binding is supported by SIOPv2/OIDC4VP
        // it is only for did and redirect_uri. As a result we
        // redirect with code here instead

        ///
        const authorizationCode = generateNonce(16);
        //cache authorizatiton_detatils witth the generated code. this is needed for the token_endpoint
        getAuthCodeAuthorizationDetail().set(
          authorizationCode,
          authorizationDetails
        );
        existingCodeSession = await getCodeFlowSession(issuerState);
        existingCodeSession.results.sessionId = authorizationCode;
        existingCodeSession.requests.sessionId = authorizationCode;
        storeCodeFlowSession(issuerState, existingCodeSession);

        const redirectUrl = `${redirectUri}?code=${authorizationCode}&state=${existingCodeSession.state}`;
        return res.redirect(302, redirectUrl);
        ///
        //        request_uri = `${serverURL}/id_token_x509_request_dynamic/${issuerState}`;
      }

      const clientId = "dss.aegean.gr";
      let vpRequest =
        "openid4vp://?client_id=" +
        encodeURIComponent(clientId) +
        "&request_uri=" +
        encodeURIComponent(request_uri);

      return res.redirect(302, vpRequest);
    } else if (client_id_scheme == "did") {
      console.log("client_id_scheme did");
      let request_uri = `${serverURL}/didJwksVPrequest_dynamic/${issuerState}`;
      if (credentialsRequested.indexOf("urn:eu.europa.ec.eudi.pid.1") >= 0) {
        //we should request only DID binding in this case
        request_uri = `${serverURL}/id_token_did_request_dynamic/${issuerState}`;
      }
      const clientId = "dss.aegean.gr";
      let vpRequest =
        "openid4vp://?client_id=" +
        encodeURIComponent(clientId) +
        "&request_uri=" +
        encodeURIComponent(request_uri);

      return res.redirect(302, vpRequest);
    }
  }
});

// Dynamic VP request by reference endpoint
codeFlowRouterSDJWT.get("/x509VPrequest_dynamic/:id", async (req, res) => {
  const uuid = req.params.id ? req.params.id : uuidv4();
  const response_uri = serverURL + "/direct_post_vci/" + uuid;

  const client_metadata = {
    client_name: "UAegean EWC Verifier",
    logo_uri: "https://studyingreece.edu.gr/wp-content/uploads/2023/03/25.png",
    location: "Greece",
    cover_uri: "string",
    description: "EWC pilot case verification",
    vp_formats: {
      "vc+sd-jwt": {
        alg: ["ES256", "ES384"],
      },
    },
  };
  const presentation_definition_sdJwt = JSON.parse(
    fs.readFileSync("./data/presentation_definition_sdjwt.json", "utf-8")
  );

  const clientId = "dss.aegean.gr";
  let signedVPJWT = await buildVpRequestJWT(
    clientId,
    response_uri,
    presentation_definition_sdJwt,
    "",
    "x509_san_dns",
    client_metadata,
    null,
    serverURL
  );

  console.log(signedVPJWT);
  res.type("text/plain").send(signedVPJWT);
});

codeFlowRouterSDJWT.get("/didJwksVPrequest_dynamic/:id", async (req, res) => {
  const uuid = req.params.id ? req.params.id : uuidv4();
  const response_uri = serverURL + "/direct_post_vci/" + uuid;

  const client_metadata = {
    client_name: "UAegean EWC Verifier",
    logo_uri: "https://studyingreece.edu.gr/wp-content/uploads/2023/03/25.png",
    location: "Greece",
    cover_uri: "string",
    description: "EWC pilot case verification",
    vp_formats: {
      "vc+sd-jwt": {
        alg: ["ES256", "ES384"],
      },
    },
  };

  const privateKeyPem = fs.readFileSync(
    "./didjwks/did_private_pkcs8.key",
    "utf8"
  );

  let contorller = serverURL;
  if (proxyPath) {
    contorller = serverURL.replace("/" + proxyPath, "") + ":" + proxyPath;
  }
  contorller = contorller.replace("https://", "");
  const clientId = `did:web:${contorller}`;
  const presentation_definition_sdJwt = JSON.parse(
    fs.readFileSync("./data/presentation_definition_sdjwt.json", "utf-8")
  );

  let signedVPJWT = await buildVpRequestJWT(
    clientId,
    response_uri,
    presentation_definition_sdJwt,
    privateKeyPem,
    "did:jwks",
    client_metadata,
    `did:web:${contorller}#keys-1`,
    serverURL
  );
  res.type("text/plain").send(signedVPJWT);
});

// Dynamic VP request with only id_token
codeFlowRouterSDJWT.get(
  "/id_token_x509_request_dynamic/:id",
  async (req, res) => {
    const uuid = req.params.id ? req.params.id : uuidv4();
    let existingCodeSession = await getCodeFlowSession(uuid);
    const response_uri = serverURL + "/direct_post_vci/" + existingCodeSession.requests.state
    ;

    const client_metadata = {
      client_name: "UAegean EWC Verifier",
      logo_uri:
        "https://studyingreece.edu.gr/wp-content/uploads/2023/03/25.png",
      location: "Greece",
      cover_uri: "string",
      description: "EWC pilot case verification",
      vp_formats: {
        "vc+sd-jwt": {
          alg: ["ES256", "ES384"],
        },
      },
    };
    const clientId = "dss.aegean.gr";
    let signedVPJWT = await buildVpRequestJWT(
      clientId,
      response_uri,
      null,
      "",
      "x509_san_dns",
      client_metadata,
      null,
      serverURL,
      "id_token"
    );

    console.log(signedVPJWT);
    res.type("text/plain").send(signedVPJWT);
  }
);

codeFlowRouterSDJWT.get(
  "/id_token_did_request_dynamic/:id",
  async (req, res) => {
    const uuid = req.params.id ? req.params.id : uuidv4();

    let existingCodeSession = await getCodeFlowSession(uuid);
    const response_uri =
      serverURL + "/direct_post_vci/" + existingCodeSession.requests.state;
    const client_metadata = {
      client_name: "UAegean EWC Verifier",
      logo_uri:
        "https://studyingreece.edu.gr/wp-content/uploads/2023/03/25.png",
      location: "Greece",
      cover_uri: "string",
      description: "EWC pilot case verification",
      vp_formats: {
        "vc+sd-jwt": {
          alg: ["ES256", "ES384"],
        },
      },
    };

    const privateKeyPem = fs.readFileSync(
      "./didjwks/did_private_pkcs8.key",
      "utf8"
    );

    let contorller = serverURL;
    if (proxyPath) {
      contorller = serverURL.replace("/" + proxyPath, "") + ":" + proxyPath;
    }
    contorller = contorller.replace("https://", "");
    const clientId = `did:web:${contorller}`;
    const presentation_definition_sdJwt = JSON.parse(
      fs.readFileSync("./data/presentation_definition_sdjwt.json", "utf-8")
    );

    let signedVPJWT = await buildVpRequestJWT(
      clientId,
      response_uri,
      null,
      privateKeyPem,
      "did:jwks",
      client_metadata,
      `did:web:${contorller}#keys-1`,
      serverURL,
      "vp_token id_token"
    );
    res.type("text/plain").send(signedVPJWT);
  }
);

/*
  presentation by the wallet during an Issuance part of the Dynamic Credential Request 
*/
codeFlowRouterSDJWT.post("/direct_post_vci/:id", async (req, res) => {
  console.log("direct_post VP for VCI is below!");
  let state = req.body["state"]; //wallet state
  let jwt = req.body["vp_token"];
  // console.log("direct_post_vci received jwt is::");
  // console.log(jwt);
  const issuerState = req.params.id;
  console.log("direct_post_vci state" + issuerState);

  //
  const authorizatiton_details = getSessionsAuthorizationDetail().get(state);

  if (jwt) {
    const authorizationCode = generateNonce(16);
    //cache authorizatiton_detatils witth the generated code. this is needed for the token_endpoint
    getAuthCodeAuthorizationDetail().set(
      authorizationCode,
      authorizatiton_details
    );

    // // THE WALLET SENDS A DIFFERENT SATE (THAT IS THE STATE OF THE VP NOT THE VCI)
    // // SO A DIFFERENT UPDATE IS REQUIRED HERE
    console.log("wallet state " + state);

    let existingCodeSession = await getCodeFlowSession(issuerState);
    if (existingCodeSession) {
      let issuanceState = existingCodeSession.results.state; //codeSessions.results[sessionIndex].state;
      existingCodeSession.results.sessionId = authorizationCode;
      existingCodeSession.requests.sessionId = authorizationCode;
      storeCodeFlowSession(issuanceState, existingCodeSession);

      const redirectUrl = `${existingCodeSession.requests.redirectUri}?code=${authorizationCode}&state=${existingCodeSession.requests.state}`;
      // return //res.redirect(302, redirectUrl);
      return res.send({ redirect_uri: redirectUrl });
    } else {
      console.log("issuance session not found " + issuerState);
      return res.sendStatus(500);
    }
  } else {
    console.log("no jwt presented");
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
  } else if (data.types) {
    return data.types;
  } else {
    return null; // Return null if neither is found
  }
}

export default codeFlowRouterSDJWT;
