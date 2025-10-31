import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import {
  pemToJWK,
  generateNonce,
  decryptJWE,
  buildVpRequestJSON,
  buildVpRequestJWT,
} from "../../utils/cryptoUtils.js";

import {
  extractClaimsFromRequest,
  hasOnlyAllowedFields,
  getSDsFromPresentationDef,
} from "../../utils/vpHeplers.js";

import { buildVPbyValue } from "../../utils/tokenUtils.js";
import { decodeSdJwt, getClaims } from "@sd-jwt/decode";
import { digest } from "@sd-jwt/crypto-nodejs";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import jwt from "jsonwebtoken";
import TimedArray from "../../utils/timedArray.js";

import { 
  getVPSession, 
  storeVPSession,
  logInfo,
  logWarn,
  logError,
  logDebug,
  setSessionContext,
  clearSessionContext
} from "../../services/cacheServiceRedis.js";
import redirectUriRouter from "../redirectUriRoutes.js";
import x509Router from "./x509Routes.js";
import didRouter from "./didRoutes.js";
import didJwkRouter from "./didJwkRoutes.js";
import { verifyMdlToken, validateMdlClaims } from "../../utils/mdlVerification.js";
import base64url from "base64url";
import { encode as encodeCbor } from 'cbor-x';

const getSessionTranscriptBytes = (
  oid4vpData,
  mdocGeneratedNonce,
) => encodeCbor(['OIDC4VPHandover', oid4vpData.client_id, oid4vpData.response_uri, mdocGeneratedNonce, oid4vpData.nonce]);

const verifierRouter = express.Router();

// Middleware to set session context for console interception
verifierRouter.use((req, res, next) => {
  const sessionId = req.query.sessionId || req.params.sessionId || req.params.id;
  if (sessionId) {
    setSessionContext(sessionId);
    // Clear context when response finishes
    res.on('finish', () => {
      clearSessionContext();
    });
  }
  next();
});

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

// This should be replaced with the actual trusted root certificate(s) for the mDL issuers.
const trustedCerts = [fs.readFileSync(
  "./x509EC/client_certificate.crt",
  "utf8"
)]; 

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
    await logInfo(sessionId, "Processing direct_post VP response", {
      endpoint: "/direct_post/:id",
      sessionId
    });
    
    const vpSession = await getVPSession(sessionId);
    
    if (!vpSession) {
      console.warn(`Session ID ${sessionId} not found.`);
      await logError(sessionId, "Session ID not found", {
        sessionId,
        error: `Session ID ${sessionId} not found.`
      });
      return res.status(400).json({ error: `Session ID ${sessionId} not found.` });
    }
    
    await logInfo(sessionId, "VP session retrieved successfully", {
      hasNonce: !!vpSession.nonce,
      hasPresentationDefinition: !!vpSession.presentation_definition,
      responseMode: vpSession.response_mode,
      status: vpSession.status
    });

    const isMdoc = vpSession.presentation_definition && vpSession.presentation_definition.format && vpSession.presentation_definition.format.mso_mdoc;

    if (isMdoc) {
      console.log("mDL verification using custom cbor-x decoder...");
      await logInfo(sessionId, "Processing mDL verification using custom cbor-x decoder", {
        isMdoc: true
      });
      try {
        const vpToken = req.body["vp_token"];
        if (!vpToken) {
          await logError(sessionId, "No vp_token found in mDL request body");
          return res.status(400).json({ error: "No vp_token found in the request body." });
        }
        
        await logDebug(sessionId, "VP token found in mDL request", {
          vpTokenLength: vpToken?.length
        });

        // Use our custom verification logic
        const verificationOptions = {
          requestedFields: vpSession.sdsRequested, // Apply selective disclosure if requested
          validateStructure: true,
          includeMetadata: true
        };

        // TODO
        const documentType=null//vpSession.vct
        await logDebug(sessionId, "Starting mDL token verification", {
          verificationOptions
        });
        
        const mdocResult = await verifyMdlToken(vpToken, verificationOptions);

        if (!mdocResult.success) {
          console.error("mDL verification failed:", mdocResult.error);
          await logError(sessionId, "mDL verification failed", {
            error: mdocResult.error,
            details: mdocResult.details
          });
          return res.status(400).json({ 
            error: `mDL verification failed: ${mdocResult.error}`,
            details: mdocResult.details 
          });
        }
        
        await logInfo(sessionId, "mDL verification successful", {
          claimsCount: Object.keys(mdocResult.claims || {}).length
        });

        const claims = mdocResult.claims;

        // Validate that extracted claims match what was requested
        if (vpSession.sdsRequested && !validateMdlClaims(claims, vpSession.sdsRequested)) {
          console.log("mDL claims do not match what was requested.");
          await logError(sessionId, "mDL claims do not match what was requested", {
            requested: vpSession.sdsRequested,
            received: Object.keys(claims)
          });
          return res.status(400).json({
            error: "mDL claims do not match what was requested.",
            requested: vpSession.sdsRequested,
            received: Object.keys(claims)
          });
        }
        
        await logDebug(sessionId, "mDL claims validation successful", {
          claimsReceived: Object.keys(claims),
          claimsRequested: vpSession.sdsRequested
        });

        vpSession.status = "success";
        vpSession.claims = claims;
        vpSession.mdlMetadata = mdocResult.metadata; // Store metadata for debugging
        await storeVPSession(sessionId, vpSession);
        
        await logInfo(sessionId, "mDL verification completed successfully", {
          status: "success",
          claimsCount: Object.keys(claims).length
        });
        
        return res.status(200).json({ status: "ok" });

      } catch (error) {
        console.error("Error processing mDL response:", error);
        await logError(sessionId, "Error processing mDL response", {
          error: error.message,
          stack: error.stack
        });
        return res.status(400).json({ error: `mDL verification failed: ${error.message}` });
      }
    }

    // Handle different response modes
    console.log("response mode: " + vpSession.response_mode);
    await logInfo(sessionId, "Processing VP response mode", {
      responseMode: vpSession.response_mode
    });
    let claimsFromExtraction;
    let jwtFromKeybind;

    // Handle dc_api.jwt response mode
    // This is for HAIP Digital Credentials API responses where the wallet
    // posts the entire VP as a signed JWT in the request body
    if (vpSession.response_mode === 'dc_api.jwt') {
      console.log("Processing HAIP dc_api.jwt response mode");
      await logInfo(sessionId, "Processing HAIP dc_api.jwt response mode", {
        responseMode: "dc_api.jwt"
      });
      try {
        // For Response Mode dc_api.jwt, the Wallet includes 
        // the response parameter, which contains an encrypted JWT encapsulating the Authorization Response, as defined in Section 8.3.
        
        // Extract encrypted JWT from request body
        const encryptedJWT = req.body.response;
        
        console.log("HAIP dc_api.jwt encrypted JWT received:", encryptedJWT ? "Yes" : "No");
        await logDebug(sessionId, "HAIP dc_api.jwt encrypted JWT received", {
          hasEncryptedJWT: !!encryptedJWT,
          encryptedJWTLength: encryptedJWT?.length
        });
        
        if (!encryptedJWT) {
          await logError(sessionId, "No encrypted JWT found in HAIP dc_api.jwt response");
          return res.status(400).json({ 
            error: "No encrypted JWT found in HAIP dc_api.jwt response", 
            note: "In HAIP dc_api.jwt, the response parameter should contain an encrypted JWT"
          });
        }

        // Decrypt the JWT using X509 EC private key
        console.log("Decrypting HAIP dc_api.jwt response...");
        await logDebug(sessionId, "Starting HAIP dc_api.jwt decryption");
        const privateKeyForDecryption = fs.readFileSync("./x509EC/ec_private_pkcs8.key", "utf8");
        
        let decryptedResponse;
        try {
          decryptedResponse = await decryptJWE(encryptedJWT, privateKeyForDecryption, "dc_api.jwt");
          console.log("HAIP dc_api.jwt decrypted response:", decryptedResponse);
          await logInfo(sessionId, "HAIP dc_api.jwt decryption successful", {
            decryptedResponseType: typeof decryptedResponse
          });
        } catch (decryptError) {
          console.error("Failed to decrypt HAIP dc_api.jwt response:", decryptError);
          await logError(sessionId, "Failed to decrypt HAIP dc_api.jwt response", {
            error: decryptError.message,
            stack: decryptError.stack
          });
          return res.status(400).json({ 
            error: "Failed to decrypt HAIP dc_api.jwt response", 
            details: decryptError.message 
          });
        }

        // Extract VP token from decrypted response
        let vpToken;
        if (typeof decryptedResponse === 'string') {
          try {
            const parsedResponse = JSON.parse(decryptedResponse);
            vpToken = parsedResponse.vp_token || parsedResponse.response || decryptedResponse;
          } catch (parseError) {
            // If it's not JSON, treat the entire decrypted response as the VP token
            vpToken = decryptedResponse;
          }
        } else if (decryptedResponse && typeof decryptedResponse === 'object') {
          vpToken = decryptedResponse.vp_token || decryptedResponse.response || JSON.stringify(decryptedResponse);
        }

        if (!vpToken) {
          console.log("No VP token found in decrypted response:", decryptedResponse);
          await logError(sessionId, "No VP token found in decrypted HAIP dc_api.jwt response", {
            decryptedResponse: decryptedResponse
          });
          return res.status(400).json({ 
            error: "No VP token found in decrypted HAIP dc_api.jwt response", 
            decryptedResponse: decryptedResponse
          });
        }

        console.log("HAIP dc_api.jwt extracted vpToken:", vpToken);
        await logDebug(sessionId, "HAIP dc_api.jwt extracted vpToken", {
          vpTokenType: typeof vpToken,
          vpTokenLength: typeof vpToken === 'string' ? vpToken.length : 'N/A'
        });

        // For HAIP dc_api.jwt with Digital Credentials API, the vpToken might be an object
        // with credential IDs as keys and mdoc data as values
        let mdocData;
        if (typeof vpToken === 'object' && vpToken !== null && !Array.isArray(vpToken)) {
          // Extract the actual mdoc data from the object structure
          const credentialKeys = Object.keys(vpToken);
          if (credentialKeys.length > 0) {
            mdocData = vpToken[credentialKeys[0]];
            console.log("Extracted mdoc data from credential ID:", credentialKeys[0]);
          } else {
            return res.status(400).json({ 
              error: "No credentials found in HAIP dc_api.jwt mdoc response" 
            });
          }
        } else {
          // If vpToken is already a string, use it directly
          mdocData = vpToken;
        }

        if (!mdocData || typeof mdocData !== 'string') {
          return res.status(400).json({ 
            error: "Invalid mdoc data in HAIP dc_api.jwt response",
            receivedType: typeof mdocData,
            vpTokenType: typeof vpToken
          });
        }

        console.log("Processing mdoc data:", mdocData.substring(0, 100) + "...");

        const verificationOptions = {
          requestedFields: vpSession.sdsRequested, // Apply selective disclosure if requested
          validateStructure: true,
          includeMetadata: true
        };

        // The document type should match what's in the mdoc - typically "org.iso.18013.5.1.mDL"
        // but we can also let verifyMdlToken auto-detect it or use the session's document type
        const documentType = vpSession.documentType || "org.iso.18013.5.1.mDL";
        const mdocResult = await verifyMdlToken(mdocData, verificationOptions, documentType);

        if (!mdocResult.success) {
          console.error("mDL verification failed:", mdocResult.error);
          return res.status(400).json({ 
            error: `mDL verification failed: ${mdocResult.error}`,
            details: mdocResult.details 
          });
        }

        const claims = mdocResult.claims;

        // Validate that extracted claims match what was requested
        if (vpSession.sdsRequested && !validateMdlClaims(claims, vpSession.sdsRequested)) {
          console.log("mDL claims do not match what was requested.");
          return res.status(400).json({
            error: "mDL claims do not match what was requested.",
            requested: vpSession.sdsRequested,
            received: Object.keys(claims)
          });
        }


        vpSession.status = "success";
        vpSession.claims = claims;
        vpSession.mdlMetadata = mdocResult.metadata; // Store metadata for debugging
        await storeVPSession(sessionId, vpSession);
        
        await logInfo(sessionId, "HAIP dc_api.jwt processing completed successfully", {
          status: "success",
          claimsCount: Object.keys(claims).length
        });
        
        return res.status(200).json({ status: "ok" });

      } catch (error) {
        console.error("Error processing HAIP dc_api.jwt response:", error);
        await logError(sessionId, "Error processing HAIP dc_api.jwt response", {
          error: error.message,
          stack: error.stack
        });
        return res.status(400).json({ error: `HAIP dc_api.jwt processing failed: ${error.message}` });
      }
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
    else if (vpSession.response_mode === 'direct_post.jwt') {
      await logInfo(sessionId, "Processing direct_post.jwt response mode", {
        responseMode: "direct_post.jwt"
      });
      
      // Surface wallet-reported error per OpenID4VP
      if (req.body && req.body.error) {
        await logError(sessionId, "Wallet reported error for direct_post.jwt", {
          error: req.body.error,
          error_description: req.body.error_description
        });
        return res.status(400).json({ error: req.body.error, error_description: req.body.error_description });
      }

      // According to OpenID4VP spec, direct_post.jwt sends response in 'response' parameter
      const jwtResponse = req.body.response;
      
      if (!jwtResponse) {
        await logError(sessionId, "No 'response' parameter in direct_post.jwt response");
        return res.status(400).json({ error: "No 'response' parameter in direct_post.jwt response" });
      }
      
      await logDebug(sessionId, "JWT response received", {
        hasJwtResponse: !!jwtResponse,
        jwtParts: jwtResponse?.split('.').length
      });
      
      try {
        // Check if it's encrypted (JWE has 5 parts)
        if (jwtResponse.split('.').length === 5) {
          console.log("Processing encrypted JWE response for direct_post.jwt");
          await logInfo(sessionId, "Processing encrypted JWE response for direct_post.jwt");
          
          // Decrypt the JWE - this may return JWT string (per spec) or payload object (wallet-specific)
          const decrypted = await decryptJWE(jwtResponse, privateKey, "direct_post.jwt");
          console.log("Decrypted result type:", typeof decrypted);
          await logDebug(sessionId, "JWE decryption completed", {
            decryptedType: typeof decrypted
          });
          
          let vpToken;
          
          if (typeof decrypted === 'string') {
            // OpenID4VP spec compliant: JWE decrypted to JWT string
            console.log("Processing JWT string from JWE (per OpenID4VP spec)");
            const decodedPayload = jwt.decode(decrypted);
            vpToken = decodedPayload?.vp_token;
            
            if (!vpToken) {
              console.log("No VP token in decrypted JWT response");
              return res.status(400).json({ error: "No VP token in decrypted JWT response" });
            }
          } else if (decrypted && decrypted.vp_token) {
            // Wallet-specific behavior: JWE decrypted to payload object
            console.log("Processing payload object from JWE (wallet-specific behavior)");
            vpToken = decrypted.vp_token;
          } else {
            return res.status(400).json({ error: "Failed to decrypt JWE response or no vp_token found" });
          }
          
          console.log("Extracted vp_token for processing");
          
          // Process the VP token as before
          const result = await extractClaimsFromRequest({ body: { vp_token: vpToken } }, digest);
          claimsFromExtraction = result.extractedClaims;
          jwtFromKeybind = result.keybindJwt;
        } else {
          console.log("Processing unencrypted JWT response for direct_post.jwt");
          // If not encrypted, just verify the signed JWT
          const decodedJWT = jwt.decode(jwtResponse);
          
          // Extract VP token from the JWT payload
          vpToken = decodedJWT?.vp_token;
          if (!vpToken) {
            console.log("No VP token in JWT response");
            return res.status(400).json({ error: "No VP token in JWT response" });
          }
          
          // Process the VP token as before
          const result = await extractClaimsFromRequest({ body: { vp_token: vpToken } }, digest);
          claimsFromExtraction = result.extractedClaims;
          jwtFromKeybind = result.keybindJwt;
        }

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
          console.log("No submitted nonce found in vp_token");
          return res.status(400).json({ error: "submitted nonce not found in vp_token" });
        }
        
        if (vpSession.nonce != submittedNonce) {
          console.log(`error nonces do not match ${submittedNonce} ${vpSession.nonce}`);
          return res.status(400).json({ error: "submitted nonce doesn't match the auth request one" });
        }

        // Verify audience if key-binding JWT provided
        if (jwtFromKeybind && jwtFromKeybind.payload && vpSession.client_id && jwtFromKeybind.payload.aud) {
          if (jwtFromKeybind.payload.aud !== vpSession.client_id) {
            await logError(sessionId, "aud claim does not match verifier client_id", {
              expected: vpSession.client_id,
              received: jwtFromKeybind.payload.aud
            });
            return res.status(400).json({ error: 'aud claim does not match verifier client_id' });
          }
        }

        // Process claims as before
        if (vpSession.sdsRequested && !hasOnlyAllowedFields(claimsFromExtraction, vpSession.sdsRequested)) {
          return res.status(400).json({
            error: "requested " + JSON.stringify(vpSession.sdsRequested) + "but received " + JSON.stringify(claimsFromExtraction),
          });
        }

        vpSession.status = "success";
        vpSession.claims = { ...claimsFromExtraction };
        await storeVPSession(sessionId, vpSession);
        
        await logInfo(sessionId, "direct_post.jwt processing completed successfully", {
          status: "success",
          claimsCount: Object.keys(claimsFromExtraction || {}).length
        });
        
        return res.status(200).json({ status: "ok" });

      } catch (error) {
        console.error("Error processing JWT response:", error);
        await logError(sessionId, "Error processing JWT response", {
          error: error.message,
          stack: error.stack
        });
        return res.status(400).json({ error: "Invalid JWT response" });
      }
    } 
    // Handle regular direct_post response mode
    else {
      await logInfo(sessionId, "Processing regular direct_post response mode", {
        responseMode: "direct_post"
      });

      try {
        // Surface wallet-reported error per OpenID4VP
        if (req.body && req.body.error) {
          await logError(sessionId, "Wallet reported error for direct_post", {
            error: req.body.error,
            error_description: req.body.error_description
          });
          return res.status(400).json({ error: req.body.error, error_description: req.body.error_description });
        }

        // Enforce state parameter presence and matching
        const submittedState = req.body.state;
        if (!submittedState) {
          await logError(sessionId, "state parameter missing in direct_post");
          return res.status(400).json({ error: 'state parameter missing' });
        }
        if (submittedState !== vpSession.state) {
          await logError(sessionId, "state mismatch in direct_post", {
            expected: vpSession.state,
            received: submittedState
          });
          return res.status(400).json({ error: 'state mismatch' });
        }

        await logDebug(sessionId, "Extracting claims from direct_post request");
        const result = await extractClaimsFromRequest(req, digest);
        claimsFromExtraction = result.extractedClaims;
        jwtFromKeybind = result.keybindJwt;
        
        await logInfo(sessionId, "Claims extracted successfully", {
          claimsCount: Object.keys(claimsFromExtraction || {}).length,
          hasKeybindJwt: !!jwtFromKeybind
        });
      }catch(error){
        console.error("Error processing direct_post response:", error);
        await logError(sessionId, "Error processing direct_post response", {
          error: error.message,
          stack: error.stack
        });
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
          console.log("No submitted nonce found in vp_token");
          await logError(sessionId, "No submitted nonce found in vp_token");
          return res.status(400).json({ error: "submitted nonce not found in vp_token" });
        }
        
        await logDebug(sessionId, "Nonce found in VP token", {
          submittedNonce,
          expectedNonce: vpSession.nonce
        });
    

      if (vpSession.nonce != submittedNonce) {
        console.log(`error nonces do not match ${submittedNonce} ${vpSession.nonce}`);
        await logError(sessionId, "Nonce mismatch", {
          submittedNonce,
          expectedNonce: vpSession.nonce
        });
        return res.status(400).json({ error: "submitted nonce doesn't match the auth request one" });
      }
      
      // Verify audience if key-binding JWT provided
      if (jwtFromKeybind && jwtFromKeybind.payload && vpSession.client_id && jwtFromKeybind.payload.aud) {
        if (jwtFromKeybind.payload.aud !== vpSession.client_id) {
          await logError(sessionId, "aud claim does not match verifier client_id", {
            expected: vpSession.client_id,
            received: jwtFromKeybind.payload.aud
          });
          return res.status(400).json({ error: 'aud claim does not match verifier client_id' });
        }
      }

      await logInfo(sessionId, "Nonce verification successful");

      if (vpSession.sdsRequested && !hasOnlyAllowedFields(claimsFromExtraction, vpSession.sdsRequested)) {
        return res.status(400).json({
          error: "requested " + JSON.stringify(vpSession.sdsRequested) + "but received " + JSON.stringify(claimsFromExtraction),
        });
      }

      vpSession.status = "success";
      vpSession.claims = { ...claimsFromExtraction };
      await storeVPSession(sessionId, vpSession);
      console.log(`vp session ${sessionId} status is success`);
      
      await logInfo(sessionId, "direct_post processing completed successfully", {
        status: "success",
        claimsCount: Object.keys(claimsFromExtraction || {}).length
      });
      
      return res.status(200).json({ status: "ok" });
    }
  } catch (error) {
    console.error("Error processing request:", error.message);
    await logError(sessionId, "Error processing direct_post request", {
      error: error.message,
      stack: error.stack
    });
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
  const state = generateNonce(16);
  const nonce = generateNonce(16);

  const response_uri = serverURL + "/direct_post/" + uuid;
  let clientId = serverURL + "/direct_post/" + uuid;

  // Store session with state and nonce using Redis instead of in-memory array
  await storeVPSession(uuid, {
    uuid: uuid,
    status: "pending",
    claims: null,
    presentation_definition: presentation_definition_jwt,
    nonce: nonce,
    state: state,
    response_mode: "direct_post"
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
    state: state,
  };

  // console.log("will send vpRequest");
  // console.log(vpRequest);

  res.json(vpRequest);
});

// *******************PILOT USE CASES ******************************
verifierRouter.get("/vp-request/:type", async (req, res) => {
  const { type } = req.params;
  const stateParam = req.query.id ? req.query.id : uuidv4();
  
  await logInfo(stateParam, "Generating VP request", {
    endpoint: "/vp-request/:type",
    type,
    sessionId: stateParam
  });
  
  const nonce = generateNonce(16);
  await logDebug(stateParam, "Generated nonce for VP request", {
    nonce
  });

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

  await logDebug(stateParam, "Generating QR code for VP request");
  let code = qr.image(vpRequest, {
    type: "png",
    ec_level: "H",
    size: 10,
    margin: 10,
  });
  let mediaType = "PNG";
  let encodedQR = imageDataURI.encode(await streamToBuffer(code), mediaType);
  
  await logInfo(stateParam, "VP request generated successfully", {
    hasQR: !!encodedQR,
    deepLinkLength: vpRequest?.length,
    sessionId: stateParam
  });
  
  res.json({
    qr: encodedQR,
    deepLink: vpRequest,
    sessionId: stateParam,
  });
});

verifierRouter.get("/vpRequest/:type/:id", async (req, res) => {
  const { type, id } = req.params;
  const uuid = id ? id : uuidv4();
  
  await logInfo(uuid, "Processing VP request by type and ID", {
    endpoint: "/vpRequest/:type/:id",
    type,
    id,
    uuid
  });
  
  const state = generateNonce(16);
  const nonce = generateNonce(16);
  
  await logDebug(uuid, "Generated parameters for VP request", {
    state,
    nonce
  });

  const response_uri = `${serverURL}/direct_post/${uuid}`;
  let clientId = `${serverURL}/direct_post/${uuid}`;

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
    await logError(uuid, "Invalid type parameter for VP request", {
      type,
      validTypes: ["pid", "epassport", "educationId", "educationid", "allianceId", "allianceid", "ferryboardingpass", "erua-id", "cff"]
    });
    return res.status(400).type("text/plain").send("Invalid type parameter");
  }

  await logInfo(uuid, "Presentation definition selected", {
    type,
    hasPresentationDefinition: !!presentationDefinition
  });

  // Store session with state and nonce using Redis
  await storeVPSession(uuid, {
    uuid: uuid,
    status: "pending",
    claims: null,
    presentation_definition: presentationDefinition,
    nonce: nonce,
    state: state,
    response_mode: "direct_post"
  });

  await logDebug(uuid, "Building VP request JWT");
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
    "direct_post", // response_mode
    undefined, // audience
    undefined, // wallet_nonce
    undefined, // wallet_metadata
    undefined, // va_jwt
    state // CRITICAL: pass state to ensure it matches session
  );
  
  await logInfo(uuid, "VP request JWT generated successfully", {
    jwtLength: vpRequestJWT?.length
  });
  
  res.type("application/oauth-authz-req+jwt").send(vpRequestJWT);
});

verifierRouter.post("/direct_post_jwt/:id", async (req, res) => {
  const sessionId = req.params.id;
  const jwtVp = req.body.vp_token;
  
  await logInfo(sessionId, "Received direct_post JWT VP", {
    endpoint: "/direct_post_jwt/:id",
    sessionId,
    hasVpToken: !!jwtVp
  });
  
  // Log received request
  console.log("Received direct_post VP for session:", sessionId);
  if (!jwtVp) {
    console.error("No VP token provided.");
    await logError(sessionId, "No VP token provided in direct_post_jwt request");
    return res.sendStatus(400); // Bad Request
  }
  let decodedWithHeader;
  try {
    decodedWithHeader = jwt.decode(jwtVp, { complete: true });
  } catch (error) {
    console.error("Failed to decode JWT:", error);
    await logError(sessionId, "Failed to decode JWT in direct_post_jwt", {
      error: error.message,
      stack: error.stack
    });
    return res.sendStatus(400); // Bad Request due to invalid JWT
  }
  const credentialsJwtArray =
    decodedWithHeader?.payload?.vp?.verifiableCredential;
  if (!credentialsJwtArray) {
    console.error("Invalid JWT structure.");
    await logError(sessionId, "Invalid JWT structure in direct_post_jwt", {
      hasPayload: !!decodedWithHeader?.payload,
      hasVp: !!decodedWithHeader?.payload?.vp
    });
    return res.sendStatus(400); // Bad Request
  }
  
  await logDebug(sessionId, "JWT decoded successfully", {
    credentialsCount: credentialsJwtArray?.length
  });
  // Convert credentials to claims
  let claims;
  try {
    console.log(credentialsJwtArray);
    claims = await flattenCredentialsToClaims(credentialsJwtArray, sessionId);
    console.log(claims);
    if (!claims) {
      throw new Error("Claims conversion returned null or undefined.");
    }
  } catch (error) {
    console.error("Error processing claims:", error);
    await logError(sessionId, "Error processing claims in direct_post_jwt", {
      error: error.message,
      stack: error.stack
    });
    return res.sendStatus(500); // Internal Server Error
  }
  // Update session status
  const index = sessions.indexOf(sessionId);
  console.log("Session index:", index);
  await logDebug(sessionId, "Looking up session index", {
    index,
    sessionId
  });
  
  if (index === -1) {
    console.error("Session ID not found.");
    await logError(sessionId, "Session ID not found in direct_post_jwt", {
      sessionId
    });
    return res.sendStatus(404); // Not Found
  }
  // Log successful verification
  verificationSessions[index].status = "success";
  verificationSessions[index].claims = claims;
  console.log("Verification success:", verificationSessions[index]);
  
  await logInfo(sessionId, "direct_post_jwt verification completed successfully", {
    status: "success",
    claimsCount: Object.keys(claims || {}).length
  });
  
  res.sendStatus(200); // OK
});

verifierRouter.get(["/verificationStatus"], async (req, res) => {
  let sessionId = req.query.sessionId;
  await logInfo(sessionId, "Checking verification status", {
    endpoint: "/verificationStatus",
    sessionId
  });
  
  // let index = sessions.indexOf(sessionId); // sessions.indexOf(sessionId+""); //
  const vpSession = await getVPSession(sessionId);

  // console.log("index is");
  // console.log(index);
  let result = null;
  if (vpSession) {
    let status = vpSession.status;
    console.log(`sending status ${status} for session ${sessionId}`);
    await logInfo(sessionId, "Verification status retrieved", {
      status,
      hasResult: status === "success"
    });
    
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
    await logWarn(sessionId, "Verification status not found", {
      sessionId
    });
    res.json({
      status: "failed",
      reason: "not found",
      sessionId: sessionId,
    });
  }
});

verifierRouter.get(["/verificationStatusHistory"], async (req, res) => {
  let sessionId = req.query.sessionId;
  await logInfo(sessionId, "Checking verification status history", {
    endpoint: "/verificationStatusHistory",
    sessionId
  });
  
  const vpSession = await getVPSession(sessionId);
  // let index = sessionHistory.getCurrentArray().indexOf(sessionId);
  if (vpSession) {
    await logInfo(sessionId, "Verification status history retrieved", {
      status: vpSession.status
    });
    res.json(vpSession);
  } else {
    await logWarn(sessionId, "Verification status history not found", {
      sessionId
    });
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

async function flattenCredentialsToClaims(credentials, sessionId = null) {
  if (sessionId) {
    await logDebug(sessionId, "Flattening credentials to claims", {
      credentialsCount: credentials?.length
    });
  }
  
  let claimsResult = {};
  credentials.forEach((credentialJwt) => {
    let decodedCredential = jwt.decode(credentialJwt, {
      complete: true,
    });
    if (decodedCredential) {
      let claims = decodedCredential.payload.vc.credentialSubject;
      console.log(claims);
      if (sessionId) {
        logDebug(sessionId, "Decoded credential claims", {
          claims: Object.keys(claims)
        }).catch(err => console.error("Failed to log credential claims:", err));
      }
      claimsResult = { ...claimsResult, ...claims };
    }
  });
  
  if (sessionId) {
    await logInfo(sessionId, "Claims flattening completed", {
      totalClaimsCount: Object.keys(claimsResult).length
    });
  }
  
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
