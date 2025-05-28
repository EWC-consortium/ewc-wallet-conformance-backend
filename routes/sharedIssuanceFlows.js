import express from "express";
import fs from "fs";
import path from "path";
import { v4 as uuidv4 } from "uuid";
import {
  pemToJWK,
  generateNonce,
  base64UrlEncodeSha256,
  jarOAutTokenResponse,
  didKeyToJwks,
} from "../utils/cryptoUtils.js";
import {
  buildAccessToken,
  generateRefreshToken,
  buildIdToken,
} from "../utils/tokenUtils.js";

import {
  getAuthCodeSessions,
  getAuthCodeAuthorizationDetail,
} from "../services/cacheService.js";

import {
  storePreAuthSession,
  getPreAuthSession,
  getSessionKeyFromAccessToken,
  getCodeFlowSession,
  storeCodeFlowSession,
  getSessionKeyAuthCode,
  getSessionAccessToken,
  getDeferredSessionTransactionId,
} from "../services/cacheServiceRedis.js";

import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import {
  createSignerVerifier,
  digest,
  generateSalt,
  createSignerVerifierX509,
  pemToBase64Der,
} from "../utils/sdjwtUtils.js";
import jwt from "jsonwebtoken";
import jwkToPem from 'jwk-to-pem';

import {
  createPIDPayload,
  createStudentIDPayload,
  getPIDSDJWTData,
  getStudentIDSDJWTData,
  getGenericSDJWTData,
  getEPassportSDJWTData,
  createEPassportPayload,
  getVReceiptSDJWTData,
  getVReceiptSDJWTDataWithPayload,
  createPaymentWalletAttestationPayload,
  createPhotoIDAttestationPayload,
  getFerryBoardingPassSDJWTData,
  createPCDAttestationPayload,
} from "../utils/credPayloadUtil.js";

import { handleVcSdJwtFormat, handleVcSdJwtFormatDeferred } from "../utils/credGenerationUtils.js";

const sharedRouter = express.Router();

// Helper to load issuer configuration
// In a production app, consider caching this or loading it once at startup.
const loadIssuerConfig = () => {
  const configPath = path.join(process.cwd(), "data", "issuer-config.json");
  const configFile = fs.readFileSync(configPath, "utf-8");
  return JSON.parse(configFile);
};

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");
const privateKeyPemX509 = fs.readFileSync(
  "./x509EC/ec_private_pkcs8.key",
  "utf8"
);
const certificatePemX509 = fs.readFileSync(
  "./x509EC/client_certificate.crt",
  "utf8"
);

const { signer, verifier } = await createSignerVerifierX509(
  privateKeyPemX509,
  certificatePemX509
);

//   console.log("privateKey");
//   console.log(privateKey);

// *********************************************************************

// *****************************************************************
// ************* TOKEN ENDPOINTS ***********************************
// *****************************************************************

sharedRouter.post("/token_endpoint", async (req, res) => {
  // Fetch the Authorization header
  const authorizationHeader = req.headers["authorization"]; // Fetch the 'Authorization' header
  // console.log("token_endpoint authorizatiotn header-" + authorizationHeader);

  const clientAttestation = req.headers["OAuth-Client-Attestation"]; //this is the WUA
  const pop = req.headers["OAuth-Client-Attestation-PoP"];

  //pre-auth code flow
  const preAuthorizedCode = req.body["pre-authorized_code"]; // req.body["pre-authorized_code"]
  const tx_code = req.body["tx_code"];
  //TODO check tx_code as well

  // check if for this auth session we are issuing a PID credential to validate the WUA and PoP
  if (preAuthorizedCode) {
    let existingPreAuthSession = await getPreAuthSession(preAuthorizedCode);
    //TODO validatte WUA and PoP
    if (existingPreAuthSession && existingPreAuthSession.isPID) {
      console.log("pid issuance detected will check WUA and PoP");
      console.log(clientAttestation);
      console.log(pop);
    }
  }

  //code flow
  const grantType = req.body.grant_type;
  const client_id = req.body.client_id;
  const code = req.body["code"];
  const code_verifier = req.body["code_verifier"];
  const redirect_uri = req.body["redirect_uri"];

  let generatedAccessToken = buildAccessToken(serverURL, privateKey);

  let authorization_details_for_response = getAuthCodeAuthorizationDetail().get(code);

  if (!(code || preAuthorizedCode)) {
    // RFC6749 Section 5.2: invalid_request
    // OID4VCI 6.6.3: Could also be more specific if context allowed, but generic invalid_request is safe.
    return res.status(400).json({ 
      error: "invalid_request", 
      error_description: "The request is missing the 'code' or 'pre-authorized_code' parameter." 
    });
  } else {
    if (grantType == "urn:ietf:params:oauth:grant-type:pre-authorized_code") {
      console.log("pre-auth code flow");
      let chosenCredentialConfigurationId = null;

      if (req.body.authorization_details) {
        try {
          let parsedAuthDetails = req.body.authorization_details;
          // If it's a string, it might be URL-encoded JSON, as in spec examples
          if (typeof parsedAuthDetails === 'string') {
            parsedAuthDetails = JSON.parse(decodeURIComponent(parsedAuthDetails));
          }

          // Assuming authorization_details is an array as per spec
          if (Array.isArray(parsedAuthDetails) && parsedAuthDetails.length > 0) {
            // Prioritize the first one if multiple are sent, or implement more specific logic
            if (parsedAuthDetails[0].credential_configuration_id) {
              chosenCredentialConfigurationId = parsedAuthDetails[0].credential_configuration_id;
              console.log(`Wallet selected credential_configuration_id via authorization_details: ${chosenCredentialConfigurationId}`);
              // We will store this choice in the session.
              // The authorization_details object itself might also be stored or passed through if needed by the /credential endpoint directly.
              authorization_details_for_response = parsedAuthDetails; // Use the parsed one for the response
            } else {
              console.warn("authorization_details provided in token request body but missing credential_configuration_id in the first element.");
            }
          } else {
            console.warn("authorization_details provided in token request body was not a non-empty array or was malformed.");
          }
        } catch (e) {
          console.error("Error parsing authorization_details from token request body:", e);
          // Decide if this is a fatal error or if you proceed without it
          // For now, just log and continue, original authorization_details (if any) will be used or none.
        }
      }

      let existingPreAuthSession = await getPreAuthSession(preAuthorizedCode);
      if (existingPreAuthSession) {
        console.log(
          `Issuing token for pre-authorized session ${preAuthorizedCode}`
        );
        existingPreAuthSession.status = "success";
        existingPreAuthSession.accessToken = generatedAccessToken;
        
        if (chosenCredentialConfigurationId) {
          existingPreAuthSession.chosenCredentialConfigurationId = chosenCredentialConfigurationId;
        }
        // Store the c_nonce in the session for later validation at the credential endpoint
        const cNonceForSession = generateNonce(); // Generate c_nonce here to ensure it's in session and response
        existingPreAuthSession.c_nonce = cNonceForSession;

        let personaId = getPersonaPart(preAuthorizedCode);
        if (personaId) {
          existingPreAuthSession.persona = personaId;
        }
        storePreAuthSession(preAuthorizedCode, existingPreAuthSession);
        
        // Prepare response, ensuring c_nonce is consistent
        const tokenResponse = {
            access_token: generatedAccessToken,
            refresh_token: generateRefreshToken(),
            token_type: "bearer",
            expires_in: 86400,
            c_nonce: cNonceForSession, // Use the c_nonce stored in session
            c_nonce_expires_in: 86400,
        };
        if (authorization_details_for_response) {
            tokenResponse.authorization_details = authorization_details_for_response;
        }
        return res.json(tokenResponse);

      } else {
        // Handle case where pre-authorized code is invalid or session expired
        return res.status(400).json({ 
            error: "invalid_grant", 
            error_description: "Invalid or expired pre-authorized code."
        });
      }
    } else if (grantType == "authorization_code") {
      console.log("codeSessions ==> grantType == authorization_code");
      let issuanceSessionId = await getSessionKeyAuthCode(code);
      if (issuanceSessionId) {
        let existingCodeSession = await getCodeFlowSession(issuanceSessionId);
        if (existingCodeSession) {
          // TODO: if PKCE validation fails, the flow should respond with an error
          const pkceVerified = await validatePKCE(
            existingCodeSession,
            code, // code from request
            code_verifier, // code_verifier from request
            existingCodeSession.requests // PKCE challenge stored here (e.g., existingCodeSession.requests.challenge)
          );

          if (!pkceVerified) {
             console.log("PKCE verification failed for authorization_code flow.");
             return res.status(400).json({
                error: "invalid_grant",
                error_description: "PKCE verification failed."
             });
          }

          existingCodeSession.results.status = "success";
          existingCodeSession.status = "success";
          existingCodeSession.requests.accessToken = generatedAccessToken;
          
          // Store the c_nonce in the session for later validation at the credential endpoint
          const cNonceForSession = generateNonce();
          existingCodeSession.c_nonce = cNonceForSession;

          storeCodeFlowSession(
            existingCodeSession.results.issuerState, // or issuanceSessionId, ensure correct key is used
            existingCodeSession
          );

          // Prepare response
          const tokenResponse = {
            access_token: generatedAccessToken,
            refresh_token: generateRefreshToken(),
            token_type: "bearer",
            expires_in: 86400,
            c_nonce: cNonceForSession,
            c_nonce_expires_in: 86400,
          };
          if (authorization_details_for_response) { // This is from getAuthCodeAuthorizationDetail().get(code)
            tokenResponse.authorization_details = authorization_details_for_response;
          } else {
            // As per spec, id_token is not typically returned when access_token is, unless it's OIDC hybrid flow.
            // For VCI, c_nonce is more relevant here. Consider if id_token is strictly needed.
            // tokenResponse.id_token = buildIdToken(serverURL, privateKey);
          }
          return res.json(tokenResponse);
        }
      }
      // If session or code is invalid for authorization_code flow
      return res.status(400).json({ 
        error: "invalid_grant", 
        error_description: "Invalid or expired authorization code or session not found."
      });
    } else {
        // Fallback for unknown grant_type or if logic didn't return earlier
        return res.status(400).json({ 
            error: "unsupported_grant_type", 
            error_description: `Grant type '${grantType}' is not supported.`
        });
    }
    // This part should not be reached if grant types are handled with returns
  }
});

// *****************************************************************
// ************* CREDENTIAL ENDPOINTS ******************************
// *****************************************************************

sharedRouter.post("/credential", async (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Split "Bearer" and the token
  const requestBody = req.body;
  const format = requestBody.format;
  
  // Update according to spec section 8.2 - Credential identifiers
  const credentialIdentifier = requestBody.credential_identifier;
  const credentialConfigurationId = requestBody.credential_configuration_id;
  
  // Check that one and only one of the credential identifiers is present
  if ((credentialIdentifier && credentialConfigurationId) || 
      (!credentialIdentifier && !credentialConfigurationId)) {
    console.log("Invalid credential request: Must provide exactly one of credential_identifier or credential_configuration_id");
    return res.status(400).json({ 
      error: "invalid_credential_request",
      error_description: "Must provide exactly one of credential_identifier or credential_configuration_id" 
    });
  }
  
  // Determine the ID to use for looking up metadata configuration.
  // For proof validation, credential_configuration_id is more direct.
  // If only credential_identifier is provided, you might need a way to map it back to a configuration
  // or assume it implies a specific configuration if your system supports that.
  // For this change, we'll prioritize credential_configuration_id for fetching proof validation rules.
  const effectiveConfigurationId = credentialConfigurationId; 

  if (!effectiveConfigurationId && credentialIdentifier) {
     console.warn("Proof validation based on metadata currently relies on credential_configuration_id. Credential_identifier was provided without it.");
      // Depending on policy, you might allow this and skip specific alg validation or enforce credential_configuration_id for requests needing such validation.
  }

  if (!requestBody.proof || !requestBody.proof.jwt) {
    /*
       Object containing the proof of possession of the cryptographic key material the issued Credential would be bound to. 
       The proof object is REQUIRED if the proof_types_supported parameter is non-empty and present in the credential_configurations_supported parameter 
       of the Issuer metadata for the requested Credential
  
       This issuer atm only supports jwt proof types
      */
    console.log("NO keybinding info found!!!");
    return res.status(400).json({ 
      error: "invalid_proof",
      error_description: "No proof information found" 
    });
  }

  // New Proof Validation Logic
  if (effectiveConfigurationId) { // Only if we have a configuration ID to look up
    try {
      const issuerConfig = loadIssuerConfig();
      const credConfig = issuerConfig.credential_configurations_supported[effectiveConfigurationId];

      if (!credConfig) {
        console.log(`Invalid credential_configuration_id: ${effectiveConfigurationId} not found in issuer metadata.`);
        return res.status(400).json({
          error: "invalid_credential_request",
          error_description: `Credential configuration ID '${effectiveConfigurationId}' not found.`
        });
      }

      if (credConfig.proof_types_supported && credConfig.proof_types_supported.jwt) {
        const supportedAlgs = credConfig.proof_types_supported.jwt.proof_signing_alg_values_supported;
        if (supportedAlgs && supportedAlgs.length > 0) {
          const proofJwt = requestBody.proof.jwt;
          const decodedProofHeader = jwt.decode(proofJwt, { complete: true })?.header;

          if (!decodedProofHeader || !decodedProofHeader.alg) {
            console.log("Proof JWT header or alg is missing.");
            return res.status(400).json({
              error: "invalid_proof",
              error_description: "Proof JWT is malformed or missing algorithm."
            });
          }

          if (!supportedAlgs.includes(decodedProofHeader.alg)) {
            console.log(`Unsupported proof algorithm: ${decodedProofHeader.alg}. Supported: ${supportedAlgs.join(", ")}`);
            return res.status(400).json({
              error: "invalid_proof",
              error_description: `Proof JWT uses an unsupported algorithm '${decodedProofHeader.alg}'. Supported algorithms are: ${supportedAlgs.join(", ")}.`
            });
          }
          console.log(`Proof JWT algorithm ${decodedProofHeader.alg} is supported.`);

          // --- Start Full Signature and Claim Verification ---
          let publicKeyForProof; // This will hold the JWK for verification

          if (decodedProofHeader.jwk) {
            publicKeyForProof = decodedProofHeader.jwk;
          } else if (decodedProofHeader.kid && decodedProofHeader.kid.startsWith("did:key:")) {
            try {
              // Assuming didKeyToJwks can convert a did:key string to a JWK object
              // You might need to adjust this based on your didKeyToJwks implementation
              const jwks = didKeyToJwks(decodedProofHeader.kid);
              if (jwks && jwks.keys && jwks.keys.length > 0) {
                publicKeyForProof = jwks.keys[0]; // Use the first key
              } else {
                throw new Error("Failed to resolve did:key to JWK or JWKS was empty.");
              }
            } catch (jwkError) {
              console.error("Error resolving did:key to JWK:", jwkError);
              return res.status(400).json({
                error: "invalid_proof",
                error_description: "Failed to resolve public key from proof JWT kid (did:key)."
              });
            }
          } else {
            console.log("Proof JWT header does not contain jwk or a resolvable did:key kid.");
            return res.status(400).json({
              error: "invalid_proof",
              error_description: "Public key for proof verification not found in JWT header."
            });
          }

          if (!publicKeyForProof) {
             // This case should ideally be caught by the checks above
            console.log("Public key for proof could not be determined.");
            return res.status(400).json({
                error: "invalid_proof",
                error_description: "Unable to determine public key for proof verification."
            });
          }
          
          // Verify the signature
          let proofPayload;
          try {
            // Note: jsonwebtoken.verify needs a PEM or JWK for the key.
            // If publicKeyForProof is a JWK object, it should work directly with some libraries or might need conversion for others.
            // For 'jsonwebtoken', if publicKeyForProof is a JWK, it might need to be converted to PEM format first, 
            // or ensure your version of jsonwebtoken handles JWK directly for verification.
            // For simplicity, let's assume direct JWK verification is possible or you have a utility for it.
            // A common pattern is to use a library like 'jose' for robust JWK handling.
            // **** IMPORTANT: Review this part based on your JWT library's capabilities for JWK verification ****
            // If using `jsonwebtoken` and it needs PEM, you'd need a jwkToPem utility.
            // For now, we will proceed as if a JWK object can be used, but this is a critical check.
            proofPayload = jwt.verify(proofJwt, publicKeyToPem(publicKeyForProof), { // publicKeyToPem is a placeholder for a required utility
                algorithms: [decodedProofHeader.alg], // Ensure only the validated alg is used
                audience: serverURL, // Expected audience is this issuer server
            });
          } catch (jwtError) {
            console.error("Proof JWT signature verification failed:", jwtError);
            return res.status(401).json({
              error: "invalid_proof",
              error_description: `Proof JWT signature verification failed: ${jwtError.message}`
            });
          }

          // Verify claims
          if (!proofPayload.iss) {
            console.log("Proof JWT missing 'iss' claim.");
            return res.status(400).json({
              error: "invalid_proof",
              error_description: "Proof JWT is missing sender identifier (iss claim)."
            });
          }

          // c_nonce check - CRITICAL for replay protection
          //TODO CHECK THIS IMPLEMENTATION
          // Retrieve the session object to get the server-side c_nonce
          // This reuses the session retrieval logic that is already present later in this endpoint
          let sessionForNonceCheck = null;
          const preAuthSessionKeyForNonce = await getSessionKeyFromAccessToken(token);
          if (preAuthSessionKeyForNonce) {
            sessionForNonceCheck = await getPreAuthSession(preAuthSessionKeyForNonce);
          }
          if (!sessionForNonceCheck) {
            const codeSessionKeyForNonce = await getSessionAccessToken(token);
            if (codeSessionKeyForNonce) {
                sessionForNonceCheck = await getCodeFlowSession(codeSessionKeyForNonce);
            }
          }

          if (!sessionForNonceCheck || !sessionForNonceCheck.c_nonce) {
            console.error("Server c_nonce for the session not found. This is a server-side issue or session problem.");
            return res.status(500).json({
              error: "server_error",
              error_description: "Could not retrieve server nonce for validation."
            });
          }

          if (proofPayload.nonce !== sessionForNonceCheck.c_nonce) {
            console.log(`Proof JWT nonce mismatch. Expected: ${sessionForNonceCheck.c_nonce}, Got: ${proofPayload.nonce}`);
            return res.status(400).json({
              error: "invalid_proof",
              error_description: "Proof JWT nonce does not match expected server nonce."
            });
          }
          // console.log("Proof JWT nonce verified."); // Already have a similar log message later

          // Optional: Log iss for tracking
          console.log(`Proof JWT validated. Issuer (Wallet): ${proofPayload.iss}, Nonce verified.`);

          // --- End Full Signature and Claim Verification --- 

        } else {
          console.log(`No proof signing algorithms defined for ${effectiveConfigurationId}, skipping algorithm validation.`);
        }
      } else {
        console.log(`No JWT proof type configuration found for ${effectiveConfigurationId}, skipping algorithm validation.`);
        // Depending on policy, you might require proof_types_supported to be defined.
      }
    } catch (err) {
      console.error("Error during proof validation:", err);
      return res.status(500).json({
        error: "server_error",
        error_description: "An error occurred during proof validation."
      });
    }
  }
  // End of New Proof Validation Logic

  // let requestedCredentialType; // This is now determined based on credentialConfigurationId or credentialIdentifier
  // if (credentialIdentifier) {
  //   requestedCredentialType = [credentialIdentifier];
  // } else if (credentialConfigurationId) {
  //   requestedCredentialType = [credentialConfigurationId];
  // }

  // Retrieve sessionObject AGAIN - this is redundant if sessionForNonceCheck is the same sessionObject needed later.
  // We should use the session object (sessionForNonceCheck) already retrieved for the nonce check if it's the correct one.
  // For now, I will leave the later session retrieval logic as is, but this could be optimized.
  let requestedCredentialType;
  if (credentialIdentifier) {
    requestedCredentialType = [credentialIdentifier];
  } else if (credentialConfigurationId) {
    requestedCredentialType = [credentialConfigurationId];
  }


  let payload = {};

  // Session object retrieval (this logic is similar to what's now in the nonce check)
  const preAuthsessionKey = await getSessionKeyFromAccessToken(token); 
  let sessionObject; // This will be the main session object for the rest of the function
  if (preAuthsessionKey) {
    sessionObject = await getPreAuthSession(preAuthsessionKey);
    if (!sessionObject)
      sessionObject = await getCodeFlowSession(preAuthsessionKey);
  }
  if (!sessionObject) { // If not found in pre-auth, try code flow
    const codeSessionKey = await getSessionAccessToken(token); 
    if (codeSessionKey) {
      sessionObject = await getCodeFlowSession(codeSessionKey);
    }
  }

  // It is important that the `sessionObject` used from here on is the same one whose c_nonce was validated.
  // The nonce check block now fetches `sessionForNonceCheck`. We should ensure `sessionObject` here is consistent.
  // If the lookups are identical, `sessionForNonceCheck` is `sessionObject`.
  // Add a check or ensure consistency.
  if (!sessionObject) {
      console.error("Session object could not be retrieved after proof validation for credential issuance.");
      return res.status(500).json({ error: "server_error", error_description: "Session lost after proof validation." });
  }
  // At this point, sessionObject should be the one containing the validated c_nonce.


  if (sessionObject && sessionObject.isDeferred) {
    //Deferred flow
    let transaction_id = generateNonce();
    sessionObject.transaction_id = transaction_id;
    sessionObject.requestBody = requestBody;
    sessionObject.isCredentialReady = false;
    sessionObject.attempt = 0; //attempt to fetch credential counter

    if (sessionObject.flowType == "code") {
      await storeCodeFlowSession(codeSessionKey, sessionObject);
    } else {
      await storePreAuthSession(preAuthsessionKey, sessionObject);
    }

    // Update to use 202 status code for deferred issuance as specified in section 8.3
    res.status(202).json({
      transaction_id: transaction_id,
      c_nonce: generateNonce(),
      c_nonce_expires_in: 86400,
    });
  } else {
    // Immediate issuance flow
    if (format === "jwt_vc_json") {
      console.log("jwt ", requestedCredentialType);
      if (requestedCredentialType && requestedCredentialType[0] === "PID") {
        payload = createPIDPayload(token, serverURL, "");
      } else if (
        requestedCredentialType &&
        requestedCredentialType[0] === "ePassportCredential"
      ) {
        payload = createEPassportPayload(serverURL, "");
      } else if (
        requestedCredentialType &&
        requestedCredentialType[0] === "StudentID"
      ) {
        payload = createStudentIDPayload(serverURL, "");
      } else if (
        requestedCredentialType &&
        requestedCredentialType[0] === "ferryBoardingPassCredential"
      ) {
        payload = createEPassportPayload(serverURL, "");
      } else if (
        requestedCredentialType &&
        requestedCredentialType[0] === "PaymentWalletAttestationAccount"
      ) {
        payload = createPIDPayload(token, serverURL, "");
      }

      const signOptions = { algorithm: "ES256" };
      const additionalHeaders = {
        kid: "aegean#authentication-key",
        typ: "JWT",
      };
      const idtoken = jwt.sign(payload, privateKey, {
        ...signOptions,
        header: additionalHeaders,
      });

      // Update response to match the specification format in section 8.3
      res.json({
        credentials: [
          {
            credential: idtoken
          }
        ],
        c_nonce: generateNonce(),
        c_nonce_expires_in: 86400,
      });
    } else if (format === "vc+sd-jwt") {
      let vct = requestBody.vct;
      console.log("vc+sd-jwt ", vct);
      try {
        const credential = await handleVcSdJwtFormat(
          requestBody,
          sessionObject,
          serverURL
        );

        // We're assuming handleVcSdJwtFormat returns a raw credential
        // Wrap it in the proper format according to the specification
        res.json({
          credentials: [
            {
              credential
            }
          ],
          c_nonce: generateNonce(),
          c_nonce_expires_in: 86400,
        });
      } catch (err) {
        console.log(err);
        return res.status(400).json({ 
          error: "credential_request_denied", 
          error_description: err.message 
        });
      }
    } else {
      console.log("UNSUPPORTED FORMAT:", format);
      return res.status(400).json({ 
        error: "unsupported_credential_format",
        error_description: `Format '${format}' is not supported`
      });
    }
  }
});

// *****************************************************************
// ************* deferred ENDPOINTS ******************************
// *****************************************************************
sharedRouter.post("/credential_deferred", async (req, res) => {
  const authorizationHeader = req.headers["authorization"]; // Fetch the 'Authorization' header

  const transaction_id = req.body.transaction_id;
  const sessionId = await getDeferredSessionTransactionId(transaction_id);
  const sessionObject = await getCodeFlowSession(sessionId)
  if (!sessionObject) {
    return res.status(400).json({
      error: "invalid_transaction_id",
    });
  } else {
    /*
    issuance_pending: The Credential issuance is still pending. The error response SHOULD also contain the interval member, determining the minimum amount of time in seconds that the Wallet needs to wait before providing a new request to the Deferred Credential Endpoint. If interval member is not present, the Wallet MUST use 5 as the default value.
    */
    const credential = await handleVcSdJwtFormatDeferred(
      sessionObject,
      serverURL
    );
    return res.status(200).json({
      format: "vc+sd-jwt",
      credential, // Omit c_nonce here
    });
  }
});

// *****************************************************************
// ************* NONCE ENDPOINT ************************************
// *****************************************************************
// TODO this might need testing/validation
sharedRouter.post("/nonce", async (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ 
      error: "unauthorized", 
      error_description: "Access token is missing or invalid."
    });
  }

  let sessionObject = null;
  let sessionKey = null;

  // Try to get session from pre-auth flow cache
  sessionKey = await getSessionKeyFromAccessToken(token);
  if (sessionKey) {
    sessionObject = await getPreAuthSession(sessionKey);
  }

  // If not found, try to get session from code flow cache
  if (!sessionObject) {
    sessionKey = await getSessionAccessToken(token); // Note: This function name might be for pre-auth, ensure it's general or use a correct one for code flow access tokens
    if (sessionKey) {
      sessionObject = await getCodeFlowSession(sessionKey);
    }
  }

  if (!sessionObject) {
    console.log("No active session found for the provided access token for nonce request.");
    return res.status(401).json({ 
      error: "invalid_token", 
      error_description: "No active session found for the provided access token." 
    });
  }

  const newCNonce = generateNonce();
  const nonceExpiresIn = 86400; // Standard expiry, can be configured

  // Update the session object with the new c_nonce
  sessionObject.c_nonce = newCNonce;
  // Optionally, store the exact expiry time if needed for server-side checks later
  // sessionObject.c_nonce_expires_at = Date.now() + nonceExpiresIn * 1000;

  // Save the updated session
  if (sessionObject.flowType === "pre-auth") { // Assuming flowType is stored in session
    await storePreAuthSession(sessionKey, sessionObject); // sessionKey here should be preAuthorizedCode for pre-auth
  } else if (sessionObject.flowType === "code") { // Assuming flowType is stored in session
    // Ensure `sessionKey` for code flow refers to the correct key for `storeCodeFlowSession` 
    // (e.g., the issuerState or original session ID)
    // This might need adjustment based on how `getSessionAccessToken` provides the key for code flow.
    // If `sessionKey` from `getSessionAccessToken` is the access token itself, we need the original session ID.
    // For now, let's assume `sessionObject.results.issuerState` or a similar field holds the main session ID.
    const codeFlowSessionId = sessionObject.results?.issuerState || sessionObject.issuerState || sessionKey; 
    await storeCodeFlowSession(codeFlowSessionId, sessionObject);
  } else {
    console.error("Could not determine session flow type to update c_nonce.");
    // Decide if this is an error or if there's a default way to store
  }

  console.log(`Generated new c_nonce for session associated with token.`);

  res.status(200).json({
    c_nonce: newCNonce,
    c_nonce_expires_in: nonceExpiresIn,
  });
});

// *****************************************************************
// ITB
// *****************************************************************
sharedRouter.get(["/issueStatus"], async (req, res) => {
  let sessionId = req.query.sessionId;
  let existingPreAuthSession = await getPreAuthSession(sessionId);
  let perAuthStatus = existingPreAuthSession
    ? existingPreAuthSession.status
    : null;

  let codeFlowSession = await getCodeFlowSession(sessionId);
  let codeFlowStatus = codeFlowSession ? codeFlowSession.status : null;

  let result = perAuthStatus || codeFlowStatus;
  if (result) {
    console.log("wi9ll send result");
    console.log({
      status: result,
      reason: "ok",
      sessionId: sessionId,
    });
    res.json({
      status: result,
      reason: "ok",
      sessionId: sessionId,
    });
  } else {
    res.json({
      status: "failed",
      reason: "not found",
      sessionId: sessionId,
    });
  }
});

async function validatePKCE(sessions, code, code_verifier, issuanceResults) {
  if ((code = sessions.requests.challenge)) {
    let challenge = sessions.challenge;
    let tester = await base64UrlEncodeSha256(code_verifier);
    if (tester === challenge) {
      codeSessions.results.status = "success";
      console.log("PKCE verification success");
      return true;
    }
  }
  console.log("PKCE verification FAILED!!!");
  return false;
}

function getPersonaPart(inputString) {
  const personaKey = "persona=";
  const personaIndex = inputString.indexOf(personaKey);

  if (personaIndex === -1) {
    return null; // "persona=" not found in the string
  }

  // Split the string based on "persona="
  const parts = inputString.split(personaKey);

  // Return the part after "persona="
  return parts[1] || null;
}


const publicKeyToPem = (jwk) => {
  if (!jwk) {
    throw new Error('JWK is undefined or null.');
  }
  // The jwk-to-pem library expects the JWK itself.
  // It handles different key types (RSA, EC, etc.) internally.
  try {
    return jwkToPem(jwk);
  } catch (err) {
    console.error("Error converting JWK to PEM:", err);
    console.error("Problematic JWK:", JSON.stringify(jwk));
    throw new Error(`Failed to convert JWK to PEM: ${err.message}`);
  }
};

export default sharedRouter;
