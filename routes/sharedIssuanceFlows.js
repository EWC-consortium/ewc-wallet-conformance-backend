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
  storeNonce,
  checkNonce,
  deleteNonce,
} from "../services/cacheServiceRedis.js";

import * as jose from "jose";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import {
  createSignerVerifier,
  digest,
  generateSalt,
  createSignerVerifierX509,
  pemToBase64Der,
} from "../utils/sdjwtUtils.js";
import jwt from "jsonwebtoken";

import {
  handleVcSdJwtFormat,
  handleVcSdJwtFormatDeferred,
} from "../utils/credGenerationUtils.js";

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
  const body = req.body;
  let authorizationDetails = body.authorization_details;

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

  if (!(code || preAuthorizedCode)) {
    // RFC6749 Section 5.2: invalid_request
    // OID4VCI 6.6.3: Could also be more specific if context allowed, but generic invalid_request is safe.
    return res.status(400).json({
      error: "invalid_request",
      error_description:
        "The request is missing the 'code' or 'pre-authorized_code' parameter.",
    });
  } else {
    if (grantType == "urn:ietf:params:oauth:grant-type:pre-authorized_code") {
      console.log("pre-auth code flow");
      let chosenCredentialConfigurationId = null;
      let existingPreAuthSession = await getPreAuthSession(preAuthorizedCode);

      if (existingPreAuthSession) {
        //Credential Issuers MAY support requesting authorization to issue a Credential using the
        // authorization_details parameter. This is particularly useful, if the Credential Issuer offered
        // multiple Credential Configurations in the Credential Offer of a Pre-Authorized Code Flow.
        if (
          existingPreAuthSession.authorizationDetails &&
          !authorizationDetails
        ) {
          console.log(
            "!!!authorization_details found in session but not in request"
          );
          //TODO this should through an error
        }

        let parsedAuthDetails = authorizationDetails;
        if (authorizationDetails) {
          try {
            // If it's a string, it might be URL-encoded JSON, as in spec examples
            if (typeof parsedAuthDetails === "string") {
              parsedAuthDetails = JSON.parse(
                decodeURIComponent(parsedAuthDetails)
              );
            }

            // Assuming authorization_details is an array as per spec
            if (
              Array.isArray(parsedAuthDetails) &&
              parsedAuthDetails.length > 0
            ) {
              // Prioritize the first one if multiple are sent, or implement more specific logic
              if (parsedAuthDetails[0].credential_configuration_id) {
                chosenCredentialConfigurationId =
                  parsedAuthDetails[0].credential_configuration_id;
                console.log(
                  `Wallet selected credential_configuration_id via authorization_details: ${chosenCredentialConfigurationId}`
                );
                // We will store this choice in the session.
                authorization_details_for_response = parsedAuthDetails; // Use the parsed one for the response
              } else {
                console.warn(
                  "authorization_details provided in token request body but missing credential_configuration_id in the first element."
                );
              }
            } else {
              console.warn(
                "authorization_details provided in token request body was not a non-empty array or was malformed."
              );
            }
          } catch (e) {
            console.error(
              "Error parsing authorization_details from token request body:",
              e
            );
            // Decide if this is a fatal error or if you proceed without it
            // For now, just log and continue, original authorization_details (if any) will be used or none.
          }
        }

        console.log(
          `generating token for pre-authorized session ${preAuthorizedCode}`
        );
        existingPreAuthSession.status = "success";
        existingPreAuthSession.accessToken = generatedAccessToken;

        // Store the c_nonce in the session for later validation at the credential endpoint
        const cNonceForSession = generateNonce(); // Generate c_nonce here to ensure it's in session and response
        existingPreAuthSession.c_nonce = cNonceForSession;

        storePreAuthSession(preAuthorizedCode, existingPreAuthSession);

        // Prepare response, ensuring c_nonce is consistent
        const tokenResponse = {
          access_token: generatedAccessToken,
          refresh_token: generateRefreshToken(),
          token_type: "bearer",
          expires_in: 86400,
          // c_nonce: cNonceForSession, // Use the c_nonce stored in session
          // c_nonce_expires_in: 86400,
        };
        if (authorizationDetails) {
          parsedAuthDetails.credential_identifiers = [
            chosenCredentialConfigurationId,
          ];
          tokenResponse.authorization_details = parsedAuthDetails;
        }

        return res.json(tokenResponse);
      } else {
        // Handle case where pre-authorized code is invalid or session expired
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "Invalid or expired pre-authorized code.",
        });
      }
    } else if (grantType == "authorization_code") {
      console.log("codeSessions ==> grantType == authorization_code");
      let issuanceSessionId = await getSessionKeyAuthCode(code);
      if (issuanceSessionId) {
        let existingCodeSession = await getCodeFlowSession(issuanceSessionId);
        if (existingCodeSession) {
          // authorizationDetails =existingCodeSession.authorization_details;
          let scope = existingCodeSession.scope;

          const pkceVerified = await validatePKCE(
            existingCodeSession,
            code_verifier, // Pass only code_verifier, original code is not needed here
            existingCodeSession.requests.challenge // Pass the stored challenge directly
          );

          if (!pkceVerified) {
            console.log(
              "PKCE verification failed for authorization_code flow."
            );
            return res.status(400).json({
              error: "invalid_grant",
              error_description: "PKCE verification failed.",
            });
          }

          existingCodeSession.results.status = "success";
          existingCodeSession.status = "success";
          existingCodeSession.requests.accessToken = generatedAccessToken;

          // Store the c_nonce in the session for later validation at the credential endpoint
          const cNonceForSession = generateNonce();
          existingCodeSession.c_nonce = cNonceForSession;

          storeCodeFlowSession(
            existingCodeSession.results.issuerState,
            existingCodeSession
          );

          // Prepare response
          const tokenResponse = {
            access_token: generatedAccessToken,
            refresh_token: generateRefreshToken(),
            token_type: "Bearer",
            expires_in: 86400,
            // c_nonce: cNonceForSession,
            // c_nonce_expires_in: 86400, removed in ID2
          };
          if (authorizationDetails) {
            parsedAuthDetails.credential_identifiers = [
              chosenCredentialConfigurationId,
            ];
            tokenResponse.authorization_details = parsedAuthDetails;
          }
          // else{
          //   tokenResponse.authorization_details = [
          //     {
          //       type: "openid_credential",
          //       credential_configuration_id: scope,
          //       credential_identifiers: [scope],
          //     },
          //   ];
          // }
          return res.json(tokenResponse);
        }
      }
      // If session or code is invalid for authorization_code flow
      return res.status(400).json({
        error: "invalid_grant",
        error_description:
          "Invalid or expired authorization code or session not found.",
      });
    } else {
      // Fallback for unknown grant_type or if logic didn't return earlier
      return res.status(400).json({
        error: "unsupported_grant_type",
        error_description: `Grant type '${grantType}' is not supported.`,
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

  const proofJwt = requestBody.proof.jwt;
  // const format = requestBody.format; // this is not part of ID2. the format should be fetched form the

  //TODO: check if the token is valid and if it is a valid token for this issuer


  let flowType = "pre-auth";
  // Session object retrieval (this logic is similar to what's now in the nonce check)
  const preAuthsessionKey = await getSessionKeyFromAccessToken(token);
  let sessionObject; // This will be the main session object for the rest of the function
  if (preAuthsessionKey) {
    sessionObject = await getPreAuthSession(preAuthsessionKey);
    if (!sessionObject)
      sessionObject = await getCodeFlowSession(preAuthsessionKey);
  }
  if (!sessionObject) {
    // If not found in pre-auth, try code flow
    const codeSessionKey = await getSessionAccessToken(token);
    if (codeSessionKey) {
      sessionObject = await getCodeFlowSession(codeSessionKey);
      flowType = "code";
    }
  }



  // Update according to spec section 8.2 - Credential identifiers
  const credentialIdentifier = requestBody.credential_identifier;
  const credentialConfigurationId = requestBody.credential_configuration_id;

  // Check that one and only one of the credential identifiers is present
  if (
    (credentialIdentifier && credentialConfigurationId) ||
    (!credentialIdentifier && !credentialConfigurationId)
  ) {
    console.log(
      "Invalid credential request: Must provide exactly one of credential_identifier or credential_configuration_id"
    );
    return res.status(400).json({
      error: "invalid_credential_request",
      error_description:
        "Must provide exactly one of credential_identifier or credential_configuration_id",
    });
  }

  // Determine the ID to use for looking up metadata configuration.
  // For proof validation, credential_configuration_id is more direct.
  const effectiveConfigurationId =
    credentialConfigurationId || credentialIdentifier;

  if (!effectiveConfigurationId && credentialIdentifier) {
    console.warn(
      "Proof validation based on metadata currently relies on credential_configuration_id. Credential_identifier was provided without it."
    );
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
      error_description: "No proof information found",
    });
  }

  // New Proof Validation Logic
  if (effectiveConfigurationId) {
    // Only if we have a configuration ID to look up
    try {
      const issuerConfig = loadIssuerConfig();
      const credConfig =
        issuerConfig.credential_configurations_supported[
          effectiveConfigurationId
        ];

      if (!credConfig) {
        console.log(
          `Invalid credential_configuration_id: ${effectiveConfigurationId} not found in issuer metadata.`
        );
        return res.status(400).json({
          error: "invalid_credential_request",
          error_description: `Credential configuration ID '${effectiveConfigurationId}' not found.`,
        });
      }

      if (
        credConfig.proof_types_supported &&
        credConfig.proof_types_supported.jwt
      ) {
        const supportedAlgs =
          credConfig.proof_types_supported.jwt
            .proof_signing_alg_values_supported;
        if (supportedAlgs && supportedAlgs.length > 0) {
          const decodedProofHeader = jwt.decode(proofJwt, {
            complete: true,
          })?.header;

          if (!decodedProofHeader || !decodedProofHeader.alg) {
            console.log("Proof JWT header or alg is missing.");
            return res.status(400).json({
              error: "invalid_proof",
              error_description: "Proof JWT is malformed or missing algorithm.",
            });
          }

          if (!supportedAlgs.includes(decodedProofHeader.alg)) {
            console.log(
              `Unsupported proof algorithm: ${
                decodedProofHeader.alg
              }. Supported: ${supportedAlgs.join(", ")}`
            );
            return res.status(400).json({
              error: "invalid_proof",
              error_description: `Proof JWT uses an unsupported algorithm '${
                decodedProofHeader.alg
              }'. Supported algorithms are: ${supportedAlgs.join(", ")}.`,
            });
          }
          console.log(
            `Proof JWT algorithm ${decodedProofHeader.alg} is supported.`
          );

          // --- Start Full Signature and Claim Verification ---
          let publicKeyForProof; // This will hold the JWK for verification


          //TODO add support for did:web and did:jwk
          if (decodedProofHeader.jwk) {
            publicKeyForProof = decodedProofHeader.jwk;
          } else if (
            decodedProofHeader.kid &&
            decodedProofHeader.kid.startsWith("did:key:")
          ) {
            try {
              const jwks = await didKeyToJwks(decodedProofHeader.kid);
              if (jwks && jwks.keys && jwks.keys.length > 0) {
                publicKeyForProof = jwks.keys[0]; // Use the first key
              } else {
                throw new Error(
                  "Failed to resolve did:key to JWK or JWKS was empty."
                );
              }
            } catch (jwkError) {
              console.error("Error resolving did:key to JWK:", jwkError);
              return res.status(400).json({
                error: "invalid_proof",
                error_description:
                  "Failed to resolve public key from proof JWT kid (did:key).",
              });
            }
          } else if (
            decodedProofHeader.kid &&
            decodedProofHeader.kid.startsWith("did:jwk:")
          ) {
            try {
              const didJwk = decodedProofHeader.kid;
              const jwkPart = didJwk.substring("did:jwk:".length);
              const jwkString = Buffer.from(jwkPart, "base64url").toString(
                "utf8"
              );
              publicKeyForProof = JSON.parse(jwkString);
              console.log("Successfully resolved did:jwk to JWK.");
            } catch (error) {
              console.error("Error resolving did:jwk to JWK:", error);
              return res.status(400).json({
                error: "invalid_proof",
                error_description:
                  "Failed to resolve public key from proof JWT kid (did:jwk).",
              });
            }
          } else if (
            decodedProofHeader.kid &&
            decodedProofHeader.kid.startsWith("did:web:")
          ) {
            try {
              const didWeb = decodedProofHeader.kid;
              const [did, keyFragment] = didWeb.split("#");
              if (!keyFragment) {
                throw new Error(
                  "kid does not contain a key identifier fragment (e.g., #key-1)"
                );
              }

              let didUrlPart = did.substring("did:web:".length);
              didUrlPart = decodeURIComponent(didUrlPart);

              const didParts = didUrlPart.split(":");
              const domain = didParts.shift();
              const path = didParts.join("/");

              let didDocUrl;
              if (path) {
                didDocUrl = `https://${domain}/${path}/did.json`;
              } else {
                didDocUrl = `https://${domain}/.well-known/did.json`;
              }

              console.log(
                `Resolving did:web by fetching DID document from: ${didDocUrl}`
              );
              const response = await fetch(didDocUrl);
              if (!response.ok) {
                throw new Error(
                  `Failed to fetch DID document, status: ${response.status}`
                );
              }
              const didDocument = await response.json();
              if (!didDocument) {
                throw new Error(
                  `Failed to parse DID document or DID document is null for URL: ${didDocUrl}`
                );
              }

              const verificationMethod = didDocument.verificationMethod?.find(
                (vm) =>
                  vm.id === didWeb ||
                  (didDocument.id && didDocument.id + vm.id === didWeb)
              );

              if (!verificationMethod || !verificationMethod.publicKeyJwk) {
                throw new Error(
                  `Public key with id '${didWeb}' not found in DID document.`
                );
              }

              publicKeyForProof = verificationMethod.publicKeyJwk;
              console.log(
                `Successfully resolved did:web and found public key for kid: ${didWeb}`
              );
            } catch (error) {
              console.error("Error resolving did:web:", error);
              return res.status(400).json({
                error: "invalid_proof",
                error_description: `Failed to resolve public key from proof JWT kid (did:web): ${error.message}`,
              });
            }
          } else {
            console.log(
              "Proof JWT header does not contain jwk or a resolvable DID kid (did:key, did:jwk, did:web)."
            );
            return res.status(400).json({
              error: "invalid_proof",
              error_description:
                "Public key for proof verification not found in JWT header.",
            });
          }

          if (!publicKeyForProof) {
            // This case should ideally be caught by the checks above
            console.log("Public key for proof could not be determined.");
            return res.status(400).json({
              error: "invalid_proof",
              error_description:
                "Unable to determine public key for proof verification.",
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

            proofPayload = jwt.verify(
              proofJwt,
              await publicKeyToPem(publicKeyForProof),
              {
                // publicKeyToPem is a placeholder for a required utility
                algorithms: [decodedProofHeader.alg], // Ensure only the validated alg is used
                audience: serverURL, // Expected audience is this issuer server
              }
            );
          } catch (jwtError) {
            console.error("Proof JWT signature verification failed:", jwtError);
            return res.status(401).json({
              error: "invalid_proof",
              error_description: `Proof JWT signature verification failed: ${jwtError.message}`,
            });
          }

          // Verify claims
          if (!proofPayload.iss && flowType == "code") {
            console.log("Proof JWT missing 'iss' claim.");
            return res.status(400).json({
              error: "invalid_proof",
              error_description:
                "Proof JWT is missing sender identifier (iss claim).",
            });
          }

          // c_nonce check - CRITICAL for replay protection
          // Check if the nonce exists in Redis cache
          const nonceExists = await checkNonce(proofPayload.nonce);
          if (!nonceExists) {
            console.log(
              `Proof JWT nonce not found in cache or expired: ${proofPayload.nonce}`
            );
            return res.status(400).json({
              error: "invalid_proof",
              error_description:
                "Proof JWT nonce is invalid, expired, or already used.",
            });
          }

          // Delete the nonce from cache to prevent replay attacks
          await deleteNonce(proofPayload.nonce);

          // Optional: Log iss for tracking
          console.log(
            `Proof JWT validated. Issuer (Wallet): ${proofPayload.iss}, Nonce verified.`
          );

          // --- End Full Signature and Claim Verification ---
        } else {
          console.log(
            `No proof signing algorithms defined for ${effectiveConfigurationId}, skipping algorithm validation.`
          );
        }
      } else {
        console.log(
          `No JWT proof type configuration found for ${effectiveConfigurationId}, skipping algorithm validation.`
        );
        // Depending on policy, you might require proof_types_supported to be defined.
      }
    } catch (err) {
      console.error("Error during proof validation:", err);
      return res.status(500).json({
        error: "server_error",
        error_description: "An error occurred during proof validation.",
      });
    }
  }
  // End of New Proof Validation Logic

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



  // It is important that the `sessionObject` used from here on is the same one whose c_nonce was validated.
  // The nonce check block now fetches `sessionForNonceCheck`. We should ensure `sessionObject` here is consistent.
  // If the lookups are identical, `sessionForNonceCheck` is `sessionObject`.
  // Add a check or ensure consistency.
  if (!sessionObject) {
    console.error(
      "Session object could not be retrieved after proof validation for credential issuance."
    );
    return res.status(500).json({
      error: "server_error",
      error_description: "Session lost after proof validation.",
    });
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

    requestBody.vct = requestedCredentialType[0];

    const issuerConfig = loadIssuerConfig();
    const credConfig =
      issuerConfig.credential_configurations_supported[
        effectiveConfigurationId
      ];

    if (!credConfig) {
      return res.status(400).json({
        error: "invalid_credential_request",
        error_description: `Credential configuration ID '${effectiveConfigurationId}' not found.`,
      });
    }
    
    let format = credConfig.format;
    if (format === "mso_mdoc") {
      format = "mdl";
    }

    try {
      const credential = await handleVcSdJwtFormat(
        requestBody,
        sessionObject,
        serverURL,
        format
      );

      // Handle different response formats based on credential type
      let response;

      response = {
        credentials: [
          {
            credential,
          },
        ],
      };

      res.json(response);
    } catch (err) {
      console.log(err);
      return res.status(400).json({
        error: "credential_request_denied",
        error_description: err.message,
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
  const sessionObject = await getCodeFlowSession(sessionId);
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

sharedRouter.post("/nonce", async (req, res) => {
  const newCNonce = generateNonce();
  const nonceExpiresIn = 86400; // Standard expiry, can be configured

  // Store the nonce in Redis cache
  await storeNonce(newCNonce, nonceExpiresIn);

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

async function validatePKCE(session, code_verifier, stored_code_challenge) {
  // The 'code' (authorization code) parameter is not needed here.
  // 'issuanceResults' parameter was also not used and can be removed.

  if (!stored_code_challenge) {
    console.log("PKCE challenge not found in session.");
    return false;
  }
  if (!code_verifier) {
    console.log("Code verifier not provided in token request.");
    return false;
  }

  let tester = await base64UrlEncodeSha256(code_verifier);
  if (tester === stored_code_challenge) {
    // Optionally, update the session status here if desired, e.g.,
    // session.pkceVerified = true;
    // Or rely on the calling function to update overall session status.
    console.log("PKCE verification success");
    return true;
  }

  console.log("PKCE verification FAILED!!!");
  console.log(`Expected challenge: ${stored_code_challenge}`);
  console.log(`Derived from verifier: ${tester}`);
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

export const publicKeyToPem = async (jwk) => {
  if (!jwk) {
    throw new Error("JWK is undefined or null.");
  }
  try {
    const publicKey = await jose.importJWK(jwk);
    const pem = await jose.exportSPKI(publicKey);
    return pem;
  } catch (err) {
    console.error("Error converting JWK to PEM:", err);
    console.error("Problematic JWK:", JSON.stringify(jwk));
    throw new Error(`Failed to convert JWK to PEM: ${err.message}`);
  }
};

export default sharedRouter;
