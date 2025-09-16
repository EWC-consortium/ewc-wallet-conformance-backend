import jp from "jsonpath";
import jwt from "jsonwebtoken";
import { decodeSdJwt, getClaims } from "@sd-jwt/decode";
import { digest } from "@sd-jwt/crypto-nodejs";
import { getVPSession } from "../services/cacheServiceRedis.js";
import zlib from 'zlib';
import base64url from 'base64url';

/**
 * Placeholder decoding/parsing functions.
 * Implement these according to the specific standards and libraries you use.
 */
async function decodeJwtVC(jwtString) {
  return jwt.decode(jwtString, { complete: true });
}

/**
 * Extracts the compact token from a data: URL used by Enveloped VC/VP objects.
 * Accepts forms like:
 *  - data:application/vc+sd-jwt,<token>
 *  - data:application/vp+sd-jwt,<token>
 *  - data:application/vc+jwt,<token>
 * Returns null if not a supported data URL.
 */
function extractTokenFromDataUrl(dataUrl) {
  if (typeof dataUrl !== 'string') return null;
  if (!dataUrl.startsWith('data:')) return null;
  const commaIdx = dataUrl.indexOf(',');
  if (commaIdx < 0) return null;
  const mediatype = dataUrl.substring(5, commaIdx); // between 'data:' and ','
  const payload = dataUrl.substring(commaIdx + 1);
  // Accept known media types; allow both vc/vp and sd-jwt/jwt variants
  const allowed = [
    'application/vc+sd-jwt',
    'application/vp+sd-jwt',
    'application/vc+jwt',
    'application/vp+jwt',
    'application/dc+sd-jwt'  // Digital Credentials SD-JWT format
  ];
  if (!allowed.some((mt) => mediatype.startsWith(mt))) return null;
  try {
    // data URL payload may be percent-encoded; decode safely
    return decodeURIComponent(payload);
  } catch {
    return payload;
  }
}

/**
 * Extracts claims from the request body.
 *
 * @param {Object} req - The Express request object.
 * @param {string} digest - The digest used for decoding SDJWT.
 * @returns {Promise<Array>} - An array of extracted claims.
 * @throws {Error} - Throws error if validation fails or processing encounters issues.
 */
export async function extractClaimsFromRequest(req, digest, isPaymentVP) {
  const sessionId = req.params.id;
  let extractedClaims = [];
  let keybindJwt; // This might need to be an array if multiple SD-JWTs with different kbJwts are possible

  const vpToken = req.body["vp_token"];
  if (!vpToken) {
    throw new Error("No vp_token found in the request body.");
  }

  const presentationSubmission = req.body["presentation_submission"];

  if (presentationSubmission) {
    // PEX flow
    console.log("Processing with PEX flow (presentation_submission found).");
    const sessionData = await getVPSession(sessionId);
    const requestedInputDescriptors =
      sessionData.presentation_definition.input_descriptors;

    const state = req.body["state"];

    let descriptorMap;
    try {
      descriptorMap = JSON.parse(presentationSubmission).descriptor_map;
    } catch (err) {
      throw new Error("Invalid JSON format for presentation_submission.");
    }

    if (!Array.isArray(descriptorMap)) {
      throw new Error("descriptor_map is not an array.");
    }

    for (const descriptor of descriptorMap) {
      const vpResult = await processDescriptorEntry(
        vpToken, // This is the outer JWT (VP) when path_nested is used
        descriptor,
        requestedInputDescriptors
      );

      if (vpResult === null) {
        console.warn(
          `Skipping descriptor with id '${descriptor.id}' due to null vpResult.`
        );
        continue;
      }

      // vpResult could be a single credential string or an array of them (from jp.query in nested).
      // It could also be the original vpToken if it's a root jwt_vc_json or sd-jwt.
      // Normalize to an array of credential strings to process.
      let credentialStringsToProcess = [];
      let credentialObjectsToProcess = [];
      if (typeof vpResult === "string") {
        // If it's a root JWT (either sd-jwt or plain jwt_vc_json) or a single nested result
        credentialStringsToProcess.push(vpResult);
      } else if (Array.isArray(vpResult)) {
        // If jp.query returned an array of JWT strings (nested case)
        for (const item of vpResult) {
          if (typeof item === 'string') {
            credentialStringsToProcess.push(item);
          } else if (item && typeof item === 'object') {
            credentialObjectsToProcess.push(item);
          }
        }
      } else {
        console.warn(
          `vpResult for descriptor id '${descriptor.id}' is neither a string nor an array of strings. Skipping.`,
          vpResult
        );
        continue;
      }

      // Prefer EnvelopedVerifiableCredential objects when present by extracting their data: URLs
      for (const obj of credentialObjectsToProcess) {
        try {
          const objType = Array.isArray(obj.type) ? obj.type : [obj.type];
          const isEnvelopedVC = objType && objType.includes('EnvelopedVerifiableCredential') && typeof obj.id === 'string';
          if (isEnvelopedVC) {
            const tokenFromData = extractTokenFromDataUrl(obj.id);
            if (tokenFromData) {
              credentialStringsToProcess.push(tokenFromData);
            }
          }
        } catch (e) {
          // ignore malformed objects and continue
        }
      }

      if (
        credentialStringsToProcess.length === 0 &&
        (descriptor.format === "vc+sd-jwt" ||
          descriptor.format === "dc+sd-jwt" ||
          descriptor.format === "jwt_vc_json" ||
          descriptor.format === "jwt_vp")
      ) {
        // If vpResult was the vpToken itself (e.g. root and format matches sd-jwt or jwt_vc_json)
        // and it wasn't caught by the string check (e.g. if vpToken itself was complex and processDescriptorEntry returned it directly),
        // this is a fallback, though processDescriptorEntry should ideally return a string here.
        // This might indicate an issue in processDescriptorEntry if vpResult is not a string for root jwt_vc_json/sd-jwt.
        // For now, let's assume processDescriptorEntry returns the string for root cases.
        // If vpResult IS the vpToken (outer JWT) and format is jwt_vc_json, it implies vpToken *is* the credential.
        // If format is sd-jwt, vpToken *is* the sd-jwt.
        console.log(
          `Processing vpResult for descriptor id '${descriptor.id}' which is likely the root vpToken.`
        );
      }

      for (const credString of credentialStringsToProcess) {
        try {
          if (
            descriptor.format === "vc+sd-jwt" ||
            descriptor.format === "dc+sd-jwt" ||
            descriptor.format === "jwt_vp"
          ) {
            const decodedSdJwt = await decodeSdJwt(credString, digest);
            if (decodedSdJwt.kbJwt) {
              // Check if kbJwt exists
              keybindJwt = decodedSdJwt.kbJwt; // Assign if present. Note: overwrites if multiple SD-JWTs have kbJwt.
            }
            const claims = await getClaims(
              decodedSdJwt.jwt.payload,
              decodedSdJwt.disclosures,
              digest
            );
            // If this SD-JWT is a VP (typ=vp+sd-jwt and cty=vp), prefer enveloped structures
            const hdr = decodedSdJwt.jwt.header || {};
            const isVpSdJwt = hdr.typ === 'vp+sd-jwt' && hdr.cty === 'vp';
            if (isVpSdJwt) {
              // Handle EnvelopedVerifiablePresentation wrapping another VP token
              const claimsType = Array.isArray(claims.type) ? claims.type : [claims.type];
              if (claimsType && claimsType.includes('EnvelopedVerifiablePresentation') && typeof claims.id === 'string') {
                const innerVpToken = extractTokenFromDataUrl(claims.id);
                if (innerVpToken) {
                  try {
                    const innerDecoded = await decodeSdJwt(innerVpToken, digest);
                    const innerClaims = await getClaims(innerDecoded.jwt.payload, innerDecoded.disclosures, digest);
                    // Process inner VP's verifiableCredential array (which may include EnvelopedVerifiableCredential)
                    if (innerClaims.vp && Array.isArray(innerClaims.vp.verifiableCredential)) {
                      for (const vcEntry of innerClaims.vp.verifiableCredential) {
                        if (typeof vcEntry === 'string') {
                          // sd-jwt or jwt string
                          if (vcEntry.includes('~')) {
                            const decVc = await decodeSdJwt(vcEntry, digest);
                            const vcClaims = await getClaims(decVc.jwt.payload, decVc.disclosures, digest);
                            extractedClaims.push(vcClaims);
                          } else {
                            const decVc = await decodeJwtVC(vcEntry);
                            if (decVc && decVc.payload) extractedClaims.push(decVc.payload);
                          }
                        } else if (vcEntry && typeof vcEntry === 'object') {
                          const tokenFromData = extractTokenFromDataUrl(vcEntry.id);
                          if (tokenFromData) {
                            if (tokenFromData.includes('~')) {
                              const decVc = await decodeSdJwt(tokenFromData, digest);
                              const vcClaims = await getClaims(decVc.jwt.payload, decVc.disclosures, digest);
                              extractedClaims.push(vcClaims);
                            } else {
                              const decVc = await decodeJwtVC(tokenFromData);
                              if (decVc && decVc.payload) extractedClaims.push(decVc.payload);
                            }
                          }
                        }
                      }
                      continue; // handled
                    }
                  } catch (e) {
                    // fall through to handle claims below
                  }
                }
              }

              // If no EnvelopedVerifiablePresentation, prefer EnvelopedVerifiableCredential entries if present
              if (claims.vp && Array.isArray(claims.vp.verifiableCredential)) {
                let handledAny = false;
                for (const vcEntry of claims.vp.verifiableCredential) {
                  if (vcEntry && typeof vcEntry === 'object') {
                    const objType = Array.isArray(vcEntry.type) ? vcEntry.type : [vcEntry.type];
                    const isEnvelopedVC = objType && objType.includes('EnvelopedVerifiableCredential') && typeof vcEntry.id === 'string';
                    if (isEnvelopedVC) {
                      const tokenFromData = extractTokenFromDataUrl(vcEntry.id);
                      if (tokenFromData) {
                        handledAny = true;
                        if (tokenFromData.includes('~')) {
                          const decVc = await decodeSdJwt(tokenFromData, digest);
                          const vcClaims = await getClaims(decVc.jwt.payload, decVc.disclosures, digest);
                          extractedClaims.push(vcClaims);
                        } else {
                          const decVc = await decodeJwtVC(tokenFromData);
                          if (decVc && decVc.payload) extractedClaims.push(decVc.payload);
                        }
                      }
                    }
                  }
                }
                if (handledAny) continue; // prefer enveloped; already pushed claims
              }
            }
            extractedClaims.push(claims);
          } else if (descriptor.format === "jwt_vc_json") {
            const decodedJwt = await decodeJwtVC(credString); // Using your existing decodeJwtVC
            if (decodedJwt && decodedJwt.payload) {
              extractedClaims.push(decodedJwt.payload);
              // keybindJwt is typically not part of a plain jwt_vc_json unless a custom mechanism is used.
              // If there's a cnf claim with jwk, it could be related but not directly a kbJwt.
            } else {
              console.error(
                "Failed to decode jwt_vc_json or payload missing:",
                credString
              );
              throw new Error("Failed to decode jwt_vc_json.");
            }
          } else {
            console.warn(
              `Unsupported format '${descriptor.format}' for descriptor id '${descriptor.id}'. Skipping credential.`
            );
          }
        } catch (e) {
          console.error(
            `Error processing credential for descriptor id '${descriptor.id}', format '${descriptor.format}':`,
            credString,
            e
          );
          // Decide if one error should stop all processing or just skip this credential
          // For now, let's throw to indicate a problem with a specific submission component.
          throw new Error(
            `Failed to process submitted credential for descriptor ${descriptor.id}.`
          );
        }
      }
    }
  } else {
    // Non-PEX flow (e.g., for DCQL) where presentation_submission is not provided.
    console.log("Processing with non-PEX flow (no presentation_submission).");
    try {
      const tokensToProcess = [];
      if (typeof vpToken === 'object' && vpToken !== null && !Array.isArray(vpToken)) {
        // This is the expected DCQL case. vpToken is an object like { pid_credential: [ "..." ] }
        for (const value of Object.values(vpToken)) {
          if (typeof value === 'string') {
            tokensToProcess.push(value);
          } else if (Array.isArray(value)) {
            for (const inner of value) {
              if (typeof inner === 'string') tokensToProcess.push(inner);
            }
          }
        }
      } else if (typeof vpToken === 'string') {
        // Fallback for single token or stringified JSON
        try {
          const parsed = JSON.parse(vpToken);
          if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
            for (const value of Object.values(parsed)) {
              if (typeof value === 'string') {
                tokensToProcess.push(value);
              } else if (Array.isArray(value)) {
                for (const inner of value) {
                  if (typeof inner === 'string') tokensToProcess.push(inner);
                }
              }
            }
          } else {
            tokensToProcess.push(vpToken);
          }
        } catch (e) {
          tokensToProcess.push(vpToken); // Not JSON, treat as raw token.
        }
      } else {
        throw new Error("Unsupported vp_token format for non-PEX flow.");
      }

      for (const token of tokensToProcess) {
        if (typeof token !== 'string') continue;

        try {
          if (token.includes("~")) { // Heuristic for SD-JWT
            const decodedSdJwt = await decodeSdJwt(token, digest);
            if (decodedSdJwt.kbJwt) {
              keybindJwt = decodedSdJwt.kbJwt;
            }
            const claims = await getClaims(decodedSdJwt.jwt.payload, decodedSdJwt.disclosures, digest);

            // Check header to prefer enveloped structures for VP SD-JWT
            const hdr = decodedSdJwt.jwt.header || {};
            const isVpSdJwt = hdr.typ === 'vp+sd-jwt' && hdr.cty === 'vp';
            if (isVpSdJwt) {
              const claimsType = Array.isArray(claims.type) ? claims.type : [claims.type];
              // Handle EnvelopedVerifiablePresentation
              if (claimsType && claimsType.includes('EnvelopedVerifiablePresentation') && typeof claims.id === 'string') {
                const innerVpToken = extractTokenFromDataUrl(claims.id);
                if (innerVpToken) {
                  try {
                    const innerDecoded = await decodeSdJwt(innerVpToken, digest);
                    const innerClaims = await getClaims(innerDecoded.jwt.payload, innerDecoded.disclosures, digest);
                    if (innerClaims.vp && Array.isArray(innerClaims.vp.verifiableCredential)) {
                      for (const vcEntry of innerClaims.vp.verifiableCredential) {
                        if (typeof vcEntry === 'string') {
                          if (vcEntry.includes('~')) {
                            const decVc = await decodeSdJwt(vcEntry, digest);
                            const vcClaims = await getClaims(decVc.jwt.payload, decVc.disclosures, digest);
                            extractedClaims.push(vcClaims);
                          } else {
                            const decVc = await decodeJwtVC(vcEntry);
                            if (decVc && decVc.payload) extractedClaims.push(decVc.payload);
                          }
                        } else if (vcEntry && typeof vcEntry === 'object') {
                          const tokenFromData = extractTokenFromDataUrl(vcEntry.id);
                          if (tokenFromData) {
                            if (tokenFromData.includes('~')) {
                              const decVc = await decodeSdJwt(tokenFromData, digest);
                              const vcClaims = await getClaims(decVc.jwt.payload, decVc.disclosures, digest);
                              extractedClaims.push(vcClaims);
                            } else {
                              const decVc = await decodeJwtVC(tokenFromData);
                              if (decVc && decVc.payload) extractedClaims.push(decVc.payload);
                            }
                          }
                        }
                      }
                      continue; // handled enveloped VP
                    }
                  } catch (e) {
                    // fall through
                  }
                }
              }

              // Prefer EnvelopedVerifiableCredential entries when present
              if (claims.vp && Array.isArray(claims.vp.verifiableCredential)) {
                let handledAny = false;
                for (const vcEntry of claims.vp.verifiableCredential) {
                  if (vcEntry && typeof vcEntry === 'object') {
                    const objType = Array.isArray(vcEntry.type) ? vcEntry.type : [vcEntry.type];
                    const isEnvelopedVC = objType && objType.includes('EnvelopedVerifiableCredential') && typeof vcEntry.id === 'string';
                    if (isEnvelopedVC) {
                      const tokenFromData = extractTokenFromDataUrl(vcEntry.id);
                      if (tokenFromData) {
                        handledAny = true;
                        if (tokenFromData.includes('~')) {
                          const decVc = await decodeSdJwt(tokenFromData, digest);
                          const vcClaims = await getClaims(decVc.jwt.payload, decVc.disclosures, digest);
                          extractedClaims.push(vcClaims);
                        } else {
                          const decVc = await decodeJwtVC(tokenFromData);
                          if (decVc && decVc.payload) extractedClaims.push(decVc.payload);
                        }
                      }
                    }
                  }
                }
                if (handledAny) continue; // prefer enveloped
              }
            }

            // Fallbacks: original behavior (strings or single VC claims)
            if (claims.vp && Array.isArray(claims.vp.verifiableCredential)) {
              for (const vcJwt of claims.vp.verifiableCredential) {
                if (typeof vcJwt !== 'string') continue;
                if (vcJwt.includes("~")) {
                  const decodedVc = await decodeSdJwt(vcJwt, digest);
                  const vcClaims = await getClaims(decodedVc.jwt.payload, decodedVc.disclosures, digest);
                  extractedClaims.push(vcClaims);
                } else {
                  const decodedVc = await decodeJwtVC(vcJwt);
                  if (decodedVc && decodedVc.payload) {
                    extractedClaims.push(decodedVc.payload);
                  }
                }
              }
            } else {
              extractedClaims.push(claims); // single VC
            }
          } else { // Handle standard JWT
            const decodedJwt = await decodeJwtVC(token);
            const payload = decodedJwt ? decodedJwt.payload : null;
            const header = decodedJwt ? decodedJwt.header : null;
            
            if (payload) {
              // Check if this is a VP+JWT (W3C Verifiable Presentation as JWT)
              if (header && header.typ === 'vp+jwt' && payload.type && Array.isArray(payload.type) && payload.type.includes('VerifiablePresentation')) {
                console.log("Processing VP+JWT token with verifiableCredential array");
                
                // Handle VP+JWT with verifiableCredential array containing EnvelopedVerifiableCredential
                if (payload.verifiableCredential && Array.isArray(payload.verifiableCredential)) {
                  let handledAny = false;
                  
                  for (const vcEntry of payload.verifiableCredential) {
                    if (vcEntry && typeof vcEntry === 'object') {
                      const objType = Array.isArray(vcEntry.type) ? vcEntry.type : [vcEntry.type];
                      const isEnvelopedVC = objType && objType.includes('EnvelopedVerifiableCredential') && typeof vcEntry.id === 'string';
                      
                      if (isEnvelopedVC) {
                        console.log("Found EnvelopedVerifiableCredential in VP+JWT, extracting from data URL");
                        const tokenFromData = extractTokenFromDataUrl(vcEntry.id);
                        if (tokenFromData) {
                          handledAny = true;
                          if (tokenFromData.includes('~')) {
                            // SD-JWT credential
                            const decVc = await decodeSdJwt(tokenFromData, digest);
                            const vcClaims = await getClaims(decVc.jwt.payload, decVc.disclosures, digest);
                            extractedClaims.push(vcClaims);
                          } else {
                            // Regular JWT credential
                            const decVc = await decodeJwtVC(tokenFromData);
                            if (decVc && decVc.payload) extractedClaims.push(decVc.payload);
                          }
                        }
                      }
                    } else if (typeof vcEntry === 'string') {
                      // Direct credential string (fallback)
                      handledAny = true;
                      if (vcEntry.includes('~')) {
                        const decVc = await decodeSdJwt(vcEntry, digest);
                        const vcClaims = await getClaims(decVc.jwt.payload, decVc.disclosures, digest);
                        extractedClaims.push(vcClaims);
                      } else {
                        const decodedVc = await decodeJwtVC(vcEntry);
                        if (decodedVc && decodedVc.payload) {
                          extractedClaims.push(decodedVc.payload);
                        }
                      }
                    }
                  }
                  
                  if (handledAny) {
                    continue; // Successfully processed VP+JWT, move to next token
                  }
                }
              }
              // Legacy VP handling (payload.vp.verifiableCredential)
              else if (payload.vp && Array.isArray(payload.vp.verifiableCredential)) {
                for (const vcJwt of payload.vp.verifiableCredential) {
                  const decodedVc = await decodeJwtVC(vcJwt);
                  if (decodedVc && decodedVc.payload) {
                    extractedClaims.push(decodedVc.payload);
                  }
                }
              } else {
                extractedClaims.push(payload); // single VC
              }
            } else {
               console.warn("Could not decode non-SD-JWT, skipping:", token);
            }
          }
        } catch (e) {
          console.error("Error processing token inside non-PEX response, skipping.", e);
        }
      }
    } catch (e) {
      console.error("Error processing non-PEX VP token:", e);
      throw new Error("Failed to process VP token.");
    }
  }

  // console.log("Final keybindJwt (could be from the last processed SD-JWT with one):");
  // console.log(keybindJwt);
  return { sessionId, extractedClaims, keybindJwt };
}

export async function validatePoP(
  oauthClientAttestation,
  oauthClientAttestationPoP,
  clientId = "dss.aegean.gr"
) {
  const decodedWUA = await await decodeSdJwt(oauthClientAttestation, digest);
  const decodedPoP = await jwt.decode(oauthClientAttestationPoP, {
    complete: true,
  });

  const wuaSub = decodedWUA.jwt.payload.sub;
  const popIss = decodedPoP.payload.iss;

  //The value of iss must exactly match the sub claim of the the WUA JWT from section 3.1
  // The value of aud must be the identifier of the relying party
  if (wuaSub !== popIss || decodedPoP.payload.aud !== clientId) return false;
  //The value of exp must be set so that the WUA PoP JWT's maximum lifetime is no longer than 24 hours
  const nowInSeconds = Math.floor(Date.now() / 1000);
  const lifetimeInSeconds = decodedPoP.payload.exp - nowInSeconds;
  // Check if lifetime exceeds 24 hours (86400 seconds)
  if (lifetimeInSeconds > 86400) {
    return false;
  }
  return true;
}

export async function validateWUA(
  oauthClientAttestation,
  clientId = "dss.aegean.gr"
) {
  const decodedWUA = await await decodeSdJwt(oauthClientAttestation, digest);
  // The alg used to sign the attestation must be ES256
  if (!decodedWUA.jwt.header.alg === "ES256") return false;

  //attested_security_context
  const securityContext = decodedWUA.jwt.payload.attested_security_context;
  if (securityContext !== "https://eudiwalletconsortium.org/") {
    console.log(
      "attested security context was not https://eudiwalletconsortium.org/"
    );
    return false;
  }

  // The kid must identify a JWK which must be resolvable as a JWK Set [5] by appending ./well-known/jwt-issuer to the value of the iss claim
  const kid = decodedWUA.jwt.header.kid;
  const iss = decodedWUA.jwt.payload.iss;
  const parsed = new URL(iss);
  const issuerURL = `${parsed.origin}/.well-known/jwt-vc-issuer${parsed.pathname}`;
  const response = await fetch(issuerURL);
  if (!response.ok) {
    console.log("could not fetch " + issuerURL);
    return false;
  }

  let jwksUriJson;

  const data = await response.json();
  if (data.jwks_uri) {
    const responseJwks = await fetch(data.jwks_uri);
    if (!responseJwks.ok) {
      console.log("could not fetch " + data.jwks_uri);
      return false;
    }
    const dataJwks = await responseJwks.json();
    jwksUriJson = dataJwks;
  } else {
    jwksUriJson = data;
  }

  const matchingKey = jwksUriJson.keys.find((value) => value.kid === kid);
  if (!matchingKey) {
    return false;
  }

  //TODO
  //The attestation should include a status claim which contains a reference to a status list as defined in [4]
  // and which allows the attestation provider to check the state of revocation of the wallet instance

  /*
    The JWT must include a status_list claim that is a JSON object containing:
    bits: an integer that must be one of the allowed values (1, 2, 4, or 8).
    lst: a base64url‑encoded string representing the compressed (using DEFLATE with the ZLIB format) bit array for the status list.
     You then decode the lst value and decompress it to obtain the raw bit array. (At this point you can, if needed, check that the number of bits matches your expected number of referenced tokens.)
  */
  const statusListURI = decodedWUA.jwt.payload.status.status_list.uri;
  let options = {
    method: "GET",
    headers: { Accept: "application/statuslist+jwt" },
  };
  const statusJwtResponse = await fetch(statusListURI, options);
  if (!statusJwtResponse.ok) {
    console.log("could not fetch " + statusListURI);
    return false;
  }
  const statusJwt = await statusJwtResponse.text();
  const decodedStatus = jwt.decode(statusJwt, {
    complete: true,
  });
  const statusListClaim = decodedStatus.payload.status_list;
  if (
    !statusListClaim ||
    typeof statusListClaim.bits !== "number" ||
    !statusListClaim.lst
  ) {
    console.log("Missing or invalid status_list claim");
    return false;
  }
  // Check that the "bits" value is one of the allowed sizes (1,2,4,8)
  if (![1, 2, 4, 8].includes(statusListClaim.bits)) {
    console.log("Invalid bits value in status_list");
    return false;
  }

  const compressed = base64url.toBuffer(statusListClaim.lst);
  let decompressed;
  try {
    decompressed = zlib.inflateSync(compressed);
  } catch (err) {
    console.log('Failed to decompress status list: ' + err.message);
    return false;
  }
  // now that we have the actuall byte array (the decompressed buffer) 
  // we can check the status of the specific wallet (the index contained in the WUA)
  const tokenIndex = decodedWUA.jwt.payload.status.status_list.idx
  return checkTokenStatus(decompressed, tokenIndex)
}

/**
 * Process a single descriptor map entry, recursively handling path_nested.
 * @param {Object} vpToken - The current "traversal" object (initially the top-level VP token payload).
 * @param {Object} descriptor - A single entry from `descriptor_map`.
 * @param {Object} requestedDescriptor - the request made by the verifier that the submission should match
 * @returns The fully decoded Claim object or null if decoding fails.
 */
/*
 vpToken,
      descriptor,
      extractedClaims,
      requestedInputDescriptors
*/
export async function processDescriptorEntry(
  vpToken,
  descriptor,
  requestedDescriptor
) {
  const { id, format, path, path_nested } = descriptor;

  const isValidDescriptorEntry = compareSubmissionToDefinition(
    descriptor,
    requestedDescriptor
  );

  if (!path_nested) {
    // the vp is in the root
    if (format === "dc+sd-jwt" || format === "vc+sd-jwt" || format === "jwt_vc_json" || format === "jwt_vp") {
      //return the root document that is the presented sd-jwt, jwt_vc_json, or jwt_vp
      return vpToken;
    } else {
      console.log(
        "presentation_submission format (root) " + format + " not supported"
      );
      return null;
    }
  } else {
    // The VP is nested. vpToken is an outer JWT containing the credential/presentation.
    // `format` is the format of the target credential/presentation.
    // `path_nested.path` is the JSONPath to find it within the decoded `vpToken`.
    const supportedNestedFormats = [
      "dc+sd-jwt", // Current/preferred for SD-JWT
      "vc+sd-jwt", // Older/alternative for SD-JWT
      "jwt_vc_json",
      "jwt_vp"
    ];

    if (supportedNestedFormats.includes(format)) {
      try {
        // decode the vpToken jwt (the outer presentation/container)
        let decodedVpToken = await decodeJwtVC(vpToken);
        if (!decodedVpToken || !decodedVpToken.payload) {
            console.error("Failed to decode vpToken or payload missing for nested VP/VC processing.");
            return null;
        }
        //return an array of matching query elements from the payload (should be the JWT string(s))
        return jp.query(decodedVpToken.payload, path_nested.path);
      } catch (e) {
        console.error("Error decoding or querying nested VP/VC:", e);
        return null;
      }
    } else {
      console.log(
        `presentation_submission format (nested) "${format}" not supported for this extraction method.`
      );
      return null;
    }
  }
}

function compareSubmissionToDefinition(submission, definitionsArray) {
  let matchingSubmissions = definitionsArray.filter((definition) => {
    // 2) Compare definition_id in the submission to definition.id
    if (
      submission.definition_id !== definition.id &&
      submission.id !== definition.id
    ) {
      console.warn(
        "Mismatch: submission.definition_id !== definition.id",
        submission.definition_id,
        definition.id
      );
      return false;
    }

    // 3) Check each descriptor_map item
    if (!Array.isArray(submission.descriptor_map)) {
      console.warn("descriptor_map is missing or not an array");
      return false;
    }

    // Check that the root format (e.g. "vc+sd-jwt") also exists in definition.format
    // For example, if descriptor_map[0].format = "vc+sd-jwt", ensure definition.format has that key
    for (const desc of submission.descriptor_map) {
      const descFormat = desc.format; // e.g. "vc+sd-jwt"
      if (!definition.format || !definition.format[descFormat]) {
        console.warn(
          `Definition does not have a root format for "${descFormat}"`
        );
        return false;
      }

      // 4) Find matching input_descriptor
      const matchingDescriptor = definition.input_descriptors.find(
        (d) => d.id === desc.id
      );
      if (!matchingDescriptor) {
        console.warn(
          "No matching input_descriptor found for descriptor_map id:",
          desc.id
        );
        return false;
      }

      // 5) Compare descriptor_map.format with input_descriptor.format
      //    i.e. check if input_descriptor.format has the same key as descFormat
      if (
        !matchingDescriptor.format ||
        !matchingDescriptor.format[descFormat]
      ) {
        console.warn(
          `descriptor_map.format "${descFormat}" not found in input_descriptors.format`
        );
        return false;
      }

      // 6) Check path_nested.format if applicable
      if (desc.path_nested && desc.path_nested.format) {
        const nestedFormat = desc.path_nested.format;
        // For instance, if you want "jwt_vc" to match "vc+sd-jwt" in some logic:
        // This might be an application-specific check. For example:
        if (nestedFormat !== descFormat) {
          console.warn(
            `Nested format mismatch: path_nested.format="${nestedFormat}" vs descriptor_map.format="${descFormat}"`
          );
          // return false;  // Decide if you want to fail or just warn
        }
      }

      // We could also compare the "alg" arrays, etc., as needed
      // e.g. compare definition.format["vc+sd-jwt"].alg with matchingDescriptor.format["vc+sd-jwt"].alg
      // This is optional and depends on your logic:
      const rootAlgs = definition.format[descFormat]?.alg || [];
      const descAlgs = matchingDescriptor.format[descFormat]?.alg || [];
      const algsMatch =
        rootAlgs.length === descAlgs.length &&
        rootAlgs.every((val) => descAlgs.includes(val));
      if (!algsMatch) {
        console.warn("Root alg array does not match descriptor alg array");
        return false;
      }
    }

    // If we get here, everything passed the checks
    return true;
  });

  return matchingSubmissions.length > 0;
}

/**
 * Checks if a single data object contains only allowed fields,
 * ignoring reserved JWT keys and the "cnf" property.
 *
 * @param {Object} dataObj - The data object to check.
 * @param {string[]} allowedPaths - The list of allowed paths (with "$." prefix).
 * @param {string[]} [ignoredKeys=['iss', 'iat', 'cnf', 'id','exp']] - Keys to ignore.
 * @returns {boolean} - True if only allowed fields (besides ignored ones) are present.
 */
export function hasOnlyAllowedFields(
  dataObj,
  allowedPaths,
  ignoredKeys = [
    "iss",
    "iat",
    "cnf",
    "id",
    "exp",
    "aud",
    "sub",
    "nonce",
    "nbf",
    "jti",
  ]
) {
  // Convert allowedPaths to a set of property names by stripping "$.".
  const allowedFields = new Set(
    allowedPaths.map((path) => path.replace(/^\$\./, ""))
  );

  // Collect all flattened key paths from dataObj, respecting ignoredKeys.
  // The flattenKeys function itself ensures that paths starting with an ignoredKey are not included.
  let allFlattenedDataPaths = [];
  if (Array.isArray(dataObj)) {
    for (const obj of dataObj) {
      allFlattenedDataPaths.push(...flattenKeys(obj, "", ignoredKeys));
    }
  } else {
    allFlattenedDataPaths.push(...flattenKeys(dataObj, "", ignoredKeys));
  }
  const dataKeySet = new Set(allFlattenedDataPaths);

  // Check that every discovered key path in dataObj is present in the allowedFields.
  // This ensures that dataObj does not contain any fields/paths not specified in allowedPaths.
  for (let key of dataKeySet) {
    if (!allowedFields.has(key)) {
      // Found a key path in dataObj that is not in the allowed list.
      return false;
    }
  }

  // If all key paths from dataKeySet were found in allowedFields,
  // it means dataObj only contains fields permitted by allowedPaths.
  return true;
}

/**
 * Recursively flattens the keys of an object using dot notation.
 * For example, { a: { b: 1 } } becomes ["a.b"].
 *
 * @param {Object} obj - The object to flatten.
 * @param {string} [prefix=""] - The prefix used for recursion.
 * @param {string[]} ignoredKeys - Keys to ignore (not flatten).
 * @returns {string[]} - An array of flattened key paths.
 */
function flattenKeys(obj, prefix = "", ignoredKeys = []) {
  let keys = [];

  for (const [key, value] of Object.entries(obj)) {
    if (ignoredKeys.includes(key)) continue;

    const fullKey = prefix ? `${prefix}.${key}` : key;
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      // Recursively flatten nested objects.
      keys.push(...flattenKeys(value, fullKey, ignoredKeys));
    } else {
      keys.push(fullKey);
    }
  }
  return keys;
}

/*
  fetch the requested disclosures from a presentationDefinintion
*/
export function getSDsFromPresentationDef(presentation_definition) {
  return presentation_definition.input_descriptors.reduce((acc, descriptor) => {
    if (
      descriptor.constraints &&
      Array.isArray(descriptor.constraints.fields)
    ) {
      descriptor.constraints.fields.forEach((field) => {
        if (field.path) {
          acc.push(...field.path);
        }
      });
    }
    return acc;
  }, []);
}


/*
 bufferToBits function loops over each byte in the Buffer and extracts the bits
 using a bitwise right-shift and bitwise AND. Since the spec says bits are counted
  from the least significant bit (LSB) to the most significant bit
*/
function bufferToBits(buffer) {
  const bits = [];
  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i];
    for (let bit = 0; bit < 8; bit++) {
      bits.push((byte >> bit) & 1);
    }
  }
  return bits;
}

export function checkTokenStatus(decompressedBuffer, tokenIndex) {
  const bits = bufferToBits(decompressedBuffer);
  if (tokenIndex < 0 || tokenIndex >= bits.length) {
    throw new Error('Token index out of range');
  }
  // In this example, 0 = valid, 1 = revoked.
  return bits[tokenIndex] === 0 //? "valid" : "revoked";
}