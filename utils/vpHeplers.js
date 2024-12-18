import jp from "jsonpath";
import jwt from "jsonwebtoken";
import { decodeSdJwt, getClaims } from "@sd-jwt/decode";
import { digest } from "@sd-jwt/crypto-nodejs";

/**
 * Placeholder decoding/parsing functions.
 * Implement these according to the specific standards and libraries you use.
 */
async function decodeJwtVC(jwtString) {
  return jwt.decode(jwtString, { complete: true });
}

/**
 * Process a single descriptor map entry, recursively handling path_nested.
 * @param {Object} vpToken - The current "traversal" object (initially the top-level VP token payload).
 * @param {Object} descriptor - A single entry from `descriptor_map`.
 * @returns The fully decoded Claim object or null if decoding fails.
 */
export async function processDescriptorEntry(vpToken, descriptor) {
  const { id, format, path, path_nested } = descriptor;

  if (!path_nested) {
    // the vp is in the root
    if (format === "vc+sd-jwt") {
      //return the root document that is the presented sd-jwt
      return vpToken;
    } else {
      console.log(
        "presentation_submission format " + format + " not supported"
      );
      return null;
    }
  } else {
    // the vp is nested
    const acceptableCombinations =
      format === "vc+sd-jwt" ||
      format === "dc+sd-jwt" ||
      (path_nested.format = "vc+sd-jwt");
    if (acceptableCombinations) {
      // decode the vpToken jwt
      let decodedVpToken = await decodeJwtVC(vpToken);
      //   console.log(decodedVpToken);
      //return an array of matching query elements
      return jp.query(decodedVpToken.payload, path_nested.path);
    } else {
      console.log(
        "presentation_submission format " + format + " not supported"
      );
      return null;
    }
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
export async function extractClaimsFromRequest(req, digest) {
  const sessionId = req.params.id;

  const vpToken = req.body["vp_token"];
  if (!vpToken) {
    throw new Error("No vp_token found in the request body.");
  }

  const presentationSubmission = req.body["presentation_submission"];
  if (!presentationSubmission) {
    throw new Error("No presentation_submission found in the request body.");
  }

  // Optionally handle 'state' if needed
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

  let extractedClaims = [];

  for (const descriptor of descriptorMap) {
    const vpResult = await processDescriptorEntry(
      vpToken,
      descriptor,
      extractedClaims
    );
    let submittedSdjwt;
    try {
      submittedSdjwt = JSON.parse(vpResult);
    } catch (e) {
      console.log(e);
      submittedSdjwt = vpResult;
    }

    if (Array.isArray(submittedSdjwt)) {
      for (const element of submittedSdjwt) {
        try {
          const decodedSdJwt = await decodeSdJwt(element, digest);
          const claims = await getClaims(
            decodedSdJwt.jwt.payload,
            decodedSdJwt.disclosures,
            digest
          );
          extractedClaims.push(claims);
        } catch (e) {
          console.error("Error decoding submitted sdjwt:", element, e);
          // Optionally, you can choose to throw the error or continue processing other elements
          throw new Error("Failed to decode submitted sdjwt.");
        }
      }
    } else {
      try {
        const decodedSdJwt = await decodeSdJwt(submittedSdjwt, digest);
        const claims = await getClaims(
          decodedSdJwt.jwt.payload,
          decodedSdJwt.disclosures,
          digest
        );
        extractedClaims.push(claims);
      } catch (e) {
        console.error("Error decoding submitted sdjwt:", submittedSdjwt, e);
        throw new Error("Failed to decode submitted sdjwt.");
      }
    }
  }

  return { sessionId, extractedClaims };
}
