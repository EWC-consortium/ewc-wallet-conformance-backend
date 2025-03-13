import jp from "jsonpath";
import jwt from "jsonwebtoken";
import { decodeSdJwt, getClaims } from "@sd-jwt/decode";
import { digest } from "@sd-jwt/crypto-nodejs";
import { getVPSession } from "../services/cacheServiceRedis.js";

/**
 * Placeholder decoding/parsing functions.
 * Implement these according to the specific standards and libraries you use.
 */
async function decodeJwtVC(jwtString) {
  return jwt.decode(jwtString, { complete: true });
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

  const sessionData = await getVPSession(sessionId);
  const requestedInputDescriptors =
    sessionData.presentation_definition.input_descriptors;

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
  let keybindJwt;

  for (const descriptor of descriptorMap) {
    const vpResult = await processDescriptorEntry(
      vpToken,
      descriptor,
      requestedInputDescriptors
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
          // if (isPaymentVP) {
          //

          keybindJwt = decodedSdJwt.kbJwt;
          // console.log("keybindJwt -1");
          // console.log(keybindJwt);
          // }

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
        keybindJwt = decodedSdJwt.kbJwt;
        // console.log("keybindJwt -2");
        // console.log(keybindJwt);

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

  console.log("keybindJwt -3");
  console.log(keybindJwt);
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
  const kid = decodedWUA.jwt.header.kid;
  const iss = decodedWUA.jwt.payload.iss;
  // The kid must identify a JWK which must be resolvable as a JWK Set [5] by appending ./well-known/jwt-issuer to the value of the iss claim
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
  if(!matchingKey){
    return false
  }

  return true;
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
  let dataKeys = [];
  if (Array.isArray(dataObj)) {
    dataKeys.push(
      ...dataObj.reduce((acc, obj) => {
        // Accumulate the keys.
        const flattenedKeys = flattenKeys(obj, "", ignoredKeys);
        // Get the keys for this object, filtering out ignored keys.
        const keys = flattenedKeys.filter((key) => !ignoredKeys.includes(key));
        return acc.concat(keys);
      }, [])
    );
    // If you need unique keys, uncomment the next line:
    // dataKeys = Array.from(new Set(dataKeys));
  } else {
    dataKeys.push(
      ...Object.keys(dataObj).filter((key) => !ignoredKeys.includes(key))
    );
  }

  // Convert dataKeys to a set.
  const dataKeySet = new Set(dataKeys);

  // Check if both sets have the same size.
  if (dataKeySet.size !== allowedFields.size) return false;

  // Check that every key in the data is in the allowed fields.
  for (let key of dataKeySet) {
    if (!allowedFields.has(key)) return false;
  }
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
