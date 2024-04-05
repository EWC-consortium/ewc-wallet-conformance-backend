import crypto from "crypto";
import jwt from "jsonwebtoken";
import * as jose from "jose";

export function pemToJWK(pem, keyType) {
  let key;
  let jwk;

  if (keyType === "private") {
    key = crypto.createPrivateKey(pem);
    // Export JWK including the private key parameter (`d`)
    jwk = key.export({ format: "jwk" }); // This includes x, y, and d for EC keys
  } else {
    key = crypto.createPublicKey(pem);
    // Export JWK with only public components
    jwk = key.export({ format: "jwk" }); // This includes x and y for EC keys
  }

  // Optionally, set or adjust JWK properties if necessary
  jwk.kty = "EC"; // Key Type
  jwk.crv = "P-256"; //"P-384"; // Curve (adjust as necessary based on your actual curve)

  return jwk;
}

export function generateNonce(length = 12) {
  return crypto.randomBytes(length).toString("hex");
}

export function buildVpRequestJwt(
  state,
  nonce,
  client_id,
  response_uri,
  presentation_definition,
  jwk,
  serverURL,
  privateKey
) {
  /*
      client_id	Verifier identifier for .e.g URI / DID. This value must be present in sub field of the verifiable presentation JWT
      response_type	The value must be vp_token
      scope	Optional value, details are specified in [Section 3.1.1](#3.1.1-scope-parameter-usage)
      response_uri	This should be present when the response_mode is direct_post.
      response_mode	The value must be direct_post
      state	The client uses an opaque value to maintain the state between the request and callback.
      nonce	Securely bin verifiable presentations provided by the wallet to a particular transaction
      presentation_definition	The verifier requires proof. It must conform to the DIF Presentation Exchange specification [4].
*/

  /**
 * response_uri
 * client_id_scheme: "redirect_uri",
 * iss": "https://some.io",
 * presentation_definition: {}
 * "response_type": "vp_token",
  "state": "344306f6-0323-4ef5-9348-70fc328efd85",
  "exp": 1712309984,
  "nonce": "1fRxngVjYq0oETeZxNYfId",
  "iat": 1712306384,
  "client_id": "https://some.io/openid4vp/authorization-response",
  "response_mode": "direct_post"
 * 
 */

  let jwtPayload = {
    client_id_scheme: "redirect_uri",
    response_uri: response_uri, //TODO Note: If the Client Identifier scheme redirect_uri is used in conjunction with the Response Mode direct_post, and the response_uri parameter is present, the client_id value MUST be equal to the response_uri value
    iss: serverURL,
    presentation_definition: presentation_definition,
    response_type: "vp_token",
    state: state,
    exp: Math.floor(Date.now() / 1000) + 60,
    nonce: nonce,
    iat: Math.floor(Date.now() / 1000),
    client_id: client_id,
    response_mode: "direct_post",
    // nbf: Math.floor(Date.now() / 1000),
    // redirect_uri: redirect_uri,
    // scope: "openid",
    
  };

  const header = {
    alg: "ES256",
    kid: `aegean#authentication-key`, //this kid needs to be resolvable from the did.json endpoint
  };

  const token = jwt.sign(jwtPayload, privateKey, {
    algorithm: "ES256",
    noTimestamp: true,
    header,
  });
  return token;
}

export async function decryptJWE(jweToken, privateKeyPEM) {
  try {
    const privateKey = crypto.createPrivateKey(privateKeyPEM);

    // Decrypt the JWE using the private key
    const decryptedPayload = await jose.jwtDecrypt(jweToken, privateKey);
    // console.log(decryptedPayload);
    let presentation_submission =
      decryptedPayload.payload.presentation_submission;
    let disclosures = parseVP(decryptedPayload.payload.vp_token);
    console.log(`diclosures in the VP found`);
    console.log(disclosures);
    return disclosures;
  } catch (error) {
    console.error("Error decrypting JWE:", error.message);
    throw error;
  }
}

function parseVP(vp_token) {
  let vpPartsArray = vp_token.split(".");
  let disclosuresPart = vpPartsArray[2]; //this is the actual sd-jdt from the vpToken

  let disclosuresArray = disclosuresPart.split("~").slice(1, -1); //get all elements apart form the first and last one
  // console.log(disclosuresArray);
  let decodedDisclosuresArray = disclosuresArray.map((element) => {
    return base64urlDecode(element);
  });
  return decodedDisclosuresArray;
}

const base64urlDecode = (input) => {
  // Convert base64url to base64 by adding padding characters
  const base64 = input
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(input.length + ((4 - (input.length % 4)) % 4), "=");
  // Decode base64
  const utf8String = atob(base64);
  // Convert UTF-8 string to byte array
  const bytes = new Uint8Array(utf8String.length);
  for (let i = 0; i < utf8String.length; i++) {
    bytes[i] = utf8String.charCodeAt(i);
  }
  let decodedString = new TextDecoder().decode(bytes);
  return JSON.parse(decodedString);
};
