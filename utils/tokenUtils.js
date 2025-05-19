import fs from "fs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { error } from "console";
import {generateNonce} from "../utils/cryptoUtils.js"

export function buildAccessToken(issuerURL, privateKey) {
  const payload = {
    iss: issuerURL,
    sub: "user123", // This should be the authenticated user's identifier
    aud: issuerURL, // The identifier of your resource server
    exp: Math.floor(Date.now() / 1000) + 60 * 60, // Token expiration time (1 hour from now)
    iat: Math.floor(Date.now() / 1000), // Current time
    scope: "openid",
  };
  // Sign the JWT
  const token = jwt.sign(payload, privateKey, { algorithm: "ES256" });

  //   console.log(token);
  return token;
}

export function generateRefreshToken(length = 64) {
  return crypto.randomBytes(length).toString("hex");
}

export function buildIdToken(issuerURL, privateKey) {
  const payload = {
    iss: issuerURL,
    sub: "user123",
    aud: "https://self-issued.me/v2", // The client ID of the application making the authentication request
    exp: Math.floor(Date.now() / 1000) + 60 * 60, // Token expiration time (1 hour from now)
    iat: Math.floor(Date.now() / 1000), // Token issued at time
    auth_time: Math.floor(Date.now() / 1000) - 60 * 5, // Assume the user authenticated 5 minutes ago
    // Optional claims
    nonce: "nonceValue", // If using implicit flow or authorization code flow with PKCE
    // Add other claims as necessary
  };

  // Sign the token
  const idToken = jwt.sign(payload, privateKey, {
    algorithm: "ES256", // Ensure the algorithm matches the key and your authorization server configuration
    // You can add a "kid" (key ID) here if your private key has one
  });

  //   console.log("Generated ID Token:", idToken);
  return idToken;
}

export function buildVPbyValue(
  client_id,
  presentation_definition_uri,
  client_id_scheme = "redirect_uri",
  client_metadata_uri,
  redirect_uri,
  state = "af0ifjsldkj",
  response_type = "vp_token",
  nonce,
  response_mode = "direct_post",
  dcql_query = null,
  transaction_data = null
) {
  if(!nonce) nonce = generateNonce(16);
  
  if (client_id_scheme == "redirect_uri") {
    redirect_uri = client_id;
  }

  let params = new URLSearchParams();
  params.append("client_id", client_id);
  params.append("response_type", response_type);
  params.append("response_mode", response_mode);
  params.append("response_uri", redirect_uri);
  params.append("client_id_scheme", client_id_scheme);
  params.append("client_metadata_uri", client_metadata_uri);
  params.append("nonce", nonce);
  params.append("state", state);

  // Add presentation_definition_uri if provided and no dcql_query
  if (presentation_definition_uri && !dcql_query) {
    params.append("presentation_definition_uri", presentation_definition_uri);
  }

  // Add dcql_query if provided
  if (dcql_query) {
    params.append("dcql_query", JSON.stringify(dcql_query));
  }

  // Add transaction_data if provided
  if (transaction_data && Array.isArray(transaction_data)) {
    // transaction_data must be an array of base64url-encoded strings
    transaction_data.forEach((data, index) => {
      params.append(`transaction_data[${index}]`, data);
    });
  }

  return `openid4vp://?${params.toString()}`;
}


// export function buildVPbyReference(
//   client_id,
//   presentation_definition_uri,
//   client_id_scheme = "redirect_uri",
//   client_metadata_uri,
//   redirect_uri,
//   state = "af0ifjsldkj",
//   response_type = "vp_token"
// ) {
//   if (client_id_scheme == "redirect_uri") {
//     throw new Error("redirect_uri is not supportted for VP by reference");
//   } else {
//     if (response_type == "id_token") {
//       // state, client_id, redirect_uri, response_type, response_mode, scope, nonce, request_uri

//       let result =
//         "openid4vp://?client_id=" +
//         encodeURIComponent(client_id) +
//         "&response_type=" +
//         response_type;
//       "&response_mode=direct_post" +
//         "&response_uri=" +
//         encodeURIComponent(redirect_uri) +
//         "&client_id_scheme=" +
//         client_id_scheme +
//         "&client_metadata_uri=" +
//         encodeURIComponent(client_metadata_uri) +
//         "&nonce=n0S6_WzA2Mj" +
//         "&state=" +
//         state  
//       return result;
//     } else {
//       let result =
//         "openid4vp://?client_id=" +
//         encodeURIComponent(client_id) +
//         "&response_type=" +
//         response_type;
//       "&response_mode=direct_post" +
//         "&response_uri=" +
//         encodeURIComponent(redirect_uri) +
//         "&presentation_definition_uri=" +
//         encodeURIComponent(presentation_definition_uri) +
//         "&client_id_scheme=" +
//         client_id_scheme +
//         "&client_metadata_uri=" +
//         encodeURIComponent(client_metadata_uri) +
//         "&nonce=n0S6_WzA2Mj" +
//         "&state=" +
//         state;
//       return result;
//     }
//   }
// }
