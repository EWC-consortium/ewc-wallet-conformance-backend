import fs from "fs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { error } from "console";

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
) {
  console.log("response_type:", response_type); // Debug log
  
  if (client_id_scheme == "redirect_uri") {
    redirect_uri = client_id;
  }

  if (response_type == "id_token") {
    let resp =
      "openid4vp://?" +
      "client_id=" +
      encodeURIComponent(client_id) +
      "&response_type=" +
      response_type +
      "&response_mode=direct_post" +
      "&response_uri=" +
      encodeURIComponent(redirect_uri) +
      "&client_id_scheme=" +
      client_id_scheme +
      "&client_metadata_uri=" +
      encodeURIComponent(client_metadata_uri) +
      "&nonce=" + nonce +
      "&state=" +
      state +
      "&scope=openid"+
      "&id_token_type=subject_signed"
      ;
    return resp;
  } else {
    let res =
      "openid4vp://?" +
      "client_id=" +
      encodeURIComponent(client_id) +
      "&response_type=" +
      response_type +
      "&response_mode=direct_post" +
      "&response_uri=" +
      encodeURIComponent(redirect_uri) +
      "&presentation_definition_uri=" +
      encodeURIComponent(presentation_definition_uri) +
      "&client_id_scheme=" +
      client_id_scheme +
      "&client_metadata_uri=" +
      encodeURIComponent(client_metadata_uri) +
      "&nonce=n0S6_WzA2Mj" + //TODO add a random nonce here
      "&state=" +
      state 
      +"&scope=code"
    return res;
  }
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
