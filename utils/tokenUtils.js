import fs from "fs";
import jwt from "jsonwebtoken";
import crypto from "crypto";

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
    aud: "yourClientId", // The client ID of the application making the authentication request
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
