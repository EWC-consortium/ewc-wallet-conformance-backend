import fs from "fs";
import { importJWK, exportJWK, SignJWT, generateKeyPair } from "jose";
import crypto from "node:crypto";

export async function ensureOrCreateEcKeyPair(optionalPath, alg = "ES256") {
  if (optionalPath && fs.existsSync(optionalPath)) {
    const raw = JSON.parse(fs.readFileSync(optionalPath, "utf8"));
    const privateJwk = raw.kty ? raw : raw.privateJwk;
    const publicJwk = raw.publicJwk || { ...privateJwk };
    delete publicJwk.d;
    return { privateJwk, publicJwk };
  }

  // Use JOSE's generateKeyPair with the JWT alg identifier (e.g., ES256, ES384, ES512, EdDSA)
  const { publicKey, privateKey } = await generateKeyPair(alg);
  const privateJwk = await exportJWK(privateKey);
  privateJwk.alg = alg;
  const publicJwk = await exportJWK(publicKey);
  publicJwk.alg = alg;
  return { privateJwk, publicJwk };
}

export function generateDidJwkFromPrivateJwk(publicJwk) {
  const jwkStr = Buffer.from(JSON.stringify(publicJwk)).toString("base64url");
  return `did:jwk:${jwkStr}`;
}

export async function createProofJwt({ privateJwk, publicJwk, audience, nonce, issuer, typ = "JWT", alg = "ES256" }) {
  const header = { alg, typ, jwk: publicJwk };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: issuer,
    aud: audience,
    iat: now,
    nbf: now - 5,
    exp: now + 300,
    nonce,
    jti: base64url(crypto.randomBytes(16)),
  };

  const key = await importJWK(privateJwk, alg);
  const jwt = await new SignJWT(payload).setProtectedHeader(header).sign(key);
  return jwt;
}

export function createPkcePair() {
  const codeVerifier = base64url(crypto.randomBytes(32));
  const hash = crypto.createHash("sha256").update(codeVerifier).digest();
  const codeChallenge = base64url(hash);
  return { codeVerifier, codeChallenge, codeChallengeMethod: "S256" };
}

function base64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}


