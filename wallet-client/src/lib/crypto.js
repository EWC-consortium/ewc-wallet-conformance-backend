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

export async function createProofJwt({ privateJwk, publicJwk, audience, nonce, issuer, typ = "JWT", alg = "ES256", key_attestation = null }) {
  const header = { alg, typ, jwk: publicJwk };
  if (key_attestation) {
    header.key_attestation = key_attestation;
  }
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

/**
 * Creates a DPoP (Demonstrating Proof-of-Possession) proof JWT
 * Based on RFC 9449: https://www.rfc-editor.org/rfc/rfc9449.html
 * 
 * @param {object} options
 * @param {object} options.privateJwk - Private JWK for signing
 * @param {object} options.publicJwk - Public JWK (for header)
 * @param {string} options.htu - HTTP URI (the token endpoint URL, normalized)
 * @param {string} options.htm - HTTP method (default: "POST")
 * @param {string} options.ath - Optional access token hash (for subsequent requests)
 * @param {string} options.alg - Signing algorithm (default: ES256)
 * @returns {Promise<string>} - Signed DPoP JWT
 */
export async function createDPoP({ privateJwk, publicJwk, htu, htm = "POST", ath = null, alg = "ES256" }) {
  // Normalize the URI per RFC 9449 (remove fragment, normalize path, etc.)
  const normalizedHtu = normalizeUri(htu);
  
  const now = Math.floor(Date.now() / 1000);
  const header = { 
    alg, 
    typ: "dpop+jwt", 
    jwk: publicJwk 
  };
  const payload = {
    htm,
    htu: normalizedHtu,
    iat: now,
    jti: base64url(crypto.randomBytes(16)),
    ...(ath ? { ath } : {}),
  };

  const key = await importJWK(privateJwk, alg);
  const jwt = await new SignJWT(payload).setProtectedHeader(header).sign(key);
  return jwt;
}

/**
 * Normalizes a URI per RFC 9449 section 4.2
 * Removes fragment, normalizes path, etc.
 */
function normalizeUri(uri) {
  try {
    const url = new URL(uri);
    // Remove fragment
    url.hash = "";
    // Normalize path (remove trailing slash unless it's the root)
    if (url.pathname !== "/" && url.pathname.endsWith("/")) {
      url.pathname = url.pathname.slice(0, -1);
    }
    return url.toString();
  } catch (e) {
    // If URL parsing fails, return as-is
    return uri;
  }
}

/**
 * Creates a Wallet Instance Attestation (WIA) JWT
 * Based on TS3 Wallet Unit Attestation spec:
 * https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md
 * 
 * @param {object} options
 * @param {object} options.privateJwk - Private JWK for signing
 * @param {object} options.publicJwk - Public JWK (for header)
 * @param {string} options.issuer - Issuer identifier (typically wallet provider DID or URL)
 * @param {string} options.audience - Audience (token endpoint URL)
 * @param {string} options.alg - Signing algorithm (default: ES256)
 * @param {number} options.ttlHours - Time-to-live in hours (default: 1, max: 24)
 * @returns {Promise<string>} - Signed WIA JWT
 */
export async function createWIA({ privateJwk, publicJwk, issuer, audience, alg = "ES256", ttlHours = 1 }) {
  // Ensure TTL is less than 24 hours per spec
  const maxTtlHours = 24;
  const effectiveTtlHours = Math.min(ttlHours, maxTtlHours - 0.01); // Ensure it's strictly less than 24
  
  const now = Math.floor(Date.now() / 1000);
  const exp = now + Math.floor(effectiveTtlHours * 3600);
  
  const header = { alg, typ: "JWT", jwk: publicJwk };
  const payload = {
    iss: issuer,
    aud: audience,
    iat: now,
    exp: exp,
    jti: base64url(crypto.randomBytes(16)),
  };

  const key = await importJWK(privateJwk, alg);
  const jwt = await new SignJWT(payload).setProtectedHeader(header).sign(key);
  return jwt;
}

/**
 * Creates a Wallet Unit Attestation (WUA) JWT
 * Based on TS3 Wallet Unit Attestation spec:
 * https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md
 * 
 * @param {object} options
 * @param {object} options.privateJwk - Private JWK for signing
 * @param {object} options.publicJwk - Public JWK (for header)
 * @param {string} options.issuer - Issuer identifier (typically wallet provider DID or URL)
 * @param {string} options.audience - Audience (credential endpoint URL)
 * @param {object[]} options.attestedKeys - Array of attested key JWKs
 * @param {object} options.eudiWalletInfo - EUDI wallet info object with general_info and key_storage_info
 * @param {object} options.status - Optional status/revocation information
 * @param {string} options.alg - Signing algorithm (default: ES256)
 * @param {number} options.ttlHours - Time-to-live in hours (default: 24)
 * @returns {Promise<string>} - Signed WUA JWT
 */
export async function createWUA({ 
  privateJwk, 
  publicJwk, 
  issuer, 
  audience, 
  attestedKeys, 
  eudiWalletInfo,
  status = null,
  alg = "ES256", 
  ttlHours = 24 
}) {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + Math.floor(ttlHours * 3600);
  
  const header = { alg, typ: "JWT", jwk: publicJwk };
  const payload = {
    iss: issuer,
    aud: audience,
    iat: now,
    exp: exp,
    jti: base64url(crypto.randomBytes(16)),
    eudi_wallet_info: eudiWalletInfo,
    attested_keys: attestedKeys || [],
    ...(status ? { status } : {}),
  };

  const key = await importJWK(privateJwk, alg);
  const jwt = await new SignJWT(payload).setProtectedHeader(header).sign(key);
  return jwt;
}


