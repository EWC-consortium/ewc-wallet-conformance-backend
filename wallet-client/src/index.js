#!/usr/bin/env node
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import fetch from "node-fetch";
import { createProofJwt, generateDidJwkFromPrivateJwk, ensureOrCreateEcKeyPair, createWIA, createWUA, createDPoP } from "./lib/crypto.js";
import { storeWalletCredentialByType } from "./lib/cache.js";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const argv = yargs(hideBin(process.argv))
    .option("issuer", { type: "string", default: "http://localhost:3000" })
    .option("offer", { type: "string", describe: "openid-credential-offer deep link" })
    .option("fetch-offer", { type: "string", describe: "issuer path to fetch an offer, e.g. /offer-no-code" })
    .option("credential", { type: "string", describe: "credential_configuration_id to request" })
    .option("key", { type: "string", describe: "path to EC P-256 private JWK file" })
    .option("poll-interval", { type: "number", default: 2000 })
    .option("poll-timeout", { type: "number", default: 30000 })
    .strict()
    .help()
    .parse();

  const issuerBase = argv.issuer.replace(/\/$/, "");

  const deepLink = argv.offer || (await getOfferDeepLink(issuerBase, argv["fetch-offer"], argv.credential));
  if (!deepLink) {
    console.error("No offer provided or fetched.");
    process.exit(1);
  }

  const offerConfig = await resolveOfferConfig(deepLink);
  const {
    credential_issuer,
    credential_configuration_ids: offerConfigIds,
    credentials: legacyCredentialIds,
    grants,
  } = offerConfig;

  const normalizedConfigIds = Array.isArray(offerConfigIds) && offerConfigIds.length > 0
    ? offerConfigIds
    : Array.isArray(legacyCredentialIds)
      ? legacyCredentialIds
      : legacyCredentialIds && typeof legacyCredentialIds === "object"
        ? Object.keys(legacyCredentialIds)
        : [];

  const configurationId = argv.credential || normalizedConfigIds?.[0];
  if (!configurationId) {
    console.error("No credential_configuration_id available in offer; use --credential");
    process.exit(1);
  }

  const apiBase = (credential_issuer || issuerBase).replace(/\/$/, "");

  const preAuthGrant = grants?.["urn:ietf:params:oauth:grant-type:pre-authorized_code"];
  if (!preAuthGrant) {
    console.error("Only pre-authorized_code is supported in this client.");
    process.exit(1);
  }

  const preAuthorizedCode = preAuthGrant["pre-authorized_code"]; // sessionId
  const txCode = preAuthGrant?.tx_code ? await promptTxCode(preAuthGrant.tx_code) : undefined;

  const tokenEndpoint = `${apiBase}/token_endpoint`;
  const authorizationDetails = configurationId ? [{
    type: "openid_credential",
    credential_configuration_id: configurationId,
    ...(credential_issuer ? { locations: [credential_issuer] } : {}),
  }] : undefined;
  
  // Generate DPoP (Demonstrating Proof-of-Possession) for token request
  let dpopJwt = null;
  try {
    const { privateJwk: dpopPrivateJwk, publicJwk: dpopPublicJwk } = await ensureOrCreateEcKeyPair(argv.key, "ES256");
    dpopJwt = await createDPoP({
      privateJwk: dpopPrivateJwk,
      publicJwk: dpopPublicJwk,
      htu: tokenEndpoint,
      htm: "POST",
      alg: "ES256"
    });
  } catch (dpopError) {
    console.warn("Failed to generate DPoP:", dpopError?.message);
  }
  
  // Generate WIA (Wallet Instance Attestation) for token request
  let wiaJwt = null;
  try {
    const { privateJwk: wiaPrivateJwk, publicJwk: wiaPublicJwk } = await ensureOrCreateEcKeyPair(argv.key, "ES256");
    const wiaIssuer = generateDidJwkFromPrivateJwk(wiaPublicJwk);
    wiaJwt = await createWIA({
      privateJwk: wiaPrivateJwk,
      publicJwk: wiaPublicJwk,
      issuer: wiaIssuer,
      audience: tokenEndpoint,
      alg: "ES256",
      ttlHours: 1
    });
  } catch (wiaError) {
    console.warn("Failed to generate WIA:", wiaError?.message);
  }
  
  const tokenPayload = {
    grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    "pre-authorized_code": preAuthorizedCode,
    ...(txCode ? { tx_code: txCode } : {}),
    ...(authorizationDetails && authorizationDetails.length
      ? { authorization_details: JSON.stringify(authorizationDetails) }
      : {}),
    ...(wiaJwt ? { client_assertion: wiaJwt, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" } : {}),
  };
  const tokenRes = await httpPostJson(tokenEndpoint, tokenPayload, dpopJwt);

  if (!tokenRes.ok) {
    const err = await tokenRes.json().catch(() => ({}));
    throw new Error(`Token error ${tokenRes.status}: ${JSON.stringify(err)}`);
  }
  const tokenBody = await tokenRes.json();
  const accessToken = tokenBody.access_token;
  let c_nonce = tokenBody.c_nonce;
  let c_nonce_expires_in = tokenBody.c_nonce_expires_in;

  if (!c_nonce) {
    const nonceEndpoint = `${apiBase}/nonce`;
    const nonceRes = await httpPostJson(nonceEndpoint, {});
    if (!nonceRes.ok) {
      const err = await nonceRes.json().catch(() => ({}));
      throw new Error(`Nonce error ${nonceRes.status}: ${JSON.stringify(err)}`);
    }
    const nonceJson = await nonceRes.json();
    c_nonce = nonceJson.c_nonce;
    c_nonce_expires_in = nonceJson.c_nonce_expires_in;
  }

  if (!c_nonce) {
    throw new Error("Issuer did not provide c_nonce; cannot complete proof-of-possession flow.");
  }

  // key management
  // In CLI mode we don't fetch issuerMeta; default to ES256 or allow override later if needed
  const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(argv.key, "ES256");
  const didJwk = generateDidJwkFromPrivateJwk(publicJwk);

  // credential request
  const credentialEndpoint = `${apiBase}/credential`;
  
  // Generate WUA (Wallet Unit Attestation) for credential request
  let wuaJwt = null;
  try {
    const { privateJwk: wuaPrivateJwk, publicJwk: wuaPublicJwk } = await ensureOrCreateEcKeyPair(argv.key, "ES256");
    const wuaIssuer = generateDidJwkFromPrivateJwk(wuaPublicJwk);
    wuaJwt = await createWUA({
      privateJwk: wuaPrivateJwk,
      publicJwk: wuaPublicJwk,
      issuer: wuaIssuer,
      audience: credentialEndpoint,
      attestedKeys: [publicJwk], // Attest the key used for proof
      eudiWalletInfo: {
        general_info: {
          name: "Test Wallet Client",
          version: "1.0.0"
        },
        key_storage_info: {
          storage_type: "software",
          protection_level: "software"
        }
      },
      alg: "ES256",
      ttlHours: 24
    });
  } catch (wuaError) {
    console.warn("Failed to generate WUA:", wuaError?.message);
  }

  // build proof JWT with WUA in header as key_attestation (per spec)
  const proofJwt = await createProofJwt({
    privateJwk,
    publicJwk,
    audience: credential_issuer || issuerBase,
    nonce: c_nonce,
    issuer: didJwk,
    typ: "openid4vci-proof+jwt",
    alg: "ES256",
    key_attestation: wuaJwt || undefined
  });
  
  const credReq = {
    credential_configuration_id: configurationId,
    proofs: { 
      jwt: [proofJwt]
    },
  };

  const credRes = await fetch(credentialEndpoint, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify(credReq),
  });

  if (credRes.status === 202) {
    //deferred issuance
    const { transaction_id } = await credRes.json();
    const start = Date.now();
    while (Date.now() - start < argv["poll-timeout"]) {
      await sleep(argv["poll-interval"]);
      const defRes = await httpPostJson(`${apiBase}/credential_deferred`, { transaction_id });
      if (defRes.ok) {
        const body = await defRes.json();
        // store credential and key-binding material using preAuthorizedCode as session key
        await storeWalletCredentialByType(configurationId, {
          credential: body,
          keyBinding: { privateJwk, publicJwk, didJwk },
          metadata: { configurationId, c_nonce, c_nonce_expires_in, credential_issuer: credential_issuer || apiBase },
        });
        console.log(JSON.stringify(body, null, 2));
        return;
      }
    }
    throw new Error("Deferred issuance timed out");
  }

  if (!credRes.ok) {
    const err = await credRes.json().catch(() => ({}));
    throw new Error(`Credential error ${credRes.status}: ${JSON.stringify(err)}`);
  }

  const credBody = await credRes.json();
  // store credential and key-binding material using preAuthorizedCode as session key
  await storeWalletCredentialByType(configurationId, {
    credential: credBody,
    keyBinding: { privateJwk, publicJwk, didJwk },
    metadata: { configurationId, c_nonce, c_nonce_expires_in, credential_issuer: credential_issuer || apiBase },
  });
  console.log(JSON.stringify(credBody, null, 2));
}

async function getOfferDeepLink(issuerBase, path, credentialType) {
  if (!path) return undefined;
  const url = new URL(issuerBase + path);
  if (credentialType) url.searchParams.set("type", credentialType);
  const res = await fetch(url.toString());
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(`Fetch-offer error ${res.status}: ${JSON.stringify(err)}`);
  }
  const body = await res.json();
  return body.deepLink;
}

async function resolveOfferConfig(deepLink) {
  const url = new URL(deepLink.replace(/^haip:\/\//, "openid-credential-offer://"));
  if (url.protocol !== "openid-credential-offer:") {
    throw new Error("Unsupported offer scheme");
  }
  const inlineOffer = url.searchParams.get("credential_offer");
  if (inlineOffer) {
    return parseCredentialOfferParam(inlineOffer);
  }
  const encoded = url.searchParams.get("credential_offer_uri");
  if (!encoded) throw new Error("Missing credential_offer_uri in offer");
  const offerUri = decodeURIComponent(encoded);
  const res = await fetch(offerUri);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(`Offer-config error ${res.status}: ${JSON.stringify(err)}`);
  }
  return res.json();
}

function parseCredentialOfferParam(value) {
  const attempts = new Set([value]);
  try {
    attempts.add(decodeURIComponent(value));
  } catch {
    // ignore decode errors
  }

  for (const attempt of attempts) {
    try {
      return JSON.parse(attempt);
    } catch {
      // not plain JSON, try base64url
      try {
        const decoded = Buffer.from(attempt, "base64url").toString("utf8");
        return JSON.parse(decoded);
      } catch {
        // continue trying other attempts
      }
    }
  }
  throw new Error("Unable to parse credential_offer parameter");
}

async function promptTxCode(cfg) {
  // Non-interactive default: generate a dummy numeric code if required; issuer currently does not validate tx_code server-side.
  if (cfg?.input_mode === "numeric" && typeof cfg?.length === "number") {
    return "".padStart(cfg.length, "1");
  }
  return undefined;
}

async function httpPostJson(url, body, dpopHeader = null) {
  const headers = { "content-type": "application/json" };
  if (dpopHeader) {
    headers["DPoP"] = dpopHeader;
  }
  return fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body || {}),
  });
}

main().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});


